#![cfg_attr(feature = "ci", deny(warnings))]

use itertools::izip;
use km_cert_exchange::KmCertExchange;
use std::default::Default;
use std::fs;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::Path;
use std::process;
use std::process::ExitCode;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::*;

mod adapter_manager_worker;
mod adapter_tables;
mod admin_worker;
mod assembly;
mod batch_io;
mod capture_worker;
mod classifier;
mod compress;
mod config;
mod counters;
mod defs;
mod fastpath;
mod fastpath_io;
mod fastpath_worker;
mod flow_control;
mod forwarding_tables;
mod km;
mod km_cert_exchange;
mod km_multiplexor;
mod km_noise;
mod link_state;
mod logging;
mod main_argparse;
mod main_args;
mod mgmt;
mod mgmt_dispatch_worker;
mod mgmt_processor_worker;
mod net_defs;
mod packet;
mod packet_queue;
mod packet_steering;
mod pcap_writer;
mod peer_table;
mod pki;
mod queues;
mod rcu;
mod sample_ring;
mod signal_worker;
mod special_peers;
mod sync_req;
mod sys;
mod test_packet;
mod tun_ctl;
mod two_way_queue;
mod visa_mgmt;
mod visa_table;
mod vs_worker;
mod vss_worker;
mod zdp;
mod zdp_ll;
mod zprtun;

#[cfg(test)]
mod km_testdata;

use assembly::{Assembly, PhMode};
use capture_worker::CaptureWorker;
use fastpath::FastpathWorkerConfig;
use flow_control::FlowControl;
use km_multiplexor::KmState;
use km_noise::NoiseKeypair;
use pki::{load_cert, load_noise_public_key};
use logging::targets::STARTUP;
use queues::*;
use sys::ZprTun;
use tun_ctl::TunCtl;

/// Creates a nonblocking local socket pair suitable for transferring
/// PACKET_BUFFER_SIZE-sized messages.
fn packet_buffer_socket_pair(
    queue_size: usize,
) -> std::io::Result<(
    std::os::unix::net::UnixDatagram,
    std::os::unix::net::UnixDatagram,
)> {
    // NOTE: ideally we'd use SOCK_SEQPACKET for reliable delivery, but it
    // isn't supported on macOS, and Linux provides reliable delivery
    // with SOCK_DGRAM.
    let (a, b) = socket2::Socket::pair(socket2::Domain::UNIX, socket2::Type::DGRAM, None)?;
    a.set_send_buffer_size(queue_size * config::PACKET_BUFFER_SIZE)?;
    a.set_recv_buffer_size(queue_size * config::PACKET_BUFFER_SIZE)?;
    b.set_send_buffer_size(queue_size * config::PACKET_BUFFER_SIZE)?;
    b.set_recv_buffer_size(queue_size * config::PACKET_BUFFER_SIZE)?;
    a.set_nonblocking(true)?;
    b.set_nonblocking(true)?;
    Ok((a.into(), b.into()))
}

fn main() -> ExitCode {
    let system_start_time = std::time::Instant::now();
    //
    // parse configuration from command line
    //
    let (ph_mode, mut config) = match main_argparse::argparse(None) {
        Ok((ph_mode, config)) => (ph_mode, config),
        Err(e) => {
            eprintln!("failed to parse command line arguments: {:?}", e);
            eprintln!("try `ph --help` for help");
            return ExitCode::FAILURE;
        }
    };

    //
    // set up logging
    //

    logging::initialize(&config);

    info!(target: STARTUP, "starting with PID {}", process::id());

    //
    // read key material
    //

    let self_noise_keypair;
    let peer_noise_keypair;
    let certx;

    let private_key = match config.get_noise_private_key_data() {
        Ok(key) => key,
        Err(e) => {
            error!(
                target: STARTUP,
                "failed to load private key from: {:?}: {e:?}",
                config.noise_private_key_source()
            );
            return ExitCode::FAILURE;
        }
    };
    if ph_mode == PhMode::Node {
        peer_noise_keypair = None;
        self_noise_keypair = Some(NoiseKeypair::new(private_key));
    } else {
        let public_key = match load_noise_public_key(&Path::new(
            &config.node_public_key_file.unwrap(),
        )) {
            Ok(key) => key,
            Err(e) => {
                error!(target: STARTUP, "failed to load node public key file: {e:?}");
                return ExitCode::FAILURE;
            }
        };
        peer_noise_keypair = Some(NoiseKeypair {
            public: public_key,
            private: [0u8; 32], // unknown
        });
        self_noise_keypair = Some(NoiseKeypair::new(private_key));
    }

    certx = match KmCertExchange::new_from_paths(&config.certificate_file, &config.ca_file) {
        Ok(certx) => Some(certx),
        Err(e) => {
            error!(target: STARTUP, "failed to initialize key exchange: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    //
    // instantiate bounded resources (queues and buffers)
    //

    let topology_config = config::TopologyConfig::default();

    let (cap_inq, cap_outq) =
        packet_buffer_socket_pair(topology_config.capture_queue_size).unwrap();
    let (md_inq_factory, md_outq) =
        two_way_queue::two_way_queue(topology_config.mgmt_dispatch_queue_size);
    let (am_inq_factory, am_outq) =
        two_way_queue::two_way_queue(topology_config.adapter_manager_queue_size);
    let (km_sig_inq, km_sig_outq) = mpsc::channel(topology_config.km_signal_queue_size);
    let (km_inq, km_outq) = mpsc::channel(topology_config.km_message_queue_size);

    //
    // startup Tokio
    //

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let _runtime_guard = runtime.enter();

    //
    // create control socket
    //

    fs::remove_file(&config.control_path)
        .or_else(|e| {
            if e.kind() == ErrorKind::NotFound {
                Ok(())
            } else {
                Err(e)
            }
        })
        .unwrap();
    let control_socket = Arc::new(
        UnixListener::bind(&config.control_path).expect("failed to bind to control socket"),
    );
    info!(target: STARTUP, "control socket bound to {:?}", config.control_path);

    //
    // open TUN devices and actor requeue sockets
    //

    // HACK: If we are using a new TUN (requirement on MAC I think), we will set the address.
    let tun_addr = if !config.zpr_addr.is_empty() && config.tun_if.is_none() {
        Some(config.zpr_addr[0].clone())
    } else {
        None
    };

    let tun_devs: Vec<_> = match ZprTun::new_mq(
        config.tun_if,
        topology_config.fastpath_concurrency,
        tun_addr,
    ) {
        Ok(devs) => devs.into_iter().map(Arc::new).collect(),
        Err(err) => {
            panic!("unable to create TUN device: {err}");
        }
    };
    let tun_ctl = Box::new(tun_ctl::TunCtlImpl::new(tun_devs[0].clone()));
    tun_ctl.set_carrier(false).unwrap();

    let mut actor_requeue_inqs = Vec::new();
    let mut actor_requeue_outqs = Vec::new();
    for _i in 0..topology_config.fastpath_concurrency {
        let (inq, outq) = packet_queue::packet_queue(topology_config.mgmt_datapath_queue_size);
        actor_requeue_inqs.push(inq);
        actor_requeue_outqs.push(outq);
    }

    //
    // open substrate sockets and mgmt substrate injection socket
    //

    let mut substrate_sockets: Vec<std::net::UdpSocket> = Vec::new();

    for _i in 0..topology_config.fastpath_concurrency {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(config.self_addr),
            socket2::Type::DGRAM,
            None,
        )
        .unwrap();
        socket.set_nonblocking(true).unwrap();
        socket.set_reuse_port(true).unwrap();
        socket
            .bind(&socket2::SockAddr::from(config.self_addr))
            .expect(&format!(
                "unable to bind to self_addr ({})",
                config.self_addr
            ));
        if config.self_addr.port() == 0 {
            let port = socket.local_addr().unwrap().as_socket().unwrap().port();
            config.self_addr.set_port(port);
            info!(target: STARTUP, "assigned substrate UDP port {port}");
        }
        substrate_sockets.push(socket.into());
    }

    let (mgmt_substrate_inq, mgmt_substrate_outq) =
        packet_queue::packet_queue(topology_config.mgmt_datapath_queue_size);

    //
    // configure packet steering for better load balancing
    //

    if let Err(err) = packet_steering::set_steering(
        &substrate_sockets[0],
        topology_config.fastpath_concurrency,
        packet_steering::SteeringMethod::ZdpStreamId,
    ) {
        // It's OK if this fails; flows will still be pinned to a queue;
        // they'll just be pinned there with all other flows from the same link.
        warn!(target: STARTUP, "Unable to enable ingress packet steering: {err}");
    }

    //
    // instantiate (but don't launch yet) Visa Service connection manager if we're a node
    //

    let mut vsconn;
    let vs_outq;

    if ph_mode == PhMode::Node {
        let node_cert = load_cert(&config.certificate_file)
            .expect("unable to read certificate");

        let node_name = node_cert
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .expect("unable to locate CN in certificate subject name")
            .data()
            .as_utf8()
            .expect("CN must be UTF-8 string");
        info!(target: STARTUP, "node name is \"{node_name}\"");

        let node_actor =
            libnode::vsconn::new_node_actor(config.zpr_addr[0], &node_name, &Default::default());

        let (vs_inq, vs_outq_inner) = mpsc::channel(topology_config.vs_queue_size);
        vs_outq = Some(vs_outq_inner);

        vsconn = Some(
            libnode::vsconn::VSConn::new(
                node_actor,
                vs_inq,
                &SocketAddr::new(zpr::VISA_SERVICE_ADDR, zpr::VISA_SERVICE_PORT).to_string(),
                &config.certificate_file,
                config.zpr_addr[0],
                None,
            )
            .expect("error launching Visa Service connection manager"),
        );
    } else {
        vsconn = None;
        vs_outq = None;
    }

    //
    // create system assembly
    //

    let asm = Arc::new(Assembly {
        ph_mode,
        topology_config,
        local_zpr_addresses: config.zpr_addr,
        mgmt_substrate_egress: MgmtSubstrateEgress::new(mgmt_substrate_inq),
        actor_output_requeue: ActorOutputRequeue::new(actor_requeue_inqs),
        vsconn: vsconn.as_ref().map(|c| c.handle()),
        visa_table: tokio::sync::RwLock::new(visa_table::VisaTable::new()),
        capture_queue: Capture::new(cap_inq),
        capture_worker: CaptureWorker::new(),
        flow_control: FlowControl::new(),
        counters: Default::default(),
        tun_ctl,
        peer_table: peer_table::PeerTable::new(),
        peer_ids: Default::default(),
        alt: adapter_tables::ActorLookupTable::new(),
        dlt: adapter_tables::DockLookupTable::new(),
        mgmt_dispatch_factory: MgmtDispatchFactory::new(md_inq_factory),
        adapter_manager_factory: AdapterManagerFactory::new(am_inq_factory),
        km_state: KmState::new(km_inq, km_sig_inq),
        self_noise_keypair,
        peer_noise_keypair,
        certx,
        system_start_time,
    });

    //
    // create a Tokio "local set" to schedule all our management workers on
    //

    let local_set = tokio::task::LocalSet::new();

    let _local_set_guard = local_set.enter();

    //
    // instantiate the "fake" local actor link
    //

    asm.add_local_actor_peer();

    //
    // instantiate tether if we're an adapter
    // NOTE: must occur before we start any other workers!
    //

    if ph_mode == PhMode::Adapter {
        let dsid = asm
            .start_tether(
                config.node_addr.as_ref().unwrap(),
                link_state::LinkType::AdapterToNode,
            )
            .unwrap();

        assert_eq!(dsid.get(), zpr::DOCK_LINK_ID);
    }

    //
    // start mgmt workers
    //

    let mut js = JoinSet::new();

    js.spawn_local(signal_worker::launch(asm.clone()));
    js.spawn_local(mgmt_dispatch_worker::launch(asm.clone(), md_outq));
    js.spawn_local(adapter_manager_worker::launch(asm.clone(), am_outq));
    js.spawn_local(admin_worker::launch(asm.clone(), control_socket));
    js.spawn_local(km_multiplexor::launch_signal_worker(
        asm.clone(),
        km_sig_outq,
    ));
    js.spawn_local(km_multiplexor::launch_message_worker(asm.clone(), km_outq));

    //
    // start data path workers
    //

    if ph_mode == PhMode::Node {
        if config.self_addr.port() == 0 {
            // TODO: Should we force setting a port when configuring a node?
            warn!(target: STARTUP, "self_addr port is 0 which means dock listening port will be randomly assigned");
        }
        info!(
            target: STARTUP,
            "dock listening on {}",
            substrate_sockets[0].local_addr().unwrap()
        );
    }

    let mut fastpath_threads = Vec::new();

    let mut mgmt_substrate_outq = Some(mgmt_substrate_outq); // only the first fastpath worker gets this

    let fastpath_worker_config = FastpathWorkerConfig {
        buffer_count: asm.topology_config.buffer_count,
        batch_size: asm.topology_config.fastpath_batch_size,
    };

    for (worker_index, socket, tun_dev, requeue_outq) in izip!(
        0..asm.topology_config.fastpath_concurrency,
        substrate_sockets,
        tun_devs,
        actor_requeue_outqs
    ) {
        let builder = std::thread::Builder::new().name(format!("fastpath {worker_index}"));
        fastpath_threads.push(
            builder
                .spawn(fastpath_worker::launch(
                    fastpath_worker_config,
                    worker_index,
                    asm.clone(),
                    socket,
                    tun_dev,
                    requeue_outq,
                    mgmt_substrate_outq.take(),
                ))
                .unwrap(),
        );
    }

    js.spawn(capture_worker::launch(
        capture_worker::Config {
            batch_size: asm.topology_config.capture_batch_size,
        },
        asm.clone(),
        tokio::net::UnixDatagram::from_std(cap_outq).unwrap(),
    ));

    if ph_mode == PhMode::Node {
        asm.tun_ctl.set_carrier(true).unwrap();
    }

    //
    // TEMP HACK: bring up tether if we're an adapter
    //

    if ph_mode == PhMode::Adapter {
        local_set.block_on(&runtime, async {
            let dsid = zpr::DOCK_LINK_ID;
            debug!(target: STARTUP, "waiting on security assocaition establishment on link {dsid}");
            while !asm.peer_table.is_security_assocaition_established(dsid) {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            debug!(target: STARTUP, "security assocaition established successfully on link {dsid}");
        });
    }

    //
    // start Visa Support Service, Visa Service connection manager, and their workers, if we're a node
    //

    if ph_mode == PhMode::Node {
        let (vss_inq, vss_outq) = mpsc::channel(asm.topology_config.vss_queue_size);

        let vss_addr =
            std::net::SocketAddr::new(asm.local_zpr_addresses[0], libnode::vss::DEFAULT_VSS_PORT);

        js.spawn_blocking(move || libnode::vss::start_vss_server(vss_inq, vss_addr));

        // launch the VS conn mgr... this weird dance is necessary because
        // although it is an async method, it calls blocking functions (namely Thrift functions)...
        // once we switch to async Thrift we can simplify this
        let rt_handle = runtime.handle().clone();
        js.spawn_blocking(move || loop {
            let res = rt_handle.block_on(
                vsconn
                    .as_mut()
                    .unwrap()
                    .run(tokio_util::sync::CancellationToken::new()),
            );

            error!(target: STARTUP, "visa service connection manager terminated: {res:?}");

            std::thread::sleep(std::time::Duration::from_secs(1));
        });

        js.spawn_local(vss_worker::launch(asm.clone(), vss_outq));
        js.spawn_local(vs_worker::launch(asm.clone(), vs_outq.unwrap()));
    }

    //
    // drive the local set, and handle worker termination
    //

    local_set.block_on(&runtime, async {
        while let Some(res) = js.join_next().await {
            res.unwrap();
        }
    });

    for th in fastpath_threads {
        th.join().unwrap();
    }

    info!(target: STARTUP, "exiting");

    ExitCode::SUCCESS
}
