#![cfg_attr(feature = "ci", deny(warnings))]

use km_cert_exchange::KmCertExchange;
use std::default::Default;
use std::fs;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::Path;
use std::process;
use std::process::ExitCode;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::*;
use tracing_subscriber;

mod adapter_manager_worker;
mod adapter_tables;
mod agent_output_worker;
mod assembly;
mod buffer_stack;
mod capture_worker;
mod classifier;
mod compress;
mod config;
mod counters;
mod defs;
mod fastpath;
mod flow_control;
mod forwarding_tables;
mod km;
mod km_cert_exchange;
mod km_multiplexor;
mod km_noise;
mod link_state;
mod logging;
mod main_args;
mod mgmt;
mod mgmt_dispatch_worker;
mod mgmt_processor_worker;
mod net_defs;
mod packet;
mod packet_steering;
mod pcap_writer;
mod peer_table;
mod queues;
mod rcu;
mod rpc_worker;
mod signal_worker;
mod special_peers;
mod substrate_ingress_worker;
mod sync_req;
mod sys;
mod test_packet;
mod tun_ctl;
mod vs_worker;
mod vss_worker;
mod zdp;
mod zdp_ll;
mod zprtun;

#[cfg(test)]
mod km_testdata;

use assembly::{Assembly, PhMode};
use buffer_stack::BufferStack;
use capture_worker::CaptureWorker;
use flow_control::FlowControl;
use km_multiplexor::KmState;
use km_noise::NoiseKeypair;
use logging::targets::STARTUP;
use queues::*;
use sys::ZprTun;
use tun_ctl::TunCtl;

fn main() -> ExitCode {
    //
    // parse configuration from command line
    //
    let (ph_mode, mut config) = match main_args::argparse(None) {
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

    let tracing_max_level;
    if config.debug {
        tracing_max_level = tracing::Level::DEBUG;
    } else {
        tracing_max_level = tracing::Level::INFO;
    }

    let subscriber = tracing_subscriber::fmt::fmt()
        .with_max_level(tracing_max_level)
        .finish();

    tracing::subscriber::set_global_default(subscriber).unwrap();

    info!(target: STARTUP, "starting with PID {}", process::id());

    //
    // read key material
    //

    let self_noise_keypair;
    let peer_noise_keypair;
    let certx;

    let private_key = match km_cert_exchange::load_private_key(&Path::new(&config.private_key_file))
    {
        Ok(key) => key,
        Err(e) => {
            error!(
                target: STARTUP,
                "failed to load private key file: {:?}: {e:?}",
                &config.private_key_file,
            );
            return ExitCode::FAILURE;
        }
    };
    if ph_mode == PhMode::Node {
        peer_noise_keypair = None;
        self_noise_keypair = Some(NoiseKeypair::new(private_key));
    } else {
        let public_key = match km_cert_exchange::load_public_key(&Path::new(
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

    let buf_storage =
        vec![Box::new([0u8; config::PACKET_BUFFER_SIZE]); topology_config.buffer_count];

    let (cap_inq, cap_outq) = mpsc::channel(topology_config.capture_queue_size);
    let (md_inq, md_outq) = mpsc::channel(topology_config.mgmt_dispatch_queue_size);
    let (am_inq, am_outq) = mpsc::channel(topology_config.adapter_manager_queue_size);
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
    // open TUN devices
    //
    // HACK: If we are using a new TUN (requirement on MAC I think), we will set the address.
    let tun_addr = if !config.agent_addr.is_empty() && config.tun_if.is_none() {
        Some(config.agent_addr[0].clone())
    } else {
        None
    };

    let tun_devs: Vec<_> = match ZprTun::new_mq(
        config.tun_if,
        topology_config.agent_output_concurrency,
        tun_addr,
    ) {
        Ok(devs) => devs.into_iter().map(Arc::new).collect(),
        Err(err) => {
            panic!("unable to create TUN device: {err}");
        }
    };
    let tun_ctl = Box::new(tun_ctl::TunCtlImpl::new(tun_devs[0].clone()));
    tun_ctl.set_carrier(false).unwrap();

    //
    // open substrate sockets
    //

    let mut substrate_sockets = Vec::new();

    for _i in 0..topology_config.substrate_ingress_concurrency {
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
            .expect("unable to bind to self_addr");
        if config.self_addr.port() == 0 {
            let port = socket.local_addr().unwrap().as_socket().unwrap().port();
            config.self_addr.set_port(port);
            info!(target: STARTUP, "assigned substrate UDP port {port}");
        }
        substrate_sockets.push(Arc::new(UdpSocket::from_std(socket.into()).unwrap()));
    }

    //
    // configure packet steering for better load balancing
    //

    if let Err(err) = packet_steering::set_steering(
        &substrate_sockets[0],
        topology_config.substrate_ingress_concurrency,
        packet_steering::SteeringMethod::ZdpStreamId,
    ) {
        // It's OK if this fails; flows will still be pinned to a queue;
        // they'll just be pinned there with all other flows from the same link.
        warn!(target: STARTUP, "Unable to enable ingress packet steering: {err}");
    }

    //
    // instantiate (but don't launch yet) Visa Service connection manager if we're a node
    //

    let vsconn;
    let vs_outq;

    if ph_mode == PhMode::Node {
        let node_cert = km_cert_exchange::load_cert(&config.certificate_file)
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

        let node_agent =
            libnode::vsconn::new_node_agent(config.agent_addr[0], &node_name, &Default::default());

        let (vs_inq, vs_outq_inner) = mpsc::channel(topology_config.vs_queue_size);
        vs_outq = Some(vs_outq_inner);

        vsconn = Some(
            libnode::vsconn::VSConn::new(
                node_agent,
                vs_inq,
                &SocketAddr::new(zpr::VISA_SERVICE_ADDR, zpr::VISA_SERVICE_PORT).to_string(),
                &config.certificate_file,
                config.agent_addr[0],
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
        agent_addresses: config.agent_addr,
        buffer_stack: BufferStack::new(buf_storage),
        agent_input: AgentInput::new(tun_devs.clone()),
        substrate_egress: SubstrateEgress::new(substrate_sockets.clone()),
        vsconn,
        capture_queue: Capture::new(cap_inq),
        capture_worker: CaptureWorker::new(),
        flow_control: FlowControl::new(),
        counters: Default::default(),
        tun_ctl,
        peer_table: peer_table::PeerTable::new(),
        peer_ids: Default::default(),
        alt: adapter_tables::AgentLookupTable::new(),
        dlt: adapter_tables::DockLookupTable::new(),
        mgmt_dispatch: MgmtDispatch::new(md_inq),
        adapter_manager: AdapterManager::new(am_inq),
        km_state: KmState::new(km_inq, km_sig_inq),
        self_noise_keypair,
        peer_noise_keypair,
        certx,
    });

    //
    // create a Tokio "local set" to schedule all our management workers on
    //

    let local_set = tokio::task::LocalSet::new();

    let _local_set_guard = local_set.enter();

    //
    // instantiate the "fake" local agent link
    //

    asm.add_local_agent_peer();

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
    js.spawn_local(rpc_worker::launch(asm.clone(), control_socket));
    js.spawn_local(km_multiplexor::launch_signal_worker(
        asm.clone(),
        km_sig_outq,
    ));
    js.spawn_local(km_multiplexor::launch_message_worker(asm.clone(), km_outq));

    //
    // start data path workers
    //

    for (worker_index, tun_dev) in tun_devs.into_iter().enumerate() {
        js.spawn(agent_output_worker::launch(
            agent_output_worker::Config {
                worker_index,
                batch_size: asm.topology_config.agent_output_batch_size,
            },
            asm.clone(),
            tun_dev,
        ));
    }

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
    for (worker_index, socket) in substrate_sockets.into_iter().enumerate() {
        js.spawn(substrate_ingress_worker::launch(
            substrate_ingress_worker::Config {
                worker_index,
                batch_size: asm.topology_config.substrate_ingress_batch_size,
            },
            asm.clone(),
            socket,
        ));
    }

    js.spawn(capture_worker::launch(
        capture_worker::Config {
            batch_size: asm.topology_config.capture_batch_size,
        },
        asm.clone(),
        cap_outq,
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
            std::net::SocketAddr::new(asm.agent_addresses[0], libnode::vss::DEFAULT_VSS_PORT);

        js.spawn_blocking(move || libnode::vss::start_vss_server(vss_inq, vss_addr));

        // launch the VS conn mgr... this weird dance is necessary because
        // although it is an async method, it calls blocking functions (namely Thrift functions)...
        // once we switch to async Thrift we can simplify this
        let rt_handle = runtime.handle().clone();
        let vsconn_asm = asm.clone();
        js.spawn_blocking(move || loop {
            let res = rt_handle.block_on(
                vsconn_asm
                    .vsconn
                    .clone()
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

    info!(target: STARTUP, "exiting");

    ExitCode::SUCCESS
}
