#![cfg_attr(feature = "ci", deny(warnings))]

use itertools::izip;
use km_cert_exchange::KmCertExchange;
use std::default::Default;
use std::fs;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::process;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::*;

mod adapter_manager_worker;
mod adapter_tables;
mod address_pool;
mod admin_worker;
mod assembly;
mod auth;
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
mod five_tuple_lookup_table;
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
mod packet;
mod packet_queue;
mod packet_steering;
mod pcap_writer;
mod peer_table;
mod pki;
mod queues;
mod rcu;
mod sample_ring;
mod set_capture_file_worker;
mod signal_worker;
mod special_peers;
mod sys;
mod tc;
mod test_packet;
mod tlv;
mod tun_ctl;
mod two_way_queue;
mod visa_mgmt;
mod visa_table;
mod vs_worker;
mod vss_worker;
mod zdp;
mod zdp_ll;
mod zdpr;
mod zdpr_worker;
mod zprtun;

#[cfg(test)]
mod km_testdata;

use assembly::{Assembly, PhMode};
use capture_worker::CaptureWorker;
use fastpath::FastpathWorkerConfig;
use flow_control::FlowControl;
use km_multiplexor::KmState;
use km_noise::NoiseKeypair;
use logging::targets::STARTUP;
use pki::{generate_self_signed_noise_cert, load_cert, load_noise_public_key};
use queues::*;
use sys::ZprTun;
use tun_ctl::TunCtl;
use zpr_ext::socket2::SockAddrExt;
use zpr_utils::net_defs::SocketAddrExt;

use zpr::addrs::{
    DEFAULT_TETHER_PORT, VISA_SERVICE_ADDR, VISA_SERVICE_PORT, ZPR_TEMP_LOCAL_ADDRESS,
};
use zpr::packet_info::{DOCK_LINK_ID, LOCAL_ACTOR_LINK_ID};
use zpr::vsapi_types::AuthServicesList;

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
    let (reload_handle, logging_map) = logging::initialize(&mut config.logging);

    info!(target: STARTUP, "starting with PID {}", process::id());

    //
    // read key material
    //

    let self_noise_keypair;
    let peer_noise_keypair;
    let certx;

    let maybe_private_key = match config.get_noise_private_key_data() {
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
        // In node mode a private key is required -- since client adapters use the public key to verify the node.
        let Some(private_key) = maybe_private_key else {
            // Note that this is already checked in the config code, so this should be redundant.
            error!(target: STARTUP, "nodes require a noise private key to be specified");
            return ExitCode::FAILURE;
        };
        peer_noise_keypair = None;
        self_noise_keypair = NoiseKeypair::new(private_key);
    } else {
        let public_key = match load_noise_public_key(&Path::new(
            &config.node_public_key_file.clone().unwrap(),
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
        self_noise_keypair = match maybe_private_key {
            Some(private_key) => NoiseKeypair::new(private_key),
            None => NoiseKeypair::generate(),
        };
    }

    // Set up key exchange.
    //
    // If we have a signed certificate, use that.  Otherwise we create a self-signed cert
    // and insert our CN (`name` from config) and our self_noise_keypair public key.

    let self_cert = match config.certificate_file.as_ref() {
        None => match generate_self_signed_noise_cert(&config.name, &self_noise_keypair) {
            Ok(cert) => cert,
            Err(e) => {
                error!(target: STARTUP, "failed to generate self-signed certificate: {e:?}");
                return ExitCode::FAILURE;
            }
        },
        Some(cert_path) => match load_cert(cert_path) {
            Ok(cert) => cert,
            Err(e) => {
                error!(target: STARTUP, "failed to load certificate from {:?}: {e:?}", cert_path);
                return ExitCode::FAILURE;
            }
        },
    };
    let ca_cert = match load_cert(&config.ca_file) {
        Ok(cert) => cert,
        Err(e) => {
            error!(target: STARTUP, "failed to load CA certificate from {:?}: {e:?}", config.ca_file);
            return ExitCode::FAILURE;
        }
    };
    certx = KmCertExchange::new(self_cert, ca_cert);

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
    let control_socket =
        UnixListener::bind(&config.control_path).expect("failed to bind to control socket");
    info!(target: STARTUP, "control socket bound to {:?}", config.control_path);

    fs::remove_file(&config.capture_path)
        .or_else(|e| {
            if e.kind() == ErrorKind::NotFound {
                Ok(())
            } else {
                Err(e)
            }
        })
        .unwrap();
    let capture_socket = Arc::new(
        UnixListener::bind(&config.capture_path).expect("failed to bind to capture socket"),
    );
    info!(target: STARTUP, "capture socket bound to {:?}", config.capture_path);

    //
    // open TUN devices and actor requeue sockets
    //

    // If a zpr_addr is supplied we use it on the TUN.  Otherwise we hand the TUN create code a
    // local address which we never use.
    // TODO: Can we create a TUN with no address on it?

    // TODO: Currently on linux we cannot configure a TUN interface with an IPv6 address.
    // So if you set tun_if in the config we assume TUN is there and has a static ZPR address.
    let tun_addr = if !config.zpr_addr.is_empty() {
        if config.tun_if.is_none() {
            Some(config.zpr_addr[0].clone())
        } else {
            None
        }
    } else {
        // TODO: If linux then do not bother setting the temp address since it will fail because ipv6.
        if cfg!(target_os = "linux") {
            None
        } else {
            Some(ZPR_TEMP_LOCAL_ADDRESS.into())
        }
    };

    let tun_devs: Vec<_> = match ZprTun::new_mq(
        config.tun_if.clone(),
        topology_config.fastpath_concurrency,
        tun_addr,
    ) {
        Ok(devs) => devs.into_iter().map(Arc::new).collect(),
        Err(err) => {
            panic!("unable to create TUN device: {err}");
        }
    };
    let tun_ctl = Box::new(tun_ctl::TunCtlImpl::new(tun_devs[0].clone()));

    // Node must be set ON (adapter will be turned on as part of finishing hello)
    // TODO: There is more subtlety here, see issue ( https://github.com/org-zpr/zpr-core/issues/937 )
    tun_ctl.set_carrier(ph_mode == PhMode::Node).unwrap();

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

    match ph_mode {
        PhMode::Node => {
            if config.self_addr.port() == 0 {
                config.self_addr.set_port(DEFAULT_TETHER_PORT);
                info!(target: STARTUP, "listening on default tether port {}", config.self_addr.port());
            }
        }

        PhMode::Adapter => {
            let node_addr = config.node_addr.as_mut().unwrap();
            if node_addr.port() == 0 {
                node_addr.set_port(DEFAULT_TETHER_PORT);
                info!(target: STARTUP, "connecting to default tether port {}", node_addr.port());
            }
        }
    }

    let mut substrate_sockets: Vec<std::net::UdpSocket> = Vec::new();

    for _i in 0..topology_config.fastpath_concurrency {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(config.self_addr),
            socket2::Type::DGRAM,
            None,
        )
        .unwrap();

        socket.set_nonblocking(true).unwrap();
        batch_io::set_recv_packet_info(&socket, true).unwrap();

        // SO_REUSEPORT allows us to open multiple sockets for the same 5-tuple
        socket.set_reuse_port(true).unwrap();

        // First bind to our self address.
        // If the port is unspecified, one will be selected by the OS.
        // (The IP address may also be unspecified, but the OS will not select one here.)
        socket
            .bind(&socket2::SockAddr::from(config.self_addr))
            .expect(&format!(
                "unable to bind to self_addr ({})",
                config.self_addr
            ));

        if config.self_addr.port() == 0 {
            // Update the port of our configured self address to match
            // what the OS chose.  This ensures that all sockets we open share
            // the same port.
            let port = socket.local_addr().unwrap().as_socket().unwrap().port();
            config.self_addr.set_port(port);
            info!(target: STARTUP, "assigned substrate UDP port {port}");
        }

        if let Some(node_addr) = config.node_addr {
            if config.self_addr.ip().is_unspecified() {
                // If we are an adapter (and thus have a remote node address),
                // but we don't have a specified self address (and thus did not
                // specify one in the bind call above), temporarily connect to
                // the remote node address to forcee the OS to choose a local
                // address.
                socket
                    .connect(&socket2::SockAddr::from(node_addr))
                    .expect(&format!("unable to connect to node_addr ({})", node_addr));

                // Update the address of our configured self address to match
                // what the OS chose.  This ensures that all sockets we open share
                // the same port.
                let addr = socket
                    .local_addr()
                    .unwrap()
                    .as_socket()
                    .unwrap()
                    .scoped_ip();
                config.self_addr.set_scoped_ip(addr);
                info!(target: STARTUP, "assigned substrate address {addr}");

                // On Linux, dropping the connection (below) also drops the bind,
                // so open a temp socket here to hold ownership of the local port.
                #[cfg(target_os = "linux")]
                let temp_socket;
                #[cfg(target_os = "linux")]
                {
                    temp_socket = socket2::Socket::new(
                        socket2::Domain::for_address(config.self_addr),
                        socket2::Type::DGRAM,
                        None,
                    )
                    .unwrap();

                    temp_socket.set_reuse_port(true).unwrap();

                    temp_socket
                        .bind(&socket2::SockAddr::from(config.self_addr))
                        .unwrap();
                }

                // Now drop the connection.  We will still specify it manually
                // for each packet sent (and it's an error to do both).
                match socket.connect(&socket2::SockAddr::new_unspec()) {
                    Ok(()) => (),
                    Err(err) if err.raw_os_error() == Some(libc::EAFNOSUPPORT) => (),
                    res => res.expect("unable to disconnect socket"),
                }

                // Disconnecting above weirdly also drops the local-address binding!
                // (Possible Linux bug?)  So now we need to re-bind.
                // Enable on Linux only, because this does not seem to be needed
                // and also does not work on macOS.
                #[cfg(target_os = "linux")]
                socket
                    .bind(&socket2::SockAddr::from(config.self_addr))
                    .expect(&format!(
                        "unable to re-bind to self_addr ({})",
                        config.self_addr
                    ));

                // Now the temp socket will go out of scope and close;
                // we've re-bound no longer need it.
            }
        }

        substrate_sockets.push(socket.into());
    }

    let node_zpr_addr: IpAddr;
    if ph_mode == PhMode::Node {
        info!(
            target: STARTUP,
            "dock listening on {}",
            substrate_sockets[0].local_addr().unwrap()
        );
        node_zpr_addr = config.zpr_addr[0].clone();
    } else {
        node_zpr_addr = Ipv6Addr::UNSPECIFIED.into(); // only node uses this.
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

    if ph_mode == PhMode::Node {
        // Note that config parsing code ensures that IF node THEN certificate_file is set.
        let node_name = config::get_noise_cn(config.certificate_file.as_ref().unwrap())
            .expect("unable to determine node name: cannot parse CN");
        info!(target: STARTUP, "node CN is \"{node_name}\"");

        // Load the node's RSA private key for VS "static" authentication. The public key is mapped to the
        // node CN value in the policy.
        let auth_key_path = config
            .auth_private_key
            .as_ref()
            .expect("nodes require auth_private_key for visa service authentication");
        let auth_key_pem = fs::read_to_string(auth_key_path)
            .unwrap_or_else(|e| panic!("failed to read auth_private_key {auth_key_path:?}: {e}"));
        let auth_private_key = openssl::pkey::PKey::private_key_from_pem(auth_key_pem.as_bytes())
            .unwrap_or_else(|e| panic!("failed to parse auth_private_key {auth_key_path:?}: {e}"));

        vsconn = Some(libnode::vsconn::VSConn::new(
            topology_config.vs_queue_size,
            SocketAddr::new(VISA_SERVICE_ADDR, VISA_SERVICE_PORT),
            node_name,
            auth_private_key,
        ));
    } else {
        vsconn = None;
    }

    //
    // create system assembly
    //

    let asm = Arc::new(Assembly {
        ph_mode,
        topology_config,
        mgmt_substrate_egress: MgmtSubstrateEgress::new(mgmt_substrate_inq),
        actor_output_requeue: ActorOutputRequeue::new(actor_requeue_inqs),
        vsconn: vsconn.as_ref().map(|c| c.handle()),
        visa_table: std::sync::RwLock::new(visa_table::VisaTable::new_with_vs_visas(
            &node_zpr_addr,
        )),
        vs_auth_services: std::sync::RwLock::new(AuthServicesList::default()),
        capture_queue: Capture::new(cap_inq),
        capture_worker: CaptureWorker::new(),
        flow_control: FlowControl::new(),
        counters: Default::default(),
        tun_ctl,
        peer_table: peer_table::PeerTable::new(),
        elt: adapter_tables::EndpointLookupTable::new(),
        dlt: adapter_tables::DockLookupTable::new(),
        mgmt_dispatch_factory: MgmtDispatchFactory::new(md_inq_factory),
        adapter_manager_factory: AdapterManagerFactory::new(am_inq_factory),
        km_state: KmState::new(km_inq, km_sig_inq),
        self_noise_keypair: Some(self_noise_keypair),
        peer_noise_keypair,
        certx: Some(certx),
        system_start_time,
        address_pool: std::sync::Mutex::new(None),
        config: rcu::RcuBox::new(config),
        logging: Mutex::new(logging_map),
        reload_handle,
    });
    //
    // create a Tokio "local set" to schedule all our management workers on
    //

    let local_set = tokio::task::LocalSet::new();

    let _local_set_guard = local_set.enter();

    //
    // instantiate the "fake" local actor link
    //

    assert_eq!(
        asm.peer_table.insert_internal_peer().get(),
        LOCAL_ACTOR_LINK_ID
    );

    if matches!(ph_mode, PhMode::Node) {
        // Nodes use this link as the source of bind requests from the
        // internal adapter, which require that the originator has a valid
        // actor address (which matches the requested source address).

        for addr in &asm.config.get().zpr_addr {
            asm.peer_table
                .get(LOCAL_ACTOR_LINK_ID)
                .unwrap()
                .link_state_machine
                .add_internal_actor_address(addr.into());
        }
    }

    //
    // instantiate tether if we're an adapter,
    // or "fake" internal dock link if we're a node
    // NOTE: must occur before we start any other workers!
    //

    match ph_mode {
        PhMode::Adapter => {
            let dsid = asm
                .start_tether(
                    asm.config.get().node_addr.as_ref().unwrap(),
                    &asm.config.get().self_addr.scoped_ip(),
                    link_state::LinkType::AdapterToNode,
                )
                .unwrap();

            assert_eq!(dsid.get(), DOCK_LINK_ID);
        }

        PhMode::Node => assert_eq!(asm.peer_table.insert_internal_peer().get(), DOCK_LINK_ID),
    }

    //
    // start mgmt workers
    //

    let mut js = JoinSet::new();

    js.spawn_local(signal_worker::launch(asm.clone()));
    js.spawn_local(mgmt_dispatch_worker::launch(asm.clone(), md_outq));
    js.spawn_local(adapter_manager_worker::launch(asm.clone(), am_outq));
    js.spawn_local(set_capture_file_worker::launch(
        asm.clone(),
        capture_socket.clone(),
    ));
    js.spawn_local(admin_worker::launch(asm.clone(), control_socket));
    js.spawn_local(km_multiplexor::launch_signal_worker(
        asm.clone(),
        km_sig_outq,
    ));
    js.spawn_local(km_multiplexor::launch_message_worker(asm.clone(), km_outq));

    //
    // select batch I/O engine
    //

    let Some(batch_io_engine) = batch_io::select_engine_by_name(&asm.config.get().batch_io_engine)
    else {
        error!(target: STARTUP, "Unknown packet I/O engine {}", asm.config.get().batch_io_engine);
        return ExitCode::FAILURE;
    };

    info!(target: STARTUP, "Using packet I/O engine {}", batch_io_engine.engine_name());

    //
    // start data path workers
    //

    let mut fastpath_threads = Vec::new();

    let mut mgmt_substrate_outq = Some(mgmt_substrate_outq); // only the first fastpath worker gets this

    let fastpath_worker_config = FastpathWorkerConfig {
        batch_io_engine,
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
            let dsid = DOCK_LINK_ID;
            debug!(target: STARTUP, "waiting on security association establishment on link {dsid}");
            while !asm.peer_table.is_security_association_established(dsid) {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            debug!(target: STARTUP, "security association established successfully on link {dsid}");
        });
    }

    //
    // start Visa Support Service, Visa Service connection manager, and their workers, if we're a node
    //
    // TODO: More thought needed here about lifecycle. It's possible the connection to the visa service
    // may fail (ie, the visa service may go down momentarily), and in that case we would normally want
    // to restart it, which may also require restarting the vss -- both while the node (ph) remains up.
    //

    if ph_mode == PhMode::Node {
        let (vss_inq, vss_outq) = mpsc::channel(asm.topology_config.vss_queue_size);

        let vss_addr =
            std::net::SocketAddr::new(asm.get_local_dock_addr(), config::DEFAULT_VSS_PORT);

        // Launch VSS server (requires local set). This expects an inbound connection from the VS.
        js.spawn_local(async move {
            if let Err(e) = libnode::vss::launch_vss(&vss_addr, vss_inq).await {
                error!(target: STARTUP, "VSS server terminated: {e:?}");
                // TODO: If the VSS goes down we would normally want to restart it.
            }
        });

        // Launch VSConn run loop (sets up its own local set). The VSConn handles reconnects.
        // Send the "stop" command to cause it to exit cleanly.
        let mut vsconn_instance = vsconn.take().unwrap();
        let vsconn_lifecycle_rx = vsconn_instance.subscribe_lifecycle_events();
        js.spawn_local(async move {
            let res = vsconn_instance
                .run_with_reconnect(config::VSCONN_RETRY_WAIT)
                .await;
            error!(target: STARTUP, "visa service connection manager terminated: {res:?}");
        });

        let vs_handle = asm.vsconn.as_ref().unwrap().clone();

        js.spawn_local(vs_worker::launch(
            asm.clone(),
            node_zpr_addr,
            vss_addr,
            vs_handle,
            vsconn_lifecycle_rx,
        ));

        js.spawn_local(vss_worker::launch(asm.clone(), vss_outq));
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
