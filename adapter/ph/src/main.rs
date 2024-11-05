#![cfg_attr(feature = "ci", deny(warnings))]

use clap::{Parser, Subcommand};
use km_cert_exchange::KmCertExchange;
use std::default::Default;
use std::fs;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process;
use std::process::ExitCode;
use tokio::net::UdpSocket;
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{error, info, warn};
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
mod dock_tables;
mod fastpath;
mod flow_control;
mod km;
mod km_cert_exchange;
mod km_multiplexor;
mod km_noise;
mod link_state;
mod mgmt;
mod mgmt_dispatch_worker;
mod mgmt_processor_worker;
mod net_defs;
mod options;
mod packet;
mod packet_steering;
mod pcap_writer;
mod peer_table;
mod queues;
mod rcu;
mod rpc_worker;
mod signal_worker;
mod substrate_ingress_worker;
mod sync_req;
mod sys;
mod test_packet;
mod tun_ctl;
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
use queues::*;
use sys::ZprTun;
use tun_ctl::TunCtl;

/// ZPR Packet Handler
///
/// The handler can run in `node` mode or `adapter` mode. There are a series of command
/// line arguments that are required in BOTH modes. These need to be specified before
/// you set the mode.  The general usage is:
///
///    sudo ph [GLOBAL_OPTIONS] (node | adapter) [MODE_OPTIONS]
///
#[derive(Parser)]
#[command(version)]
struct Control {
    /// An optional, identifying name for instance.  Will default to "adapter" or "node" depending on mode.
    #[arg(short, long)]
    name: Option<String>,

    /// The unix domain socket path for the "control" interface.
    #[arg(long, value_name = "DOMAIN_SOCKET_PATH")]
    control_path: String,

    /// The local substrate IPv4 or IPv6 address and port for this node or adapter.
    #[arg(short, long, value_name = "ADDR:PORT", default_value = "0.0.0.0:0")]
    self_addr: SocketAddr,

    /// Certificate of the Certificate Authority
    #[arg(long, value_name = "PATH")]
    ca_file: String,

    /// Certificate including the noise public key, signed by the authority.
    #[arg(long, value_name = "PATH")]
    certificate_file: String, // noise public key signed by authority

    /// Path to the noise private key file (PEM format)
    #[arg(long, short = 'k', value_name = "PATH")]
    private_key_file: String, // noise private key

    /// The TUN device to use, eg "tun1".  Leave blank for automatic selection.
    #[arg(long, short = 'i', value_name = "DEVICE")]
    tun_if: Option<String>,

    /// Enable debug logging
    #[arg(long, short, default_value_t = false)]
    debug: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Starts the handler in adapter mode.
    #[command()]
    Adapter {
        /// The substrate address of the node.
        #[arg(long, short = 'N', value_name = "ADDR:PORT")]
        node_addr: SocketAddr,

        /// The ZPR address (no port) of the adapter. Must match your TUN address!
        #[arg(long, short)]
        agent_addr: IpAddr,

        /// PEM file holding the nodes noise public key.
        #[arg(long, short, value_name = "PATH")]
        node_public_key_file: String, // noise public key for node (only specified when starting an adapter)
    },
    /// Starts the handler in node mode.
    #[command()]
    Node,
}

// This config struct is loaded up from the command line args.
struct Config {
    name: String,
    control_path: PathBuf,
    self_addr: SocketAddr,
    ca_file: PathBuf,
    certificate_file: PathBuf,
    private_key_file: PathBuf,
    tun_if: Option<String>,
    debug: bool,
    node_addr: Option<SocketAddr>,
    agent_addr: Option<IpAddr>,
    node_public_key_file: Option<PathBuf>,
}

fn main() -> ExitCode {
    //
    // parse configuration from command line
    //
    let config: Config;
    let ph_mode;
    let control = Control::parse();
    match control.command {
        Some(Command::Adapter {
            node_addr,
            agent_addr,
            node_public_key_file,
        }) => {
            ph_mode = PhMode::Adapter;
            config = Config {
                name: control.name.unwrap_or("adapter".to_string()),
                control_path: control.control_path.into(),
                self_addr: control.self_addr,
                ca_file: control.ca_file.into(),
                certificate_file: control.certificate_file.into(),
                private_key_file: control.private_key_file.into(),
                tun_if: control.tun_if,
                debug: control.debug,
                node_addr: Some(node_addr),
                agent_addr: Some(agent_addr),
                node_public_key_file: Some(node_public_key_file.into()),
            };
        }
        Some(Command::Node) => {
            ph_mode = PhMode::Node;
            config = Config {
                name: control.name.unwrap_or("node".to_string()),
                control_path: control.control_path.into(),
                self_addr: control.self_addr,
                ca_file: control.ca_file.into(),
                certificate_file: control.certificate_file.into(),
                private_key_file: control.private_key_file.into(),
                tun_if: control.tun_if,
                debug: control.debug,
                node_addr: None,
                agent_addr: None,
                node_public_key_file: None,
            };
        }
        None => {
            println!("command required: either 'adapter' or 'node'");
            return ExitCode::FAILURE;
        }
    }

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

    info!("{} starting with PID {}", config.name, process::id());

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
            error!("failed to load private key file: {:?}", e);
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
                error!("failed to load node public key file: {:?}", e);
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
            error!("failed to initialize key exchange: {:?}", e);
            return ExitCode::FAILURE;
        }
    };

    //
    // instantiate bounded resources (queues and buffers)
    //

    let topology_config = config::TopologyConfig::default();

    let buf_storage = vec![[0u8; config::PACKET_BUFFER_SIZE]; topology_config.buffer_count];

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

    let control_socket = Box::leak(Box::new(UnixListener::bind(config.control_path).unwrap()));

    //
    // open TUN devices
    //
    let tun_devs = match ZprTun::new_mq(config.tun_if, topology_config.agent_output_concurrency) {
        Ok(devs) => devs.leak(),
        Err(e) => {
            panic!("unable to create TUN device: {:?}", e);
        }
    };

    let tun_ctl = Box::new(tun_ctl::TunCtlImpl::new(&tun_devs[0]));

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
            .expect("unable to bind to self addr");
        substrate_sockets.push(UdpSocket::from_std(socket.into()).unwrap());
    }

    let substrate_sockets = substrate_sockets.leak();

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
        warn!("Unable to enable ingress packet steering: {err}");
    }

    //
    // create system assembly
    //
    let asm = Box::leak(Box::new(Assembly {
        ph_mode,
        topology_config,
        system_name: config.name,
        agent_address: config.agent_addr,
        buffer_stack: BufferStack::new(buf_storage.leak::<'static>()),
        agent_input: AgentInput::new(tun_devs.iter()),
        substrate_egress: SubstrateEgress::new(substrate_sockets.iter()),
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
    }));

    //
    // create a Tokio "local set" to schedule all our management workers on
    //

    let local_set = tokio::task::LocalSet::new();

    let _local_set_guard = local_set.enter();

    //
    // instantiate tether if we're an adapter
    // NOTE: must occur before we start any other workers!
    //

    let dsid = match ph_mode {
        PhMode::Adapter => Some(
            asm.start_tether(
                config.node_addr.as_ref().unwrap(),
                link_state::LinkType::AdapterToNode,
            )
            .unwrap(),
        ),
        PhMode::Node => None,
    };

    //
    // start mgmt workers
    //

    let mut js = JoinSet::new();

    js.spawn_local(signal_worker::launch(asm));
    js.spawn_local(mgmt_dispatch_worker::launch(asm, md_outq));
    js.spawn_local(adapter_manager_worker::launch(&*asm, am_outq));
    js.spawn_local(rpc_worker::launch(asm, control_socket));
    js.spawn_local(km_multiplexor::launch_signal_worker(&*asm, km_sig_outq));
    js.spawn_local(km_multiplexor::launch_message_worker(&*asm, km_outq));

    //
    // start data path workers
    //

    for (worker_index, tun_dev) in tun_devs.iter().enumerate() {
        js.spawn(agent_output_worker::launch(
            &agent_output_worker::Config {
                worker_index,
                batch_size: asm.topology_config.agent_output_batch_size,
            },
            &*asm,
            tun_dev,
        ));
    }

    for (worker_index, socket) in substrate_sockets.iter().enumerate() {
        js.spawn(substrate_ingress_worker::launch(
            &substrate_ingress_worker::Config {
                worker_index,
                batch_size: asm.topology_config.substrate_ingress_batch_size,
            },
            &*asm,
            socket,
        ));
    }

    js.spawn(capture_worker::launch(
        &capture_worker::Config {
            batch_size: asm.topology_config.capture_batch_size,
        },
        &*asm,
        cap_outq,
    ));

    if asm.is_node() {
        asm.tun_ctl.set_carrier(true).unwrap();
    }

    //
    // TEMP HACK: bring up tether if we're an adapter
    //

    local_set.block_on(&runtime, async {
        if ph_mode == PhMode::Adapter {
            let Some(dsid) = dsid else {
                panic!("we are an adapter but have no tether configured");
            };

            info!(
                "{}: waiting on security assocaition establishment on link {}",
                asm.system_name, dsid
            );
            while !asm.peer_table.is_security_assocaition_established(dsid) {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            info!(
                "{}: security assocaition established successfully on link {}",
                asm.system_name, dsid
            );
        }
    });

    //
    // drive the local set, and handle worker termination
    //

    local_set.block_on(&runtime, async {
        while let Some(res) = js.join_next().await {
            res.unwrap();
        }
    });

    ExitCode::SUCCESS
}
