#![cfg_attr(feature = "ci", deny(warnings))]

use cbpf_rs::bpf_code;
use clap::Parser;
use km_cert_exchange::KmCertExchange;
use std::default::Default;
use std::fs;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use tokio::net::UdpSocket;
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_tun::TunBuilder;
use tracing::{info, warn};
use tracing_subscriber;
use zpr_ext::tokio::net::UdpSocketExt;

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
mod pcap_writer;
mod peer_table;
mod queues;
mod rcu;
mod rpc_worker;
mod signal_worker;
mod substrate_ingress_worker;
mod sync_req;
mod test_packet;
mod tun_ctl;
mod zdp;
mod zdp_ll;
mod zpr;

#[cfg(test)]
mod km_testdata;

use assembly::{Assembly, PhFlags, PhMode};
use buffer_stack::BufferStack;
use capture_worker::CaptureWorker;
use flow_control::FlowControl;
use km_multiplexor::KmState;
use km_noise::NoiseKeypair;
use queues::*;
use tun_ctl::TunCtl;

#[derive(Parser)]
#[command(version, about)]
struct Config {
    #[arg(long)]
    name: String,

    #[arg(long)]
    control_path: String,

    #[arg(long)]
    self_addr: SocketAddr,

    #[arg(long)]
    node_addr: Option<SocketAddr>,

    #[arg(long)]
    ca_file: Option<String>,

    #[arg(long)]
    certificate_file: Option<String>, // noise public key signed by authority

    #[arg(long)]
    private_key_file: Option<String>, // noise private key

    #[arg(long)]
    node_public_key_file: Option<String>, // noise public key for node (only specified when starting an adapter)

    #[arg(long)]
    tun_if: Option<String>,

    #[arg(long)]
    disable_km: bool,

    #[arg(long)]
    allow_insecure_zpi_zero: bool,

    #[arg(long)]
    debug: bool,
}

fn main() -> ExitCode {
    //
    // parse configuration from command line
    //

    let config = Config::parse();

    let ph_mode;
    if config.node_addr.is_some() {
        ph_mode = PhMode::Adapter;
    } else {
        ph_mode = PhMode::Node;
    }

    //
    // validate configuration
    //

    if !config.disable_km {
        if config.ca_file.is_none() {
            panic!("Authority certificate file must be specified when key management is enabled");
        }
        if config.certificate_file.is_none() {
            panic!("Certificate file must be specified when key management is enabled");
        }
        if config.private_key_file.is_none() {
            panic!("Private key file must be specified when key management is enabled");
        }
    }

    if ph_mode == PhMode::Adapter && !config.disable_km && config.node_public_key_file.is_none() {
        panic!("Node public key file must be specified when starting an adapter");
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

    //
    // read key material
    //

    let self_noise_keypair;
    let peer_noise_keypair;
    let certx;

    if !config.disable_km {
        let private_key =
            km_cert_exchange::load_private_key(&Path::new(&config.private_key_file.unwrap()))
                .unwrap();
        if ph_mode == PhMode::Node {
            peer_noise_keypair = None;
            self_noise_keypair = Some(NoiseKeypair::new(private_key));
        } else {
            let public_key = km_cert_exchange::load_public_key(&Path::new(
                &config.node_public_key_file.unwrap(),
            ))
            .unwrap();
            peer_noise_keypair = Some(NoiseKeypair {
                public: public_key,
                private: [0u8; 32], // unknown
            });
            self_noise_keypair = Some(NoiseKeypair::new(private_key));
        }

        certx = Some(
            KmCertExchange::new_from_paths(
                &Path::new(&config.certificate_file.as_ref().unwrap()),
                &Path::new(&config.ca_file.as_ref().unwrap()),
            )
            .unwrap(),
        );
    } else {
        peer_noise_keypair = None;
        self_noise_keypair = None;
        certx = None;
    }

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

    let tun_devs = TunBuilder::new()
        .name(config.tun_if.unwrap_or(String::new()).as_str())
        .try_build_mq(topology_config.agent_output_concurrency)
        .expect("unable to open TUN device")
        .leak();

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

    // Configure packet steering to separate flows for better load balancing.
    // It's OK if this fails; flows will still be pinned to a queue;
    // they'll just be pinned there with all other flows from the same link.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        use crate::zdp::*;
        use bpf_code::*;
        use libc::sock_filter as sf;
        use std::mem::{offset_of, size_of};

        // TODO/FIXME: Ideally we want to select the queue by the _sum_ of the
        // hash and stream ID, thus avoiding clumping due to correlated stream IDs between
        // links.  That requires eBPF though, since the hash value is only present for
        // eBPF programs (see <https://github.com/torvalds/linux/blob/master/net/core/sock_reuseport.c#L595-L598>).
        // (`[SKF_AD_RXHASH]` just reads as 0!)
        let prog = &[
            // [0] load ZPI and packet type
            sf {
                code: LD | H | ABS,
                jt: 0,
                jf: 0,
                k: 0,
            },
            // [1] if packet is encrypted, or packet is non-flow, fall back to hash
            sf {
                code: JMP | JSET | K,
                jt: 3,
                jf: 0,
                k: ((zpr::ZPI_ENCRYPTED_HEADER_FLAG as u32) << 8)
                    | ZDP_PACKET_TYPE_NON_FLOW_FLAG as u32,
            },
            // [2] load stream ID
            sf {
                code: LD | W | ABS,
                jt: 0,
                jf: 0,
                k: (size_of::<ZdpZpiHeader>()
                    + size_of::<ZdpBaseHeader>()
                    + offset_of!(ZdpPerFlowHeader, stream_id)) as u32,
            },
            // [3] modulo # of queues
            sf {
                code: ALU | MOD | K,
                jt: 0,
                jf: 0,
                k: topology_config.substrate_ingress_concurrency as u32,
            },
            // [4] return as selected queue #
            sf {
                code: RET | A,
                jt: 0,
                jf: 0,
                k: 0,
            },
            // [5] return huge value to force fallback to hash-based steering
            sf {
                code: RET | K,
                jt: 0,
                jf: 0,
                k: u32::MAX,
            },
        ];

        match substrate_sockets[0].attach_reuse_port_cbpf(prog) {
            Ok(()) => (),
            Err(err) => warn!("Unable to enable ingress packet steering: {err}"),
        }
    }

    //
    // create system assembly
    //

    let flags = PhFlags {
        allow_insecure_zpi_zero: config.disable_km || config.allow_insecure_zpi_zero,
        disable_key_management: config.disable_km,
        ..Default::default()
    };

    if flags.allow_insecure_zpi_zero {
        warn!(
            "Insecure ZPI ZERO is enabled.  This is insecure and should only be used for testing."
        );
    }

    let asm = Box::leak(Box::new(Assembly {
        flags,
        ph_mode,
        system_name: config.name,
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
            asm.initiate_tether(config.node_addr.as_ref().unwrap())
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
    if !config.disable_km {
        js.spawn_local(km_multiplexor::launch_signal_worker(&*asm, km_sig_outq));
        js.spawn_local(km_multiplexor::launch_message_worker(&*asm, km_outq));
    }

    //
    // start data path workers
    //

    for (worker_index, tun_dev) in tun_devs.iter().enumerate() {
        js.spawn(agent_output_worker::launch(
            &agent_output_worker::Config {
                worker_index,
                batch_size: topology_config.agent_output_batch_size,
            },
            &*asm,
            tun_dev,
        ));
    }

    for (worker_index, socket) in substrate_sockets.iter().enumerate() {
        js.spawn(substrate_ingress_worker::launch(
            &substrate_ingress_worker::Config {
                worker_index,
                batch_size: topology_config.substrate_ingress_batch_size,
            },
            &*asm,
            socket,
        ));
    }

    js.spawn(capture_worker::launch(
        &capture_worker::Config {
            batch_size: topology_config.capture_batch_size,
        },
        &*asm,
        cap_outq,
    ));

    //
    // TEMP HACK: set TUN carrier up
    //

    asm.tun_ctl.set_carrier(true).unwrap();

    //
    // TEMP HACK: bring up tether if we're an adapter
    //

    local_set.block_on(&runtime, async {
        if ph_mode == PhMode::Adapter {
            let Some(dsid) = dsid else { panic!("we are an adapter but have no tether configured"); };

            if !config.disable_km {
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

                // HACK - In our tests we need to send from adapter through the node to the adapter.
                // We do not know when the other adapter has setup its association. So lets give
                // it a little time here.
                info!("{}: waiting for the other adapter to (hopfully) establish its security association...", asm.system_name);
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
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
