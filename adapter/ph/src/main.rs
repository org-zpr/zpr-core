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
use tokio::signal::unix::{signal, SignalKind};
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
use counters::*;
use flow_control::FlowControl;
use km_multiplexor::KmState;
use km_noise::NoiseKeypair;
use queues::*;
use tun_ctl::TunCtl;

#[derive(Parser)]
#[command(version, about)]
struct CmdLine {
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

fn emit_counts(system_name: &String, counters: &Counters) {
    println!("\n*** {} Counters ***", system_name);
    for (key, ref value) in counters {
        println!("{}: {}", key, value.get_count());
    }
}

fn main() -> ExitCode {
    let cmd_line = CmdLine::parse();

    let mut subscriber = tracing_subscriber::fmt::fmt();
    if cmd_line.debug {
        subscriber = subscriber.with_max_level(tracing::Level::DEBUG);
    } else {
        subscriber = subscriber.with_max_level(tracing::Level::INFO);
    }
    let subscriber = subscriber.finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let system_name = cmd_line.name;
    let sock_path = cmd_line.control_path;
    let self_addr = cmd_line.self_addr;
    let node_addr = cmd_line.node_addr;
    let ca_file = cmd_line.ca_file;
    let cert_file = cmd_line.certificate_file;
    let priv_key_file = cmd_line.private_key_file;
    let node_pubkey_file = cmd_line.node_public_key_file;
    let disable_km = cmd_line.disable_km;
    if !disable_km {
        if ca_file.is_none() {
            panic!("Authority certificate file must be specified when key management is enabled");
        }
        if cert_file.is_none() {
            panic!("Certificate file must be specified when key management is enabled");
        }
        if priv_key_file.is_none() {
            panic!("Private key file must be specified when key management is enabled");
        }
    }
    let allow_insecure_zpi_zero = if disable_km {
        true
    } else {
        cmd_line.allow_insecure_zpi_zero
    };
    if allow_insecure_zpi_zero {
        warn!(
            "Insecure ZPI ZERO is enabled.  This is insecure and should only be used for testing."
        );
    }
    let ph_mode;

    let topology_config = config::TopologyConfig::default();

    let buf_storage = vec![[0u8; config::PACKET_BUFFER_SIZE]; topology_config.buffer_count];
    let buffer_stack = BufferStack::new(buf_storage.leak::<'static>());

    let (cap_inq, cap_outq) = mpsc::channel(topology_config.capture_queue_size);
    let capture_queue = Capture::new(cap_inq);

    let (md_inq, md_outq) = mpsc::channel(topology_config.mgmt_dispatch_queue_size);
    let mgmt_dispatch = MgmtDispatch::new(md_inq);

    let (am_inq, am_outq) = mpsc::channel(topology_config.adapter_manager_queue_size);
    let adapter_manager = AdapterManager::new(am_inq);

    let capture_worker = CaptureWorker::new();
    let flow_control = FlowControl::new();

    let (km_sig_tx, km_sig_rx) = mpsc::channel(topology_config.km_signal_queue_size);
    let (km_tx, km_rx) = mpsc::channel(topology_config.km_message_queue_size);
    let km_state = KmState::new(km_tx, km_sig_tx);

    if node_addr.is_some() {
        ph_mode = PhMode::Adapter;
        if !disable_km && node_pubkey_file.is_none() {
            panic!("Node public key file must be specified when starting an adapter");
        }
    } else {
        ph_mode = PhMode::Node;
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let tun_devs = runtime.block_on(async {
        TunBuilder::new()
            .name(cmd_line.tun_if.unwrap_or(String::new()).as_str())
            .try_build_mq(topology_config.agent_output_concurrency)
            .expect("unable to open TUN device")
            .leak()
    });

    let tun_ctl = Box::new(tun_ctl::TunCtlImpl::new(&tun_devs[0]));

    tun_ctl.set_carrier(false).unwrap();

    let alt = adapter_tables::AgentLookupTable::new();
    let dlt = adapter_tables::DockLookupTable::new();

    // Open ingress sockets.
    let mut sockets = Vec::new();
    runtime.block_on(async {
        for _i in 0..topology_config.substrate_ingress_concurrency {
            let socket = socket2::Socket::new(
                socket2::Domain::for_address(self_addr),
                socket2::Type::DGRAM,
                None,
            )
            .unwrap();
            socket.set_nonblocking(true).unwrap();
            socket.set_reuse_port(true).unwrap();
            socket
                .bind(&socket2::SockAddr::from(self_addr))
                .expect("unable to bind to self addr");
            sockets.push(UdpSocket::from_std(socket.into()).unwrap());
        }
    });

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

        match sockets[0].attach_reuse_port_cbpf(prog) {
            Ok(()) => (),
            Err(err) => warn!("Unable to enable ingress packet steering: {err}"),
        }
    }

    let sockets = sockets.leak();

    let agent_input = AgentInput::new(tun_devs.iter());
    let substrate_egress = SubstrateEgress::new(sockets.iter());

    let mut flags: PhFlags = Default::default();
    flags.allow_insecure_zpi_zero = allow_insecure_zpi_zero;
    flags.disable_key_management = disable_km;

    // TEMP HACK to statically install peers
    let asm = Box::leak(Box::new(Assembly {
        flags,
        ph_mode,
        system_name,
        buffer_stack,
        agent_input,
        substrate_egress,
        capture_queue,
        capture_worker,
        flow_control,
        counters: Default::default(),
        tun_ctl,
        peer_table: peer_table::PeerTable::new(),
        peer_ids: std::sync::Mutex::new(Vec::new()),
        alt,
        dlt,
        mgmt_dispatch,
        adapter_manager,
        km_state,
        self_noise_keypair: None,
        peer_noise_keypair: None,
        certx: None,
    }));

    tokio::task::LocalSet::new().block_on(&runtime, async {
        if !disable_km {
            let private_key = km_cert_exchange::load_private_key(&Path::new(&priv_key_file.unwrap())).unwrap();
            if ph_mode == PhMode::Node {
                asm.self_noise_keypair = Some(NoiseKeypair::new(private_key));
            } else {
                let public_key = km_cert_exchange::load_public_key(&Path::new(&node_pubkey_file.unwrap())).unwrap();
                asm.peer_noise_keypair = Some(NoiseKeypair {
                    public: public_key,
                    private: [0u8; 32], // unknown
                });
                asm.self_noise_keypair = Some(NoiseKeypair::new(private_key));
            }

            asm.certx = Some(KmCertExchange::new_from_paths(
                &Path::new(&cert_file.as_ref().unwrap()),
                &Path::new(&ca_file.as_ref().unwrap())
                ).unwrap());
        }


        let dsid = match ph_mode {
            PhMode::Adapter => match asm.initiate_tether(node_addr.as_ref().unwrap()) {
                Ok(dsid) => Some(dsid),
                Err(_) => None
            },
            PhMode::Node => None
        };

        // TODO signal handler goes here

        fs::remove_file(&sock_path)
            .or_else(|e| {
                if e.kind() == ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(e)
                }
            })
            .unwrap();
        let unix_socket = Box::leak(Box::new(UnixListener::bind(sock_path).unwrap())); //TODO not sure if this needs the Box leak wrapper

        let mut js = JoinSet::new();

        let usr1_stream = Box::leak(Box::new(signal(SignalKind::user_defined1()).unwrap()));
        let term_stream = Box::leak(Box::new(signal(SignalKind::terminate()).unwrap()));

        js.spawn(async {
            loop {
                tokio::select! {
                    _ = usr1_stream.recv() => emit_counts(&asm.system_name, &asm.counters),
                    _ = term_stream.recv() => {
                        emit_counts(&asm.system_name, &asm.counters);
                        std::process::exit(128 + SignalKind::terminate().as_raw_value())
                    }
                }
            }
        });

        js.spawn_local(mgmt_dispatch_worker::launch(&*asm, md_outq));

        js.spawn_local(adapter_manager_worker::launch(&*asm, am_outq));

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

        js.spawn_local(rpc_worker::launch(&*asm, &*unix_socket));

        js.spawn(capture_worker::launch(
            &capture_worker::Config {
                batch_size: topology_config.capture_batch_size,
            },
            &*asm,
            cap_outq,
        ));

        if !disable_km {
            // Start key managemenent workers
            js.spawn(km_multiplexor::launch_signal_worker(&*asm, km_sig_rx));
            js.spawn(km_multiplexor::launch_message_worker(&*asm, km_rx));
        }

        info!("{}: Starting substrate ingress workers", asm.system_name);
        for (worker_index, socket) in sockets.iter().enumerate() {
            js.spawn(substrate_ingress_worker::launch(
                &substrate_ingress_worker::Config {
                    worker_index,
                    batch_size: topology_config.substrate_ingress_batch_size,
                },
                &*asm,
                socket,
            ));
        }
        //if asm.is_node() {
            asm.tun_ctl.set_carrier(true).unwrap();
        //}


        if matches!(ph_mode, PhMode::Adapter) {
            if !disable_km && dsid.is_some() {
                info!(
                    "{}: waiting on security assocaition establishment on link {}",
                    asm.system_name, dsid.unwrap()
                );
                while !asm.peer_table.is_security_assocaition_established(dsid.unwrap()) {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
                info!(
                    "{}: security assocaition established successfully on link {}",
                    asm.system_name, dsid.unwrap()
                );

                // HACK - In our tests we need to send from adapter through the node to the adapter.
                // We do not know when the other adapter has setup its association. So lets give
                // it a little time here.
                info!("{}: waiting for the other adapter to (hopfully) establish its security association...", asm.system_name);
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }


            mgmt::requests::send_report(asm, dsid.unwrap(), "Reporting for Duty!").await;
            mgmt::requests::send_discard(asm, dsid.unwrap()).await;
        }

        while let Some(res) = js.join_next().await {
            res.unwrap();
        }
    });

    ExitCode::SUCCESS
}
