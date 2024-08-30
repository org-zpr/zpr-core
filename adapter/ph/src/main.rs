#![cfg_attr(feature = "ci", deny(warnings))]

use cbpf_rs::bpf_code;
use clap::Parser;
use enum_map::{enum_map, EnumMap};
use std::fs;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::process::ExitCode;
use tokio::net::UdpSocket;
use tokio::net::UnixListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_tun::TunBuilder;
use tracing::warn;
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
mod counter;
mod counters_enum;
mod defs;
mod fastpath;
mod flow_control;
mod mgmt;
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
mod test_packet;
mod tun_ctl;
mod zdp;
mod zdp_ll;
mod zpr;

use assembly::{Assembly, SyncReqState};
use buffer_stack::BufferStack;
use capture_worker::CaptureWorker;
use counter::*;
use counters_enum::*;
use flow_control::FlowControl;
use options::PhMode;
use queues::*;
use tun_ctl::CarrierSetter;

#[derive(Parser)]
#[command(version, about)]
struct CmdLine {
    #[arg(long, default_value_t, value_enum)]
    mode: PhMode,

    #[arg(long)]
    control_path: String,

    #[arg(long)]
    self_addr: SocketAddr,

    #[arg(long)]
    dock_addr: SocketAddr,

    #[arg(long)]
    ca_file: String,

    #[arg(long)]
    certificate_file: String,

    #[arg(long)]
    private_key_file: String,

    #[arg(long)]
    tun_if: Option<String>,
}

fn emit_counts(counts_map: &EnumMap<CounterType, Counter>) {
    for (key, &ref value) in counts_map {
        println!("{}: {}", key, value.get_count());
    }
}

fn main() -> ExitCode {
    let cmd_line = CmdLine::parse();

    let sock_path = cmd_line.control_path;
    let peer_addr = cmd_line.dock_addr;
    let self_addr = cmd_line.self_addr;
    let _ca_file = cmd_line.ca_file;
    let _cert_file = cmd_line.certificate_file;
    let _priv_key_file = cmd_line.private_key_file;

    // TODO: These batch sizes are placeholders for now.  So are the queue
    // sizes below which are all just double the batch size.  Performance
    // testing will inform us the correct values for these, which balance
    // throughput with service time.
    let substrate_socket_count = 4;
    let substrate_ingress_batch_size = 8;
    let mgmt_processor_queue_size = 16;
    let agent_output_batch_size = 4;
    let capture_queue_size = 16;
    let capture_batch_size = 8;
    let tun_queue_count = 4;
    let adapter_manager_queue_size = 16;

    let buf_storage = vec![[0u8; config::PACKET_BUFFER_SIZE]; 256];
    let buffer_stack = BufferStack::new(buf_storage.leak::<'static>());

    let (mp_inq, mp_outq) = mpsc::channel(mgmt_processor_queue_size);
    let mgmt_processor = MgmtProcessor::new(mp_inq);

    let (cap_inq, cap_outq) = mpsc::channel(capture_queue_size);
    let capture_queue = Capture::new(cap_inq);

    let (am_inq, am_outq) = mpsc::channel(adapter_manager_queue_size);
    let adapter_manager = AdapterManager::new(am_inq);

    let capture_worker = CaptureWorker::new();
    let flow_control = FlowControl::new();

    let counters = enum_map! { _ => Counter::new(), };

    let sync_req_state = SyncReqState::new();
    /*let mut ssl_context_builder = ssl::SslContext::builder(ssl::SslMethod::dtls()).unwrap();
    ssl_context_builder.set_options(
        ssl::SslOptions::NO_COMPRESSION
            | (ssl::SslOptions::NO_SSL_MASK & !ssl::SslOptions::NO_DTLSV1_2),
    );

    ssl_context_builder.set_ca_file(&ca_file).unwrap();
    ssl_context_builder.set_verify(ssl::SslVerifyMode::PEER);
    ssl_context_builder
        .set_certificate_file(cert_file, ssl::SslFiletype::PEM)
        .unwrap();
    ssl_context_builder
        .set_private_key_file(priv_key_file, ssl::SslFiletype::PEM)
        .unwrap();

    let mut open_ca = File::open(ca_file).unwrap();
    let mut buffer = Vec::new();
    open_ca.read_to_end(&mut buffer).unwrap();
    ssl_context_builder
        .add_client_ca(&X509::from_pem(&buffer).unwrap())
        .unwrap();*/

    let peer_table = peer_table::PeerTable::new();
    let adapter_docking_session_id = peer_table
        .insert(peer_table::PeerState::new(
            peer_table::PeerType::Adapter, /* TEMP HACK */
            peer_addr,
        ))
        .unwrap();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let tun_devs = TunBuilder::new()
                .name(cmd_line.tun_if.unwrap_or(String::new()).as_str())
                .try_build_mq(tun_queue_count)
                .expect("unable to open TUN device")
                .leak();

            let tun_ctl = Box::leak(Box::new(tun_ctl::TunCtl::new(&tun_devs[0])));

            tun_ctl.set_carrier(false).unwrap();

            let alt = adapter_tables::AgentLookupTable::new();
            let dlt = adapter_tables::DockLookupTable::new();

            // Open ingress sockets.
            let mut sockets = Vec::new();
            for _i in 0..substrate_socket_count {
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
                            + offset_of!(ZdpPerFlowHeader, stream_id))
                            as u32,
                    },
                    // [3] modulo # of queues
                    sf {
                        code: ALU | MOD | K,
                        jt: 0,
                        jf: 0,
                        k: substrate_socket_count,
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

            let asm = Box::leak(Box::new(Assembly {
                buffer_stack,
                mgmt_processor,
                agent_input,
                substrate_egress,
                capture_queue,
                capture_worker,
                flow_control,
                counters,
                tun_ctl: tun_ctl,
                sync_req_state,
                peer_table,
                adapter_docking_session_id,
                alt,
                dlt,
                adapter_manager,
            }));

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
                        _ = usr1_stream.recv() => emit_counts(&asm.counters),
                        _ = term_stream.recv() => {
                            emit_counts(&asm.counters);
                            std::process::exit(128 + SignalKind::terminate().as_raw_value())
                        }
                    }
                }
            });

            js.spawn(mgmt_processor_worker::launch(&*asm, mp_outq));
            js.spawn(adapter_manager_worker::launch(&*asm, am_outq));

            for (worker_index, tun_dev) in tun_devs.iter().enumerate() {
                js.spawn(agent_output_worker::launch(
                    &agent_output_worker::Config {
                        worker_index,
                        batch_size: agent_output_batch_size,
                    },
                    &*asm,
                    tun_dev,
                ));
            }

            js.spawn(rpc_worker::launch(&*asm, &*unix_socket));

            js.spawn(capture_worker::launch(
                &capture_worker::Config {
                    batch_size: capture_batch_size,
                },
                &*asm,
                cap_outq,
            ));

            eprintln!("Connecting...");
            eprintln!("Connected!"); // FIXME: it's a lie
            asm.tun_ctl.set_carrier(true).unwrap();

            for (worker_index, socket) in sockets.iter().enumerate() {
                js.spawn(substrate_ingress_worker::launch(
                    &substrate_ingress_worker::Config {
                        worker_index,
                        batch_size: substrate_ingress_batch_size,
                    },
                    &*asm,
                    socket,
                ));
            }

            mgmt::send_report(asm, asm.adapter_docking_session_id, "Reporting for Duty!").await;
            mgmt::send_discard(asm, asm.adapter_docking_session_id).await;
            mgmt::send_hello_request(asm, asm.adapter_docking_session_id)
                .await
                .unwrap();

            while let Some(res) = js.join_next().await {
                res.unwrap();
            }
        });

    ExitCode::SUCCESS
}

