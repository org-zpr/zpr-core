#![allow(dead_code)]
mod adapter_tables;
mod address_pool;
mod assembly;
mod auth;
mod batch_io;
mod capture_worker;
mod classifier;
mod config;
mod counters;
mod defs;
mod five_tuple_lookup_table;
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
mod mgmt_processor_worker;
mod packet;
mod packet_queue;
mod pcap_writer;
mod peer_table;
mod pki;
mod queues;
mod rcu;
mod sample_ring;
mod special_peers;
mod sys;
mod tc;
mod test_packet;
mod tlv;
mod tun_ctl;
mod two_way_queue;
mod visa_mgmt;
mod visa_table;
mod zdp;
mod zdpr;
mod zdpr_worker;
mod zprtun;

use clap::{CommandFactory, Parser};
use clap_complete::{generate, shells::Shell};
use std::fs::File;
use std::fs::create_dir_all;
use std::io::BufWriter;

#[derive(Parser, Debug)]
#[command(version, about = "This program creates the shell completion files for the PH/Adapter", long_about = None, override_usage = "cargo run --features complete --bin generate_completions -- --generate <PATH>")]
struct Args {
    // Path to the generations file you want to create
    #[arg(long, short = 'g')]
    generate: String,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    generate_completion(args.generate)?;

    Ok(())
}

fn generate_completion(path: String) -> std::io::Result<()> {
    let shells_exts: Vec<(Shell, &str)> = Vec::from([
        (Shell::Bash, "sh"),
        (Shell::Elvish, "elv"),
        (Shell::Fish, "fish"),
        (Shell::PowerShell, "ps1"),
        (Shell::Zsh, "zsh"),
    ]);

    create_dir_all(&path)?;

    for (shell, extension) in shells_exts {
        let formatted_path = format!("{path}/ph.{extension}");
        let file = File::create(formatted_path)?;
        let mut writer = BufWriter::new(file);
        generate(
            shell,
            &mut main_args::Control::command(),
            main_args::Control::command().get_name().to_string(),
            &mut writer,
        );
    }

    Ok(())
}
