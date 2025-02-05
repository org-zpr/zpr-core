use std::fs::File;
use std::io::prelude::*;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;



use apitypes::RevokeResponse;
use base64::prelude::*;
use clap::{Args, Parser, Subcommand};
use colored::Colorize;
use flate2::write::GzEncoder;
use flate2::Compression;
use reqwest;
use reqwest::tls::Certificate;
use reqwest::StatusCode;

mod apitypes;
use apitypes::{PolicyBundle, PolicyListEntry, PolicyVersion, VisaDescriptor, HostRecordBrief};

// Somewhat inconveniently, this must match the setting in:
// - visaservice/mods/polio/const.go (used by the "new" visa service)
// - zpr-prototype/pkg/snet/policy/const.go (used by the old compiler)
const POLICY_SERIAL_VERSION: u32 = 41;

#[derive(Parser)]
#[command(version, about = "Visa Service Admin Tool", long_about = None)]
struct Cmd {
    #[command(subcommand)]
    command: Option<SubCmd>,

    /// The visa service base API url without any final slash, eg "https://[fd5a:5052::1]:8182".
    #[arg(short, long, value_name = "URL")]
    svc_url: String,

    /// Path to the CA certificate file used to validate the visa service TLS credentials.
    #[arg(short, long, value_name = "PEM_CERT_FILE")]
    ca_cert: PathBuf,
}

#[derive(Subcommand)]
enum SubCmd {
    /// List installed policy
    #[command()]
    List,

    /// Install a policy from a compiled policy file
    #[command()]
    Install {
        #[arg(short, long, value_name = "POLICY_FILE")]
        policy: PathBuf,
    },

    /// Revoke a visa by ID or an adapter's access by CN.
    #[command()]
    Revoke {
        #[command(flatten)]
        arg: RevokeArg,
    },

    /// List visas
    #[command()]
    Visas,

    /// List agents
    #[command()]
    Agents,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct RevokeArg {
    /// Revoke a visa ID
    #[arg(long)]
    visa_id: Option<u64>,

    /// Revoke access to a given adapter CN
    #[arg(long)]
    agent_cn: Option<String>,
}

fn main() {
    let args = Cmd::parse();

    let ca_cert = load_cert(&args.ca_cert).unwrap();

    match args.command {
        Some(SubCmd::List) => match list(&args.svc_url, ca_cert) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("{} {}", "Error: ".red(), e);
            }
        },
        Some(SubCmd::Install { policy }) => match install(&args.svc_url, ca_cert, &policy) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("{} {}", "Error: ".red(), e);
            }
        },
        Some(SubCmd::Revoke { arg }) if arg.agent_cn.is_some() => {
            revoke_cn(&args.svc_url, ca_cert, arg.agent_cn.unwrap()).unwrap_or_else(|e| {
                eprintln!("{} {}", "Error: ".red(), e);
            });
        }
        Some(SubCmd::Revoke { arg }) if arg.visa_id.is_some() => {
            revoke_visa_id(&args.svc_url, ca_cert, arg.visa_id.unwrap()).unwrap_or_else(|e| {
                eprintln!("{} {}", "Error: ".red(), e);
            });
        }
        Some(SubCmd::Revoke { arg: _ }) => {
            eprintln!(
                "{} {}",
                "Error: ".red(),
                "No adapter CN or visa ID specified"
            );
        }
        Some(SubCmd::Visas) => {
            list_visas(&args.svc_url, ca_cert).unwrap_or_else(|e| {
                eprintln!("{} {}", "Error: ".red(), e);
            });
        }
        Some(SubCmd::Agents) => {
            list_agents(&args.svc_url, ca_cert).unwrap_or_else(|e| {
                eprintln!("{} {}", "Error: ".red(), e);
            });
        }
        None => {
            println!("{}", "No command specified".red());
        }
    }
}

fn load_cert(ca: &Path) -> Result<Certificate, Box<dyn std::error::Error>> {
    let mut cert_buf = Vec::new();
    File::open(ca)?.read_to_end(&mut cert_buf)?;
    let cert = Certificate::from_pem(&cert_buf)?;
    Ok(cert)
}

fn list(api_url: &str, cert: Certificate) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: Get rid of this "invalid cert".  I think the issue is that the vs cert does not include correct KeyUsage values.
    let cb = reqwest::blocking::ClientBuilder::new()
        .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10));
    let client = cb.build()?;

    let resp = client.get(format!("{}/admin/policies", api_url)).send()?;
    if !resp.status().is_success() {
        return Err(format!(
            "error (status {:?}:{}) : {}",
            resp.status(),
            reason_for(resp.status()),
            resp.text()?
        )
        .into());
    }

    let entries: Vec<PolicyListEntry> = resp.json()?;

    let i = 0;
    println!(
        "{}",
        format!(
            "🐎 found {} installed polic{}",
            entries.len(),
            if entries.len() == 1 { "y" } else { "ies" }
        )
        .magenta()
    );
    for pv in entries {
        let pver = PolicyVersion::new(&pv.version);
        println!("  {}", format!("slot {}", i + 1).underline());
        println!("     {} {}", "CONFIG ID:".bold(), pv.config_id);
        println!("       {} {}", "VERSION:".bold(), pver);
    }

    Ok(())
}

fn install(
    api_url: &str,
    cert: Certificate,
    policy: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let cb = reqwest::blocking::ClientBuilder::new()
        .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10));
    let client = cb.build()?;

    let mut policy_buf = Vec::new();
    File::open(policy)?.read_to_end(&mut policy_buf)?;

    let raw_len = policy_buf.len();

    // compress policy data with gzip
    let mut gz_w = GzEncoder::new(Vec::new(), Compression::default());
    gz_w.write_all(&policy_buf)?;
    let gz_bytes = gz_w.finish()?;

    let gz_len = gz_bytes.len();

    // encode the compressed data as base64
    let container = BASE64_STANDARD.encode(&gz_bytes);

    println!(
        "{}",
        format!(
            "🐎 sending policy: container size {} bytes (raw {} / {} compressed)",
            container.len(),
            raw_len,
            gz_len
        )
        .magenta()
    );

    let bundle = PolicyBundle {
        config_id: 0,
        version: "".to_string(),
        format: format!("base64;zip;{}", POLICY_SERIAL_VERSION),
        container,
    };

    let resp = client
        .post(format!("{}/admin/policy", api_url))
        .json(&bundle)
        .send()?;

    if !resp.status().is_success() {
        return Err(format!(
            "error (status {:?}:{}) : {}",
            resp.status(),
            reason_for(resp.status()),
            resp.text()?
        )
        .into());
    }

    let entry: PolicyListEntry = resp.json()?;
    println!("  {}", "SUCCESS".bold().green());
    println!("     {} {}", "CONFIG ID:".bold(), entry.config_id);
    println!(
        "       {} {}",
        "VERSION:".bold(),
        PolicyVersion::new(&entry.version)
    );
    Ok(())
}

fn revoke_cn(
    _api_url: &str,
    _cert: Certificate,
    _adapter_cn: String,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("Not implemented".into())
}

fn revoke_visa_id(
    api_url: &str,
    cert: Certificate,
    visa_id: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let cb = reqwest::blocking::ClientBuilder::new()
        .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10));
    let client = cb.build()?;

    let resp = client.delete(format!("{}/admin/visas/{}", api_url, visa_id)).send()?;
    if !resp.status().is_success() {
        return Err(format!(
            "error (status {:?}:{}) : {}",
            resp.status(),
            reason_for(resp.status()),
            resp.text()?
        )
        .into());
    }

    let rr: RevokeResponse = resp.json()?;
    if rr.revoked.is_empty() {
        println!("  {}", "ERROR".bold().red());
    } else {
        println!("  {}", "SUCCESS".bold().green());
        println!("     {} {}", "REVOKED:".bold(), rr.revoked);
    }
    Ok(())
}

fn list_visas(api_url: &str, cert: Certificate) -> Result<(), Box<dyn std::error::Error>> {
    let cb = reqwest::blocking::ClientBuilder::new()
        .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10));
    let client = cb.build()?;

    let resp = client.get(format!("{}/admin/visas", api_url)).send()?;
    if !resp.status().is_success() {
        return Err(format!(
            "error (status {:?}:{}) : {}",
            resp.status(),
            reason_for(resp.status()),
            resp.text()?
        )
        .into());
    }

    let mut entries: Vec<VisaDescriptor> = resp.json()?;
    entries.sort_by(|a, b| a.id.cmp(&b.id));


    println!(
        "{}",
        format!(
            "🐎 found {} installed visa{}",
            entries.len(),
            if entries.len() == 1 { "" } else { "s" }
        )
        .magenta()
    );
    for vd in entries {
        println!("{vd}");
    }
    Ok(())
}

fn list_agents(api_url: &str, cert: Certificate) -> Result<(), Box<dyn std::error::Error>> {
    let cb = reqwest::blocking::ClientBuilder::new()
        .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10));
    let client = cb.build()?;

    let resp = client.get(format!("{}/admin/agents", api_url)).send()?;
    if !resp.status().is_success() {
        return Err(format!(
            "error (status {:?}:{}) : {}",
            resp.status(),
            reason_for(resp.status()),
            resp.text()?
        )
        .into());
    }

    let entries: Vec<HostRecordBrief> = resp.json()?;

    println!(
        "{}",
        format!(
            "🐎 found {} agent{}",
            entries.len(),
            if entries.len() == 1 { "" } else { "s" }
        )
        .magenta()
    );
    for hr in entries {
        println!("{hr}");
    }
    Ok(())
}

fn reason_for(sc: StatusCode) -> String {
    match sc.canonical_reason() {
        Some(reason) => reason.to_string(),
        None => "unknown".to_string(),
    }
}
