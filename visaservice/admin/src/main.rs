use clap::{Parser, Subcommand};
use std::path::{PathBuf, Path};
use reqwest;
use reqwest::tls::Certificate;
use reqwest::StatusCode;
use std::fs::File;
use std::io::Read;
use std::io::prelude::*;
use std::time::Duration;
use flate2::Compression;
use flate2::write::GzEncoder;
use base64::prelude::*;
use colored::Colorize;

mod apitypes;
use apitypes::{PolicyListEntry, PolicyBundle, PolicyVersion};



// Somewhat inconveniently, this must match the setting in:
// - visaservice/mods/polio/const.go (used by the "new" visa service)
// - zpr-prototype/pkg/snet/policy/const.go (used by the old compiler)
const POLICY_SERIAL_VERSION: u32 = 41;



#[derive(Parser)]
#[command(version, about = "Visa Service Admin Tool", long_about = None)]
struct Cmd {
    #[command(subcommand)]
    command: Option<SubCmd>,

    /// The visa service base API url without any final slash, eg "https://vs.zpr.org:8182".
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
    }

}


fn main() {
    let args = Cmd::parse();

    let ca_cert = load_cert(&args.ca_cert).unwrap();

    match args.command {
        Some(SubCmd::List) => {
            match list(&args.svc_url, ca_cert) {
                Ok(_) => {},
                Err(e) => {
                    eprintln!("{} {}", "Error: ".red(), e);
                }
            }
        }
        Some(SubCmd::Install { policy }) => {
            match install(&args.svc_url, ca_cert, &policy) {
                Ok(_) => {},
                Err(e) => {
                    eprintln!("{} {}", "Error: ".red(), e);
                }
            }
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



fn list(api_url: &str, cert: Certificate)  -> Result<(), Box<dyn std::error::Error>> {
    // TODO: Get rid of this "invalid cert".  I think the issue is that the vs cert does not include correct KeyUsage values.
    let cb = reqwest::blocking::ClientBuilder::new()
        .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10));
    let client = cb.build()?;

    let resp = client.get(format!("{}/admin/policies", api_url)).send()?;
    if !resp.status().is_success() {
        return Err(format!("error (status {:?}:{}) : {}", resp.status(), reason_for(resp.status()), resp.text()?).into());
    }

    let entries: Vec<PolicyListEntry> = resp.json()?;

    let i = 0;
    println!("{}", format!("🐎 found {} installed polic{}", entries.len(), if entries.len() == 1 { "y" } else { "ies" }).magenta());
    for pv in entries {
        let pver = PolicyVersion::new(&pv.version);
        println!("  {}", format!("slot {}", i+1).underline());
        println!("     {} {}", "CONFIG ID:".bold(), pv.config_id);
        println!("       {} {}", "VERSION:".bold(), pver);
    }

    Ok(())
}


fn install(api_url: &str, cert: Certificate, policy: &Path) -> Result<(), Box<dyn std::error::Error>> {
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

    println!("{}", format!("🐎 sending policy: container size {} bytes (raw {} / {} compressed)", container.len(), raw_len, gz_len).magenta());

    let bundle = PolicyBundle {
        config_id: 0,
        version: "".to_string(),
        format: format!("base64;zip;{}", POLICY_SERIAL_VERSION),
        container,
    };

    let resp = client.post(format!("{}/admin/policy", api_url))
        .json(&bundle)
        .send()?;

    if !resp.status().is_success() {
        return Err(format!("error (status {:?}:{}) : {}", resp.status(), reason_for(resp.status()), resp.text()?).into());
    }

    let entry: PolicyListEntry = resp.json()?;
    println!("  {}", "SUCCESS".bold().green());
    println!("     {} {}", "CONFIG ID:".bold(), entry.config_id);
    println!("       {} {}", "VERSION:".bold(), PolicyVersion::new(&entry.version));
    Ok(())
}

fn reason_for(sc: StatusCode) -> String {
    match sc.canonical_reason() {
        Some(reason) => reason.to_string(),
        None => "unknown".to_string(),
    }
}