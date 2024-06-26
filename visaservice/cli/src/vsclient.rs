use thrift::protocol::{TBinaryInputProtocol, TBinaryOutputProtocol};
use thrift::transport::{ReadHalf, WriteHalf};
use thrift::transport::{TFramedReadTransport, TFramedWriteTransport};
use thrift::transport::{TIoChannel, TTcpChannel};

// Tried to use the rust crypt* crates, but could not figure out how to get an HMAC.
// And its not clear how to use an RSA private key with the ring crage HMAC.
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::Signer;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::prelude::*;
use std::net::IpAddr;
use std::time::SystemTime;

use crate::vsapi;

use vsapi::{TVisaServiceSyncClient, VisaServiceSyncClient};

// ugh!!
type VSClientT = VisaServiceSyncClient<
    TBinaryInputProtocol<TFramedReadTransport<ReadHalf<TTcpChannel>>>,
    TBinaryOutputProtocol<TFramedWriteTransport<WriteHalf<TTcpChannel>>>,
>;

fn newclient(service: &str) -> thrift::Result<VSClientT> {
    let mut c = TTcpChannel::new();
    c.open(service)?;

    let (i_chan, o_chan) = c.split()?;

    let i_prot = TBinaryInputProtocol::new(TFramedReadTransport::new(i_chan), true);
    let o_prot = TBinaryOutputProtocol::new(TFramedWriteTransport::new(o_chan), true);

    Ok(vsapi::VisaServiceSyncClient::new(i_prot, o_prot))
}

pub fn hello(service: &str) -> thrift::Result<()> {
    let mut client = newclient(service)?;
    match client.hello() {
        Ok(result) => {
            println!("HelloResponse:");
            println!("   session_id: {}", result.session_id.unwrap());
            println!("   challenge:");
            if let Some(chal) = result.challenge {
                println!("      challenge_type: {}", chal.challenge_type.unwrap());
                if let Some(cdata) = chal.challenge_data {
                    println!("      challenge_data: {}", hex::encode(cdata));
                }
            }
        }
        Err(e) => {
            return Err(e);
        }
    }
    Ok(())
}

pub fn authenticate(
    service: &str,
    claim: Vec<String>,
    cert_file: &str,
    private_key_file: &str,
) -> thrift::Result<()> {
    let mut client = newclient(service)?;

    println!("sending HELLO");
    let hello_response = client.hello()?;
    println!("HELLO OK");

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut attrs = BTreeMap::new();
    for c in claim {
        let parts: Vec<&str> = c.splitn(2, '=').collect();
        if parts.len() == 2 {
            attrs.insert(parts[0].to_string(), parts[1].to_string());
        }
    }

    let provides = vec![String::from("/zpr/node")];

    // Two IPv6 addresses
    let zpraddr = vec![0xfc, 0, 0x30, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let tetheraddr = vec![0xfc, 0, 0x30, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    let agent = vsapi::Agent {
        agent_type: Some(vsapi::AgentType::NODE),
        attrs: Some(attrs),
        auth_expires: Some((timestamp + 60 * 60) as i64),
        zpr_addr: Some(zpraddr),
        tether_addr: Some(tetheraddr),
        ident: Some(String::from("ident-not-generated")), // TODO
        provides: Some(provides),
    };

    let mut certfile = File::open(cert_file)?;
    let mut cert_pem_data = String::new();
    certfile.read_to_string(&mut cert_pem_data)?;

    let mut keyfile = File::open(private_key_file)?;
    let mut key_pem_data = String::new();
    keyfile.read_to_string(&mut key_pem_data)?;

    let hrchal = hello_response.challenge.unwrap();
    let chal_copy = hrchal.clone(); // we send this one back

    let key = Rsa::private_key_from_pem(key_pem_data.as_bytes()).unwrap();
    let pkey = PKey::from_rsa(key).unwrap();

    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();

    let mut buf = Vec::new();
    buf.write_all(&hrchal.challenge_data.unwrap()).unwrap();

    signer.update(&buf).unwrap();
    signer.update(&timestamp.to_be_bytes()).unwrap();
    signer
        .update(&hello_response.session_id.unwrap().to_be_bytes())
        .unwrap();

    let hmac = signer.sign_to_vec().unwrap();

    let authreq = vsapi::NodeAuthRequest {
        session_id: hello_response.session_id,
        challenge: Some(chal_copy),
        timestamp: Some(timestamp as i64),
        node_cert: Some(cert_pem_data.into()),
        hmac: Some(hmac),
        node_agent: Some(agent),
    };

    match client.authenticate(authreq) {
        Ok(result) => {
            println!("authenticate sent!");
            println!("result = {:?}", result);
        }
        Err(e) => {
            return Err(e);
        }
    }

    Ok(())
}

pub fn deregister(service: &str, apikey: &str) -> thrift::Result<()> {
    let mut client = newclient(service)?;
    match client.de_register(apikey.into()) {
        Ok(result) => {
            println!("de_register sent!");
            println!("result = {:?}", result);
        }
        Err(e) => {
            return Err(e);
        }
    }
    Ok(())
}

pub fn disconnect(service: &str, apikey: &str, addrstr: &str) -> thrift::Result<()> {
    let addr: IpAddr = addrstr.parse().unwrap();

    let octets = match addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };

    let mut client = newclient(service)?;
    match client.agent_disconnect(apikey.into(), octets) {
        Ok(result) => {
            println!("agent_disconnect sent!");
            println!("result = {:?}", result);
        }
        Err(e) => {
            return Err(e);
        }
    }
    Ok(())
}

pub fn poll(service: &str, apikey: &str) -> thrift::Result<()> {
    let mut client = newclient(service)?;

    match client.poll(apikey.into()) {
        Ok(result) => {
            print!("PollResponse:  (more = ");
            if result.more.unwrap() > 0 {
                print!("YES");
            } else {
                print!("NO");
            }
            println!(")");
            if let Some(visas) = result.visas {
                println!("  Got {} visas", visas.len());
                for visa in visas {
                    println!(
                        "    visa {}   hop_count {}    size {} bytes",
                        visa.issuer_id.unwrap(),
                        visa.hop_count.unwrap(),
                        visa.visa_pb.unwrap().len()
                    );
                }
            } else {
                println!("  0 visas")
            }
            if let Some(revokes) = result.revocations {
                println!("  Got {} revocations", revokes.len());
                for revoke in revokes {
                    println!(
                        "    revoke issuer_id {}, config_id {}",
                        revoke.issuer_id.unwrap(),
                        revoke.configuration.unwrap()
                    );
                }
            } else {
                println!("  0 revocations")
            }
        }
        Err(e) => {
            return Err(e);
        }
    }

    Ok(())
}
