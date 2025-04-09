use thrift::protocol::{TBinaryInputProtocol, TBinaryOutputProtocol};
use thrift::transport::{ReadHalf, WriteHalf};
use thrift::transport::{TFramedReadTransport, TFramedWriteTransport};
use thrift::transport::{TIoChannel, TTcpChannel};

use std::collections::BTreeMap;
use std::fs::File;
use std::io::prelude::*;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::SystemTime;

use crate::traffic_parser::TrafficDesc;
use vsapi::{TVisaServiceSyncClient, VisaServiceSyncClient};

use libnode::m2;
use libnode::vsapi;

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
    zpr_addr: &IpAddr,
    node_name: &str,
    vss_port: u16,
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

    let provides = vec![format!("/zpr/{}", node_name)];

    let addr_bytes = match zpr_addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };

    let actor = vsapi::Actor {
        actor_type: Some(vsapi::ActorType::NODE),
        attrs: Some(attrs),
        auth_expires: Some((timestamp + 60 * 60) as i64),
        zpr_addr: Some(addr_bytes.clone()),
        tether_addr: Some(addr_bytes),
        ident: Some(String::from("ident-not-generated")), // TODO
        provides: Some(provides),
    };

    let mut certfile = File::open(cert_file)?;
    let mut cert_pem_data = String::new();
    certfile.read_to_string(&mut cert_pem_data)?;

    let hrchal = hello_response.challenge.unwrap();
    let chal_copy = hrchal.clone(); // we send this one back

    let hmac = m2::milestone2_create_hmac(hrchal, hello_response.session_id.unwrap(), timestamp);

    let authreq = vsapi::NodeAuthRequest {
        session_id: hello_response.session_id,
        challenge: Some(chal_copy),
        timestamp: Some(timestamp as i64),
        node_cert: Some(cert_pem_data.into()),
        hmac: Some(hmac),
        vss_service: Some(SocketAddr::new(*zpr_addr, vss_port).to_string()),
        node_actor: Some(actor),
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

pub fn authorize_connect(
    service: &str,
    apikey: &str,
    node_zpr_addr: &IpAddr,
    claims: Vec<String>,
) -> thrift::Result<()> {
    let node_addr_bytes = match node_zpr_addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };

    let mut attrs = BTreeMap::new();
    for c in claims {
        let parts: Vec<&str> = c.splitn(2, '=').collect();
        if parts.len() == 2 {
            attrs.insert(parts[0].to_string(), parts[1].to_string());
        }
    }

    // In initial version of the connect messaging with visa service the following
    // claims must be set:
    //   - "zpr.adapater.cn" set to the CN in the noise certificate presented by the adapter.
    //   - "zpr.addr" the ZPR contact address in use by the adapter.
    if !attrs.contains_key("zpr.adapter.cn") {
        return Err(thrift::Error::from(
            "missing required claim 'zpr.adapter.cn'",
        ));
    }
    if !attrs.contains_key("zpr.addr") {
        return Err(thrift::Error::from("missing required claim 'zpr.addr'"));
    }

    let cid = rand::random::<u16>() as i32;

    // In initial version of this visa service integration we are not using the challenge or challenge-response.
    let req = vsapi::ConnectRequest {
        connection_id: Some(cid),
        dock_addr: Some(node_addr_bytes),
        claims: Some(attrs),
        challenge: None,
        challenge_responses: None,
    };

    let mut client = newclient(service)?;
    match client.authorize_connect(apikey.into(), req) {
        Ok(resp) => {
            let rid = resp.connection_id.unwrap();
            if rid != cid {
                println!(
                    "authorize_connect response: connection_id mismatch (got {}, expected {})",
                    rid, cid
                );
                return Ok(());
            }
            println!("authorize_connect response:");
            match resp.status {
                Some(vsapi::StatusCode::SUCCESS) => {
                    println!("  status: SUCCESS");
                }
                Some(vsapi::StatusCode::FAIL) => {
                    println!("  status: FAILURE");
                }
                None => {
                    println!("  status: none given / unknown") // unexpected
                }
                _ => {
                    println!("  status: {:?}", resp.status) // unexpected
                }
            }
            if let Some(agnt) = resp.actor {
                println!("  actor: {:?}", agnt);
            }
            if let Some(reason) = resp.reason {
                println!("  reason: {}", reason);
            }
        }
        Err(e) => {
            return Err(e);
        }
    };

    Ok(())
}

pub fn actor_disconnect(service: &str, apikey: &str, addrstr: &str) -> thrift::Result<()> {
    let addr: IpAddr = addrstr.parse().unwrap();

    let octets = match addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };

    let mut client = newclient(service)?;
    match client.actor_disconnect(apikey.into(), octets) {
        Ok(result) => {
            println!("actor_disconnect sent!");
            println!("result = {:?}", result);
        }
        Err(e) => {
            return Err(e);
        }
    }
    Ok(())
}

pub fn ping(service: &str, apikey: &str) -> thrift::Result<()> {
    let mut client = newclient(service)?;

    match client.ping(apikey.into()) {
        Ok(result) => {
            println!("PingResponse:");
            println!("    configuration: {}", result.configuration.unwrap());
            println!("   policy version: {}", result.policy_version.unwrap());
        }
        Err(e) => {
            return Err(e);
        }
    }

    Ok(())
}

pub fn request_visa(service: &str, apikey: &str, traffic: &TrafficDesc) -> thrift::Result<()> {
    let l3_type = match traffic.source.is_ipv4() {
        true => 4,
        _ => 6,
    };

    let pktbuf = traffic.build_packet();

    // Tether address is not used in the current version of the ZPR.
    let fake_tether_addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);

    let mut client = newclient(service)?;
    match client.request_visa(
        apikey.into(),
        fake_tether_addr.octets().to_vec(),
        l3_type as i8,
        pktbuf,
    ) {
        Ok(result) => {
            println!("visa request response:");
            match result.status {
                Some(vsapi::StatusCode::SUCCESS) => {
                    println!("  status: SUCCESS");
                }
                Some(vsapi::StatusCode::FAIL) => {
                    println!("  status: FAILURE");
                }
                None => {
                    println!("  status: none given / unknown")
                }
                _ => {
                    println!("  status: {:?}", result.status)
                }
            }
            if result.status.unwrap() != vsapi::StatusCode::SUCCESS {
                match result.reason {
                    Some(reason) => {
                        println!("  reason: {:?}", reason)
                    }
                    None => {
                        println!("  reason: none given")
                    }
                };
            } else {
                if let Some(visa) = result.visa {
                    println!("  visa issuer_id: {}", visa.issuer_id.unwrap());
                    println!("  visa hop_count: {}", visa.hop_count.unwrap());
                    println!("  visa {:?}", visa.visa.unwrap());
                }
            }
        }
        Err(e) => {
            println!("visa request failed");
            return Err(e);
        }
    }
    Ok(())
}
