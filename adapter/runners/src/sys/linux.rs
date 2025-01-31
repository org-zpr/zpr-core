use nix::unistd::Uid;
use std::net::IpAddr;
use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::sys::{Platform, PlatformErr};

const DEFAULT_TUN_NAME: &str = "tun0";

pub struct LinuxPlatform {}

impl Platform for LinuxPlatform {
    fn has_root_perms(&self) -> bool {
        Uid::effective().is_root()
    }

    // TODO: in future could have code to find an unused tun
    fn get_tun_ifname(&self) -> String {
        DEFAULT_TUN_NAME.to_string()
    }

    fn is_tun_exist(&self, tun_name: &str) -> bool {
        Command::new("ip")
            .arg("link")
            .arg("show")
            .arg(tun_name)
            .status()
            .unwrap()
            .success()
    }

    fn create_tun(
        &self,
        tun_name: &str,
        node_addr: IpAddr,
        mask: u8,
        mtu: usize,
        dry_run: bool,
    ) -> Result<(), PlatformErr> {
        let addr_and_mask = format!("{}/{}", node_addr, mask);
        {
            let mut c = Command::new("ip");
            c.arg("tuntap")
                .arg("add")
                .arg("name")
                .arg(tun_name)
                .arg("mode")
                .arg("tun")
                .arg("multi_queue");
            if dry_run {
                println!("run {:?}", c);
            } else {
                c.status().map_err(|e| {
                    PlatformErr::OsError(format!("failed to create tun interface: {}", e))
                })?;
            }
        }
        {
            let mut c = Command::new("ip");
            c.arg("link")
                .arg("set")
                .arg(tun_name)
                .arg("mtu")
                .arg(mtu.to_string());
            if dry_run {
                println!("run {:?}", c);
            } else {
                c.status()
                    .map_err(|e| PlatformErr::OsError(format!("failed to set mtu: {}", e)))?;
            }
        }
        {
            let mut c = Command::new("ip");
            c.arg("addr")
                .arg("add")
                .arg(addr_and_mask)
                .arg("dev")
                .arg(tun_name);
            if dry_run {
                println!("run {:?}", c);
            } else {
                c.status()
                    .map_err(|e| PlatformErr::OsError(format!("failed to set address: {}", e)))?;
            }
        }
        {
            let mut c = Command::new("ip");
            c.arg("link").arg("set").arg(tun_name).arg("up");
            if dry_run {
                println!("run {:?}", c);
            } else {
                c.status().map_err(|e| {
                    PlatformErr::OsError(format!("failed to bring up interface: {}", e))
                })?;
            }
        }
        Ok(())
    }

    fn exec(&self, mut cmd: Command, dry_run: bool) -> Result<(), PlatformErr> {
        if dry_run {
            println!("exec {:?}", cmd);
            return Ok(());
        }
        let err = cmd.exec();
        Err(PlatformErr::IoError(err))
    }
}
