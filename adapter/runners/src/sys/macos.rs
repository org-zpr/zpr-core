use std::net::IpAddr;
use std::process::Command;

use crate::sys::{Platform, PlatformErr};

const DEFAULT_TUN_NAME: &str = "tun0";

pub struct MacosPlatform {}

impl Platform for MacosPlatform {
    fn has_root_perms(&self) -> bool {
        panic!("has_root_perms not implemented for macos");
    }

    fn get_tun_ifname(&self) -> String {
        DEFAULT_TUN_NAME.to_string()
    }

    fn is_tun_exist(&self, tun_name: &str) -> bool {
        panic!("is_tun_exist not implemented for macos");
    }

    fn create_tun(
        &self,
        tun_name: &str,
        node_addr: IpAddr,
        mask: u8,
        mtu: usize,
        dry_run: bool,
    ) -> Result<(), PlatformErr> {
        if dry_run {
            println!("will panic due to create_tun not implemented for macos");
            return Ok(());
        }
        panic!("create_tun not implemented for macos");
    }

    fn exec(&self, cmd: Command, dry_run: bool) -> Result<(), PlatformErr> {
        if dry_run {
            println!("will panic due to exec not implemented for macos");
            return Ok(());
        }
        panic!("exec not implemented for macos");
    }
}
