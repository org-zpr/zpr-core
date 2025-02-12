use crate::sys::unix as common;
use crate::sys::{Platform, PlatformErr};
use std::net::IpAddr;
use std::process::Command;

pub struct MacosPlatform {}

impl Platform for MacosPlatform {
    // TODO: is same as linux
    fn has_root_perms(&self) -> bool {
        common::has_root_perms()
    }

    // On macos it's best to not set a tun name. The mac tun network code will create one.
    fn get_tun_ifname(&self) -> String {
        return String::new();
    }

    fn is_tun_exist(&self, tun_name: &str) -> bool {
        Command::new("ifconfig")
            .arg(tun_name)
            .status()
            .unwrap()
            .success()
    }

    fn set_control_dir_owner_and_perms(
        &self,
        ctrl_path: &std::path::PathBuf,
        username: &str,
        dry_run: bool,
    ) -> Result<(), PlatformErr> {
        common::set_control_dir_owner_and_perms(ctrl_path, username, dry_run)
    }

    fn drop_privledges(&self, _username: &str, dry_run: bool) -> Result<(), PlatformErr> {
        if dry_run {
            println!("drop_privledges is NOP on macos");
        }
        Ok(())
    }

    fn create_tun(
        &self,
        _tun_name: &str,
        _tun_addr: IpAddr,
        _mask: u8,
        _mtu: usize,
        dry_run: bool,
    ) -> Result<(), PlatformErr> {
        // On mac, best to create tun in the PH.
        if dry_run {
            println!("create_tun is NOP on macos");
        }
        Ok(())
    }

    fn exec(&self, cmd: Command, dry_run: bool) -> Result<(), PlatformErr> {
        common::exec(cmd, dry_run)
    }
}
