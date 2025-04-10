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

    fn set_control_dir_owner_and_perms(
        &self,
        ctrl_path: &std::path::PathBuf,
        username: &str,
        dry_run: bool,
    ) -> Result<(), PlatformErr> {
        common::set_control_dir_owner_and_perms(ctrl_path, username, dry_run)
    }

    // On macos we do not drop since we need root to create the TUN interface.
    fn drop_privileges(&self, _username: &str, dry_run: bool) -> Result<(), PlatformErr> {
        if dry_run {
            println!("drop_privileges is NOP on macos");
        }
        Ok(())
    }

    fn create_tun(
        &self,
        tun_name: &str,
        _tun_addr: IpAddr,
        _mask: u8,
        _mtu: usize,
        dry_run: bool,
    ) -> Result<(), PlatformErr> {
        // On mac, best (only possible?) to create tun in the PH.
        if dry_run {
            if tun_name.is_empty() {
                println!("create_tun: does nothing on macos");
            } else {
                println!("will fail with error: on macos tun should be created by ph");
            }
        }
        if !tun_name.is_empty() {
            Err(PlatformErr::OsError(
                "on macos tun should be created by ph: do not set tun_if".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    fn exec(&self, cmd: Command, dry_run: bool) -> Result<(), PlatformErr> {
        common::exec(cmd, dry_run)
    }
}
