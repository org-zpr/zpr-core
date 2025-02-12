use nix::unistd::{self, Gid, Uid};
use users::get_user_by_name;

use std::net::IpAddr;
use std::process::Command;

use crate::sys::unix as common;
use crate::sys::{Platform, PlatformErr};

const DEFAULT_TUN_NAME: &str = "tun0";

pub struct LinuxPlatform {}

impl Platform for LinuxPlatform {
    fn has_root_perms(&self) -> bool {
        common::has_root_perms()
    }

    // TODO: in future could have code to find an unused tun
    fn get_tun_ifname(&self) -> String {
        DEFAULT_TUN_NAME.to_string()
    }

    fn set_control_dir_owner_and_perms(
        &self,
        ctrl_path: &std::path::PathBuf,
        username: &str,
        dry_run: bool,
    ) -> Result<(), PlatformErr> {
        common::set_control_dir_owner_and_perms(ctrl_path, username, dry_run)
    }

    fn drop_privledges(&self, username: &str, dry_run: bool) -> Result<(), PlatformErr> {
        let user = get_user_by_name(username)
            .ok_or(PlatformErr::OsError(format!("user {} not found", username)))?;
        if dry_run {
            println!("setgid {} setuid {}", user.primary_group_id(), user.uid());
            for grp in user.groups().unwrap() {
                if grp.gid() == user.primary_group_id() {
                    continue;
                }
                println!(
                    "  supplimentary group {} ({})",
                    grp.name().to_str().unwrap(),
                    grp.gid()
                );
            }
            return Ok(());
        }
        // In virtual box (at least) it is critical to set the supplimentary groups
        // since the whole filesystem may require membership in special `vboxsf` group.
        unistd::setgroups(
            &user
                .groups()
                .unwrap()
                .iter()
                .map(|g| Gid::from_raw(g.gid()))
                .collect::<Vec<Gid>>(),
        )
        .map_err(|e| PlatformErr::OsError(format!("setgroups failed: {}", e)))?;
        unistd::setgid(Gid::from_raw(user.primary_group_id()))
            .map_err(|e| PlatformErr::OsError(format!("setgid failed: {}", e)))?;
        unistd::setuid(Uid::from_raw(user.uid()))
            .map_err(|e| PlatformErr::OsError(format!("setuid failed: {}", e)))?;
        Ok(())
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
        tun_addr: IpAddr,
        mask: u8,
        mtu: usize,
        dry_run: bool,
    ) -> Result<(), PlatformErr> {
        let addr_and_mask = format!("{}/{}", tun_addr, mask);
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

    fn exec(&self, cmd: Command, dry_run: bool) -> Result<(), PlatformErr> {
        common::exec(cmd, dry_run)
    }
}
