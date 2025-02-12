use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::config::{ConfigRdr, PCErr};
use crate::errors::LaunchErr;
use crate::sys;
use crate::zpr;

// Setup the environment for a successful PH run, includes:
// - create the parent directories for the control socket.
// - create the TUN interface if there isn't one already.
pub fn configure_env(config: &Path, dry_run: bool) -> Result<(), LaunchErr> {
    let rdr = ConfigRdr::new(config)?;

    // Maybe in the future we will have user and group info in the
    // config file.  Here we assume we are operating under sudo.
    let run_as_user = match std::env::var("SUDO_USER") {
        Ok(user) => user,
        Err(_) => {
            return Err(LaunchErr::PCError(PCErr::KeyError(
                "unable to determine run-as user: SUDO_USER not set".to_string(),
            )))
        }
    };

    // The control_path parent directories must exist. This can be set in the
    // config, or there is a default.
    let ctrl_path =
        match rdr.get_config_str_value_for_section_and_key("global", zpr::CONTROL_PATH_KEY) {
            Ok(Some(path)) => PathBuf::from(path),
            Ok(None) => sys::get_data_home(),
            Err(e) => return Err(LaunchErr::PCError(e)),
        };
    if dry_run {
        println!("mkdir -p {}", ctrl_path.display());
    } else {
        fs::create_dir_all(&ctrl_path)?;
    }
    sys::get_platform().set_control_dir_owner_and_perms(&ctrl_path, &run_as_user, dry_run)?;

    let tun_addr_str = rdr.must_get_config_str_value_for_key(zpr::AGENT_ADDR_KEY)?;
    let tun_addr = tun_addr_str
        .parse::<IpAddr>()
        .or(Err(PCErr::KeyError(format!(
            "{} not valid IP address",
            zpr::AGENT_ADDR_KEY
        ))))?;

    let mask = match tun_addr {
        IpAddr::V4(_ipv4) => zpr::IPV4_MASK,
        IpAddr::V6(_ipv6) => zpr::IPV6_MASK,
    };

    let tun_name = match rdr.get_config_str_value_for_key(zpr::TUN_NAME_KEY)? {
        Some(name) => name,
        None => sys::get_platform().get_tun_ifname().to_string(),
    };

    #[cfg(target_os = "macos")]
    {
        if !tun_name.is_empty() {
            println!(
                "warning: on macos it is reccommended to not set a tun name (found {})",
                tun_name
            );
        }
        // The ph will fail anyway, but might as well warn here too.
        match tun_addr {
            IpAddr::V4(_ipv4) => (),
            IpAddr::V6(_ipv6) => {
                println!("warning: IPv6 for agent_addr tunnel address is not supported on macos");
            }
        }
    }

    // TODO: We could check self_addr setting and make sure that we have the
    //       address there on an interface.

    // If TUN already exists we could check to see if it has correct address etc.
    // But for now just notify.
    if sys::get_platform().is_tun_exist(&tun_name) {
        println!(
            "TUN interface {} already exists, skipping TUN configuration",
            tun_name
        );
    } else {
        // Create the tun interface, assign addresses etc.
        sys::get_platform().create_tun(&tun_name, tun_addr, mask, zpr::TUN_MTU, dry_run)?;
    }

    // Now drop root permissions.
    println!(
        "dropping root permissions, switching to user {}",
        run_as_user
    );
    sys::get_platform().drop_privledges(&run_as_user, dry_run)?;

    Ok(())
}
