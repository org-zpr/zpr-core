use std::env;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;

use thiserror::Error;

#[cfg(target_family = "unix")]
pub(crate) mod unix;

#[cfg(target_os = "linux")]
pub(crate) mod linux;

#[cfg(target_os = "macos")]
pub(crate) mod macos;

#[derive(Debug, Error)]
pub enum PlatformErr {
    #[error("os error: {0}")]
    OsError(String),

    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Our "interface" to platform specific functions.
pub trait Platform {
    /// Return true if currently executing under "root" permissions.
    /// We need this to determine if we can create and manipulate a TUN interface.
    /// And also the ph itself needs to run as root.
    fn has_root_perms(&self) -> bool;

    /// Return the default TUN interface name for this platform.
    fn get_tun_ifname(&self) -> String;

    /// Check if a TUN interface with the given name exists.
    fn is_tun_exist(&self, tun_name: &str) -> bool;

    /// The control directory holds the control socket for the ph.
    /// This function sets the owner and permissions on the control directory.
    fn set_control_dir_owner_and_perms(
        &self,
        ctrl_path: &PathBuf,
        username: &str,
        dry_run: bool,
    ) -> Result<(), PlatformErr>;

    /// Drop root privileges by switching to the given OS user.
    fn drop_privileges(&self, username: &str, dry_run: bool) -> Result<(), PlatformErr>;

    /// Create a TUN interface with the given name, IP address, mask, and MTU.
    fn create_tun(
        &self,
        tun_name: &str,
        tun_addr: IpAddr,
        mask: u8,
        mtu: usize,
        dry_run: bool,
    ) -> Result<(), PlatformErr>;

    /// Replace currently running process with the given command.
    fn exec(&self, cmd: Command, dry_run: bool) -> Result<(), PlatformErr>;
}

/// Return a Platform object for the current platform.
pub fn get_platform() -> Box<dyn Platform> {
    #[cfg(target_os = "linux")]
    return Box::new(linux::LinuxPlatform {});

    #[cfg(target_os = "macos")]
    return Box::new(macos::MacosPlatform {});

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    panic!("unsupported platform");
}

/// Copied out of the ph main_args source. Returns the default directory that the
/// ph will use for its control socket.
pub fn get_data_home() -> PathBuf {
    let mut dh = match env::var("XDG_DATA_HOME") {
        Ok(val) => PathBuf::from(val),
        Err(_) => match env::var("HOME") {
            Ok(val) => {
                let mut pb = PathBuf::from(val);
                pb.push(".local/share");
                // Now we will only take this if user already has a .local/share dir.
                if pb.exists() {
                    pb
                } else {
                    PathBuf::from("/var/run")
                }
            }
            Err(_) => PathBuf::from("/var/run"),
        },
    };
    dh.push("zpr");
    dh
}
