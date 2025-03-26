//! unix.rs - platform functions common amoung the unix family of OSes.

use nix::sys::stat;
use nix::unistd::{self, Gid, Uid};
use std::os::unix::process::CommandExt;
use std::process::Command;

use users::get_user_by_name;

use crate::sys::PlatformErr;

pub fn has_root_perms() -> bool {
    Uid::effective().is_root()
}

pub fn set_control_dir_owner_and_perms(
    ctrl_path: &std::path::PathBuf,
    username: &str,
    dry_run: bool,
) -> Result<(), PlatformErr> {
    match get_user_by_name(username) {
        None => {
            return Err(PlatformErr::OsError(format!("user {} not found", username)));
        }
        Some(user) => {
            if dry_run {
                println!(
                    "chown {}:{} {}",
                    user.uid(),
                    user.primary_group_id(),
                    ctrl_path.display()
                );
            } else {
                unistd::chown(
                    ctrl_path,
                    Some(Uid::from_raw(user.uid())),
                    Some(Gid::from_raw(user.primary_group_id())),
                )
                .map_err(|e| {
                    PlatformErr::OsError(format!(
                        "chown {:?} as user:{} group:{} failed: {}",
                        ctrl_path,
                        user.uid(),
                        user.primary_group_id(),
                        e
                    ))
                })?;
            }
        }
    };

    // Now set perm to 775
    if dry_run {
        println!("chmod 775 {}", ctrl_path.display());
        return Ok(());
    }

    let dirfd = nix::fcntl::open(
        ctrl_path,
        nix::fcntl::OFlag::O_DIRECTORY,
        nix::sys::stat::Mode::S_IRWXU,
    )
    .map_err(|e| PlatformErr::OsError(format!("open failed on {:?}: {}", ctrl_path, e)))?;

    stat::fchmod(
        dirfd,
        stat::Mode::S_IRWXU | stat::Mode::S_IRWXG | stat::Mode::S_IROTH | stat::Mode::S_IXOTH,
    )
    .map_err(|e| PlatformErr::OsError(format!("fchmod failed: {}", e)))?;
    Ok(())
}

pub fn exec(mut cmd: Command, dry_run: bool) -> Result<(), PlatformErr> {
    if dry_run {
        println!("exec {:?}", cmd);
        return Ok(());
    }
    let err = cmd.exec();
    Err(PlatformErr::IoError(err))
}
