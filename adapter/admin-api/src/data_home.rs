use std::path::PathBuf;
use std::env;

// Return the path to the data home directory. A place we can stash things like
// unix domain sockets. Default is '/var/run/zpr'.
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
