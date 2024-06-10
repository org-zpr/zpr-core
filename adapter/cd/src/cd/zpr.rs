use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::io::{BufReader, Error, ErrorKind, Read};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::info;

use crate::cd::startmeup::do_start_me_up;

#[derive(Debug, Clone, PartialEq)]
pub enum ConfigState {
    Connecting,
    Connected(Instant),
    Disconnecting,
    Disconnected,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Configuration {
    #[serde(skip)]
    path_name: String,

    profile: Profile,
    dock: Dock,
    adapter: Adapter,
    // TODO: credentials: Credentials,
}

#[derive(Debug, Clone, Deserialize)]
struct Profile {
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Dock {
    host_or_ip: String,
    startup_port: u16,
    certificate: String, // path to node key file in DER format (TODO: ability to just use a PEM cert here!!)
}

#[derive(Debug, Clone, Deserialize)]
struct Adapter {
    private_key: Option<String>, // base64 noise key
    public_key: Option<String>, // base64 noise key (TODO: should be able to derive from private key)
}

pub fn load_configuration(path: &str) -> Result<Configuration, std::io::Error> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut toml_text = String::new();
    let len = reader.read_to_string(&mut toml_text)?;
    if len == 0 {
        return Err(Error::new(
            ErrorKind::Other,
            format!("Empty configuration file: {}", path),
        ));
    }
    let mut c: Configuration = match toml::from_str(&toml_text) {
        Ok(c) => c,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Error parsing configuration file {}: {}", path, e),
            ))
        }
    };
    c.path_name = path.to_string();
    Ok(c)
}

impl Configuration {
    pub fn get_name(&self) -> &str {
        self.profile.name.as_str()
    }

    pub fn get_dock_host(&self) -> &str {
        self.dock.host_or_ip.as_str()
    }

    pub fn get_dock_startup_port(&self) -> u16 {
        self.dock.startup_port
    }

    pub fn get_path(&self) -> &str {
        self.path_name.as_str()
    }

    // Returns a filename (possibly relative to the config file path)
    pub fn get_dock_certificate(&self) -> &str {
        self.dock.certificate.as_str()
    }

    pub fn get_adapter_public_key(&self) -> Option<&str> {
        self.adapter.public_key.as_deref()
    }
}

// Zpr is the "shared state" for the control daemon. Not quite sure yet what will be in
// here.  For now is holding state information about configurations.
//
// This pattern on an Arc and then a Mutex is copied from the tokio "best practice" as
// illustrated in the redis example.
#[derive(Debug, Clone)]
pub struct Zpr {
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    configurations: HashMap<String, (Configuration, ConfigState)>, // indexed by configuration.profile.name.
}

impl Default for Zpr {
    fn default() -> Self {
        Zpr::new()
    }
}

impl Zpr {
    pub fn new() -> Zpr {
        Zpr {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    configurations: HashMap::new(),
                }),
            }),
        }
    }

    // If a configuration exists with the same path, we overrite the existing one but only if it is disconnected.
    pub fn add_configuration(&self, c: Configuration) -> Result<(), std::io::Error> {
        let mut found = false;
        let mut found_name: String = String::new();
        let mut state = self.shared.state.lock().unwrap();
        for (conf, state) in state.configurations.values() {
            if conf.path_name == c.path_name {
                found = true;
                found_name = conf.get_name().to_string();
                if !matches!(state, ConfigState::Disconnected) {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "Configuration already exists and is not disconnected",
                    ));
                }
            }
        }
        if found {
            // If the names are the same, just writing our new config will overwrite the existing one.
            if found_name != c.profile.name {
                state.configurations.remove(&found_name);
            }
        } else {
            // The new path is not present, but also we require a unique name.
            if state.configurations.contains_key(c.get_name()) {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Configuration with name {} already exists", c.profile.name),
                ));
            }
        }

        state
            .configurations
            .insert(c.get_name().to_string(), (c, ConfigState::Disconnected));
        Ok(())
    }

    // Mock up status function.  This returns a vector of (CONFIG_NAME, ENDPOINT, STATUS)
    pub fn get_status(&self) -> Vec<(String, String, String)> {
        let mut status = Vec::new();
        let state = self.shared.state.lock().unwrap();
        for (cname, (conf, state)) in &state.configurations {
            let s = match state {
                ConfigState::Connecting => String::from("connecting"),
                ConfigState::Connected(ctime) => {
                    let now = Instant::now();
                    let elapsed = now.duration_since(*ctime);
                    format!("connected {}s", elapsed.as_secs())
                }
                ConfigState::Disconnecting => String::from("disconnecting"),
                ConfigState::Disconnected => String::from("disconnected"),
            };
            status.push((cname.clone(), conf.dock.host_or_ip.clone(), s));
        }
        status
    }

    pub fn get_configuration_state(&self, name: &str) -> Option<ConfigState> {
        let state = self.shared.state.lock().unwrap();
        let cfg = state.configurations.get(name);
        cfg?;
        let (_, cs) = cfg.unwrap();
        Some(cs.clone())
    }

    // This public access to the status property is temporary.  As this is developed the status
    // value will depend on the outcome of operations or reactions to events.
    //
    // For example, when `start_me_up` succeeds, the status moves to "connected".
    pub fn set_status(&self, name: &str, status: ConfigState) -> Result<(), std::io::Error> {
        let mut state = self.shared.state.lock().unwrap();
        let conf_state_tuple = state.configurations.get_mut(name).ok_or_else(|| {
            Error::new(
                ErrorKind::Other,
                format!("Configuration with name {} not found", name),
            )
        })?;
        conf_state_tuple.1 = status;
        Ok(())
    }

    pub fn has_configuration(&self, name: &str) -> bool {
        let state = self.shared.state.lock().unwrap();
        state.configurations.contains_key(name)
    }

    // Perform the start-me-up protocol using the named configuration.
    pub async fn start_me_up(&self, name: &str) -> Result<(), std::io::Error> {
        let cc = match self.start_me_up_prepare(name) {
            Ok(c) => c,
            Err(e) => {
                return Err(e);
            }
        };

        // Do the start-me-up protocol here.
        match do_start_me_up(&cc).await {
            Err(e) => {
                // Set the state back to disconnected.
                let _ = self.set_status(name, ConfigState::Disconnected);
                Err(e)
            }
            Ok(resp) => {
                // TODO: Figure out what todo with our new information.
                info!(
                    config = name,
                    dock_wg_port = resp.wg_port,
                    local_wg_addr = format!("{:?}", resp.local_wg_addr),
                    "start-me-up sucess"
                );
                self.set_status(name, ConfigState::Connected(Instant::now()))
            }
        }
    }

    // Prepare for start-me-up by setting the state of the config to "connecting".
    // Returns a clone of the configuration.
    fn start_me_up_prepare(&self, name: &str) -> Result<Configuration, std::io::Error> {
        let mut state = self.shared.state.lock().unwrap();
        let conf_state_tuple = state.configurations.get_mut(name).ok_or_else(|| {
            Error::new(
                ErrorKind::Other,
                format!("Configuration with name {} not found", name),
            )
        })?;
        let (_, conf_state) = conf_state_tuple;
        // In order to start the state must be in disconnected.
        if !matches!(conf_state, ConfigState::Disconnected) {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Configuration {} is not disconnected", name),
            ));
        }
        conf_state_tuple.1 = ConfigState::Connecting;

        // Loose the MUT reference and get a read-only one:
        let conf_state_tuple = state.configurations.get(name).ok_or_else(|| {
            Error::new(
                ErrorKind::Other,
                format!("Configuration with name {} not found", name),
            )
        })?;
        let (conf, _) = conf_state_tuple;
        Ok(conf.clone())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;
    use std::env;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempTomlFile {
        path: String,
    }

    impl Drop for TempTomlFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    impl TempTomlFile {
        fn new(contents: &str) -> TempTomlFile {
            let mut rng = rand::thread_rng();
            let tstamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let dir = env::temp_dir();
            let num: u32 = rng.gen();
            let path = dir.join(format!("org_zpr_cd_test_{}_{}.toml", num, tstamp));
            fs::write(&path, contents).expect("Unable to write file");
            TempTomlFile {
                path: path.to_str().unwrap().to_string(),
            }
        }

        fn get_path(&self) -> &str {
            self.path.as_str()
        }
    }

    #[test]
    fn test_load_configuration() {
        let toml_txt = r#"
            [profile]
            name = "test"
            [dock]
            host_or_ip = "localhost"
            startup_port = 2242
            certificate = "missing"
            [adapter]
            #blank
        "#;
        let tmpfile = TempTomlFile::new(toml_txt);
        let c = load_configuration(tmpfile.get_path());
        if let Err(e) = c {
            panic!("Error loading configuration: {}", e);
        }
        assert!(c.is_ok());
        let c = c.unwrap();
        assert_eq!(c.profile.name, "test");
        assert_eq!(c.get_name(), "test");
        assert_eq!(c.dock.host_or_ip, "localhost");
        assert_eq!(c.dock.startup_port, 2242);
        assert_eq!(c.adapter.private_key, None);
    }

    #[test]
    fn test_add_configuration() {
        let toml_txt = r#"
            [profile]
            name = "test"
            [dock]
            host_or_ip = "localhost"
            startup_port = 2242
            certificate = "missing"
            [adapter]
            #blank
        "#;
        let tmpfile = TempTomlFile::new(toml_txt);
        let c = load_configuration(tmpfile.get_path());
        assert!(c.is_ok());

        let conf = c.unwrap();
        let zpr = Zpr::new();

        let mut stats = zpr.get_status();
        assert_eq!(stats.len(), 0);

        let r = zpr.add_configuration(conf);
        if let Err(e) = r {
            panic!("Error adding configuration to Zpr: {}", e);
        }
        assert!(r.is_ok());

        stats = zpr.get_status();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].0, "test");
        assert_eq!(stats[0].1, "localhost");
        assert_eq!(stats[0].2, "disconnected");
    }

    #[test]
    fn test_cannot_have_duplicate_name() {
        let toml_txt = r#"
            [profile]
            name = "test"
            [dock]
            host_or_ip = "localhost"
            startup_port = 2242
            certificate = "missing"
            [adapter]
            #blank
        "#;
        let tmpfile1 = TempTomlFile::new(toml_txt);
        let c = load_configuration(tmpfile1.get_path());
        assert!(c.is_ok());
        let conf = c.unwrap();

        let zpr = Zpr::new();

        let r = zpr.add_configuration(conf);
        if let Err(e) = r {
            panic!("Error adding configuration to Zpr: {}", e);
        }
        assert!(r.is_ok());

        let toml_txt = r#"
            [profile]
            name = "test"
            [dock]
            host_or_ip = "anotherlocalhost"
            startup_port = 2243
            certificate = "missing"
            [adapter]
            #blank
        "#;
        let tmpfile2 = TempTomlFile::new(toml_txt);
        let c = load_configuration(tmpfile2.get_path());
        assert!(c.is_ok());
        let conf2 = c.unwrap();
        let r = zpr.add_configuration(conf2);
        assert!(r.is_err());
        let e = r.unwrap_err();
        assert!(e
            .to_string()
            .contains("Configuration with name test already exists"));
    }

    #[test]
    fn test_empty_zpr_no_crash() {
        let zpr = Zpr::new();
        let stats = zpr.get_status();
        assert_eq!(stats.len(), 0);
        assert!(zpr.get_configuration_state("foo").is_none());
        let r = zpr.set_status("foo", ConfigState::Disconnected);
        assert!(r.is_err());
        let e = r.unwrap_err();
        assert!(e
            .to_string()
            .contains("Configuration with name foo not found"));
    }

    #[test]
    fn test_set_state() {
        let toml_txt = r#"
            [profile]
            name = "test"
            [dock]
            host_or_ip = "localhost"
            startup_port = 2242
            certificate = "missing"
            [adapter]
            #blank
        "#;
        let tmpfile = TempTomlFile::new(toml_txt);
        let c = load_configuration(tmpfile.get_path());
        assert!(c.is_ok());
        let conf = c.unwrap();
        let zpr = Zpr::new();
        let r = zpr.add_configuration(conf);
        assert!(r.is_ok());

        let state = zpr.get_configuration_state("test");
        assert!(state.is_some());
        assert_eq!(state.unwrap(), ConfigState::Disconnected);

        let r = zpr.set_status("test", ConfigState::Connecting);
        assert!(r.is_ok());
        let state = zpr.get_configuration_state("test");
        assert!(state.is_some());
        assert_eq!(state.unwrap(), ConfigState::Connecting);

        let r = zpr.set_status("test", ConfigState::Connected(Instant::now()));
        assert!(r.is_ok());
        let state = zpr.get_configuration_state("test");
        assert!(state.is_some());
        assert!(matches!(state.unwrap(), ConfigState::Connected(_)));
    }
}
