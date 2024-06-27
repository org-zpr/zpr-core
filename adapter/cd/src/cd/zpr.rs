use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::cd::config::ConfigRecord;





#[derive(Debug, Clone, PartialEq)]
pub enum ConfigState {
    Connecting,
    Connected(Instant),
    Disconnecting,
    Disconnected,
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
    configs: HashMap<String, (ConfigRecord, ConfigState)>, // indexed by configuration.profile.name.
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
                    configs: HashMap::new(),                    
                }),
            }),
        }
    }

    // If a configuration exists with the same path, we overrite the existing one but only if it is disconnected.
    pub fn add_configuration(&self, c: ConfigRecord) -> Result<(), std::io::Error> {
        let mut found = false;
        let mut found_name: String = String::new();
        let mut state = self.shared.state.lock().unwrap();            
        for (conf, state) in state.configs.values() {
            if conf.has_same_source_as(&c) {
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
            if found_name != c.get_name() {
                state.configs.remove(&found_name);
            }
        } else {
            // The new path is not present, but also we require a unique name.
            if state.configs.contains_key(c.get_name()) {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Configuration with name {} already exists", c.get_name()),
                ));
            }
        }

        state.configs.insert(c.get_name().to_string(), (c, ConfigState::Disconnected));
        Ok(())
    }

    // This returns a vector of (CONFIG_NAME/CN, ENDPOINT, STATUS)
    pub fn get_status(&self) -> Vec<(String, String, String)> {
        let mut status = Vec::new();
        let state = self.shared.state.lock().unwrap();
        for (cname, (conf, state)) in &state.configs {
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
            status.push((format!("{}/{}", cname.clone(), conf.get_cn()), String::from(conf.get_dock_host()), s));
        }
        status
    }


    pub fn get_configuration_state(&self, name: &str) -> Option<ConfigState> {
        let state = self.shared.state.lock().unwrap();
        let cfg = state.configs.get(name);
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
        let conf_state_tuple = state.configs.get_mut(name).ok_or_else(|| {
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
        state.configs.contains_key(name)
    }
}





#[cfg(test)]
mod test {
    use super::*;
    use std::env;    
    use std::time::{SystemTime, UNIX_EPOCH};
    use rand::Rng;
    use crate::cd::config::load_configuration;
    use std::fs;    


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
            let tstamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
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
            root_ca = "root-ca.pem"
            [dock]
            host_or_ip = "localhost"
            port = 2242
            [adapter]
            certificate = "a-cert.pem"            
            private_key = "a-key.pem"                        
            #blank
        "#;
        let tmpfile = TempTomlFile::new(toml_txt);
        let c = load_configuration(tmpfile.get_path());
        if let Err(e) = c {
            panic!("Error loading configuration: {}", e);
        }
        assert!(c.is_ok());
        let c = c.unwrap();
        assert_eq!(c.get_name(), "test");
        assert_eq!(c.get_name(), "test");
        assert_eq!(c.get_dock_host(), "localhost");
        assert_eq!(c.get_dock_port(), 2242);
    }

    #[test]
    fn test_add_configuration() {
        let toml_txt = r#"
            [profile]
            name = "test"
            root_ca = "root-ca.pem"
            [dock]
            host_or_ip = "localhost"
            port = 2242
            [adapter]
            certificate = "a-cert.pem"            
            private_key = "a-key.pem"                        
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
            root_ca = "root-ca.pem"
            [dock]
            host_or_ip = "localhost"
            port = 2242
            [adapter]
            certificate = "a-cert.pem"            
            private_key = "a-key.pem"                        
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
            root_ca = "root-ca.pem"
            [dock]
            host_or_ip = "another.localhost"
            port = 2243
            [adapter]
            certificate = "a-cert.pem"            
            private_key = "a-key.pem"                        
            #blank
        "#;
        let tmpfile2 = TempTomlFile::new(toml_txt);
        let c = load_configuration(tmpfile2.get_path());
        assert!(c.is_ok());
        let conf2 = c.unwrap();
        let r = zpr.add_configuration(conf2);
        assert!(r.is_err());
        let e = r.unwrap_err();
        assert!( e.to_string().contains("Configuration with name test already exists"));
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
        assert!( e.to_string().contains("Configuration with name foo not found"));
    }

    #[test]
    fn test_set_state() {
        let toml_txt = r#"
            [profile]
            name = "test"
            root_ca = "root-ca.pem"
            [dock]
            host_or_ip = "localhost"
            port = 2242
            [adapter]
            certificate = "a-cert.pem"            
            private_key = "a-key.pem"                        
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

