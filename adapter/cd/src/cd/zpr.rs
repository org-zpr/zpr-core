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

        state
            .configs
            .insert(c.get_name().to_string(), (c, ConfigState::Disconnected));
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
            status.push((
                format!("{}/{}", cname.clone(), conf.get_cn()),
                String::from(conf.get_dock_host()),
                s,
            ));
        }
        status
    }

    pub fn get_configuration_names(&self) -> Vec<String> {
        let state = self.shared.state.lock().unwrap();
        state.configs.keys().cloned().collect()
    }


    /// Returns "ADDR:PORT"
    pub fn get_connect_string(&self, name: &str) -> Option<String> {
        let state = self.shared.state.lock().unwrap();
        let cfg = state.configs.get(name);
        cfg?;
        let (conf, _) = cfg.unwrap();
        Some(format!("{}:{}", conf.get_dock_host(), conf.get_dock_port()))
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
    use crate::cd::config::load_configuration;
    use rand::Rng;
    use std::env;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    const CA_CERT_DATA: &str = r#"-----BEGIN CERTIFICATE-----
MIIDijCCAnICCQDvR2uxX2eKJTANBgkqhkiG9w0BAQsFADCBhjELMAkGA1UEBhMC
VVMxCzAJBgNVBAgMAktZMQ4wDAYDVQQHDAVWaWxsZTEQMA4GA1UECgwHc3VyZW5l
dDEWMBQGA1UECwwNYXV0aG9yaXphdGlvbjEXMBUGA1UEAwwOYXV0aDAuaW50ZXJu
YWwxFzAVBgkqhkiG9w0BCQEWCGF1dGhAZm9vMB4XDTIwMDIyODE5MjMyN1oXDTI1
MDIyNjE5MjMyN1owgYYxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJLWTEOMAwGA1UE
BwwFVmlsbGUxEDAOBgNVBAoMB3N1cmVuZXQxFjAUBgNVBAsMDWF1dGhvcml6YXRp
b24xFzAVBgNVBAMMDmF1dGgwLmludGVybmFsMRcwFQYJKoZIhvcNAQkBFghhdXRo
QGZvbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMCxt6RgI11Q3aZa
DTUp6Q+5uMB+fqhhuaPoeqEZYujgLbeJrldMQ2aIHlqntC1y4tPSCCYriVRS5j6V
cqgtu3saFsA/8MwAvaeY5LmD8wE7fl4b/MGst86FVyD3TLlTt5FDIkhJK+jpgKf1
4NjGDBYSiYVuZ54Kxg8HQXPGXx5txjTxmcBY44b5g5ARxOVu/u/ut0ZeS3z2Uf7K
q4cZ2/C+xxpYo+NMgg3sfuUDfMDAhLymfmWGa5SEj8XCUoYZv3bJLUDjMLtB06yo
alxQowZovSpUdJOjb0e+B8FvaziwRVohQ4Y1hEpx9X/idvwgHxzGzR9mSax+iz+p
OUbw3TMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAChfVONalJLlRCgbqC9gxjhYq
3fA3E4r9yVVlWQmkx8XTK4Z2NWqSdE5PmaYQdvdnzMAsxGHjxgaN/KH/wctEL+qK
2C7bnaevDBrHTtrVM6UUZfec5eerf7UA1MDKq0BqsaUamhzqxygh9Ei2mrG36+LK
my2Mk/tFcvSOS8tB8Q+gAGDKX/4DshR3aEkIDzqpdmwK8ffxD9sJp8HewjNtO3Pv
nsdyXmJ65z95DU5GIsshL7og94933hCN/b86R9Zq6/RAoAM/87TJFnxCywG39Zr5
GRAzgLWJLdkNEos8XB42MCS7tn/jefKDGquuI625jeARa2eCoJT9yk95pQbuAQ==
-----END CERTIFICATE-----
"#;

    const ADAPTER_CERT_DATA: &str = r#"-----BEGIN CERTIFICATE-----
MIIEWzCCA0OgAwIBAgIJAMSVUe6Pd/Z7MA0GCSqGSIb3DQEBBQUAMIGGMQswCQYD
VQQGEwJVUzELMAkGA1UECAwCS1kxDjAMBgNVBAcMBVZpbGxlMRAwDgYDVQQKDAdz
dXJlbmV0MRYwFAYDVQQLDA1hdXRob3JpemF0aW9uMRcwFQYDVQQDDA5hdXRoMC5p
bnRlcm5hbDEXMBUGCSqGSIb3DQEJARYIYXV0aEBmb28wHhcNMjQwNjE4MTQzMjI4
WhcNMjUwNjE4MTQzMjI4WjBLMQswCQYDVQQGEwJVUzELMAkGA1UECAwCS1kxCzAJ
BgNVBAoMAllZMQswCQYDVQQLDAJaWjEVMBMGA1UEAwwMdGVzdG5vZGUuenByMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAk0x4ui48znwmmnbeVrRMXeiz
DdR2EKbZwsoW/sfePCTa50UJHgA3vPPTGhJTTfjJrVyp2nazpaBuy66h85PQWS2x
FqstxHVTj0+CF4t+YKUyHFZiF2rLWQonO5R43v489NF9JHKH2SgxKMjTsPpJY8sd
yFgUTbiD6G8T/j/ZIojBIkQG2wWNpdjqUDnzeaU32MGHV8iigUrpc3xDqw+RWhKP
kPjoyInoA4tNNrfHrddu61w3FPx6KTN1L8UV9K+BlNW/s3buluYMSi2vW24fjdTn
F3ev2+w+QUcvWP94/pFRiLEDAO+LO3hxFC16qNU33LMvAo8BdJvPG3GbN2+fIwID
AQABo4IBBDCCAQAwgaUGA1UdIwSBnTCBmqGBjKSBiTCBhjELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAktZMQ4wDAYDVQQHDAVWaWxsZTEQMA4GA1UECgwHc3VyZW5ldDEW
MBQGA1UECwwNYXV0aG9yaXphdGlvbjEXMBUGA1UEAwwOYXV0aDAuaW50ZXJuYWwx
FzAVBgkqhkiG9w0BCQEWCGF1dGhAZm9vggkA70drsV9niiUwCQYDVR0TBAIwADAL
BgNVHQ8EBAMCBPAwHwYDVR0RBBgwFoIUYXV0aDAuc3BhY2VsYXNlci5uZXQwHQYD
VR0OBBYEFFdtDdU6IP12wNv4YUdyZejdx8EaMA0GCSqGSIb3DQEBBQUAA4IBAQBp
gM2xMYgo6ntaPTV7xhLmAbwlhoKBt3I+i6KQUU9Ec/3AEiiZsyQxcPHAtmeU4han
5JpOK3hUYVH/SaSj2BHqkXH0yfFyIkAf0V1UsfWwcD8OEZffb5yP02RzIWCqdBN7
pdx9gtGwy4l779FNvHGQ8AI4y+cpxwiXyBiXdB3Mv1wG5gUNe4pGk7JWA5lb9XQ9
sOwVMjkwcUsqGr489gqYRWl1mAMz1D2T+U91HavGybvUBlgb/3+dgjksa/ZWTUhD
2CRFn7sqmwcPHLoGV/+yCjjuheyx+z7LrPqyqPfWwrr68udK4Yqz8iiqwMC1b8m0
1Hm6nwN1sHYkYgYgk/Ey
-----END CERTIFICATE-----
"#;

    const ADAPTER_KEY_DATA: &str = r#"
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCTTHi6LjzOfCaa
dt5WtExd6LMN1HYQptnCyhb+x948JNrnRQkeADe889MaElNN+MmtXKnadrOloG7L
rqHzk9BZLbEWqy3EdVOPT4IXi35gpTIcVmIXastZCic7lHje/jz00X0kcofZKDEo
yNOw+kljyx3IWBRNuIPobxP+P9kiiMEiRAbbBY2l2OpQOfN5pTfYwYdXyKKBSulz
fEOrD5FaEo+Q+OjIiegDi002t8et127rXDcU/HopM3UvxRX0r4GU1b+zdu6W5gxK
La9bbh+N1OcXd6/b7D5BRy9Y/3j+kVGIsQMA74s7eHEULXqo1Tfcsy8CjwF0m88b
cZs3b58jAgMBAAECggEAQYQ8FqPGTBmQmhfRIUOkzAhazAX6VcHBDhERVVXVFW9X
JpLgUUXLhPH2rZwFDaNhIQkcS52MnljTrykHw+21OFVIdUrCWqXM+utkc9CJ77bK
qSwLCVtpAzuu46NQd+8hcctUHEgNAJwN8ZQSBJ/u0MJhhuEWdtNhaJsvi2Ee1WrN
ZvUkpn6SpCHVvEtZjJZL0elQrgk7EMzWSWz/1a8ORzbmBDw5X/0dV/VKCfx1kJ+w
9fmIhfGU3lFT8rOpqcx3MlB+PzRVV4P3hUBirovxBu2TEqp01hvPnb5m6ZGE0U/p
B4LBke3S23iSkYwPaHwcbLVLhF2pruYmXS1hvCZxEQKBgQC3gBWKZZeV8uT0vKN+
FScBk5WLYSq63dUSonszWr0AxN03WsoHjkr4AqB+wtMPI2L7Kpy8whwtTXehqNpT
W+Zz12eVQI2fuGTYZg7zjxN0+H2nRxTOWyVcpW4h1tavzzXAzTDo1jc8DYvMhgXp
IIOMYDbOCQPCnopdE0Xd2QF7NQKBgQDNftHfeNOINkt3RTTI5NY9pTibl/alzqJf
aW8BXEsnKM8BB6ux/sTNE4ejaK7a4xvKhgss+Z0FkM11Ycoa2D5/X9CyXT/cOmhF
E2vt6yyQUSscMQMAaUmma8Gvu5dDF3a7/5liphjafPyFRa275JIxdbDgaCvV62kH
EjPLMjOj9wKBgQCHhe9iwVlNA5EZN2DAM7sVLPybbe3zCPbexmWbLf683KhMw57G
Kc8wkDAcrqLWYVovCe+scOgChV4/ZMeqHQt8rq/vyTdPqQ3BzM5qD1ddYlDbBGJX
bXWQkRVfpJ32RmD6vhDLRbqRfaesK6ed38eIG18emAXQ7Opfh2ZoTGcNqQKBgDKN
/53lwMyi5t/506mUuqxByHJm6VQTSNkGPDvuc8K3hG2xcGkCz3HQWy81YscQ1lZ1
sawn4Jxs6k71dt4x0vZNIS+wRzSr3dkYlRXcJIOApIVz/VQNkwPxQJ42HVlxHVHU
6OxfBoBB/XHgGYS/D8RBOvmKRzaCir0lmj5kJFYzAoGBAKEEaHn0LvmDpHYSUOA4
FgJnFmtHTHcYFaFus/oqwEtylftAsM5h8o5ww2OCJDa2FSxzaayV1wpm2r1HwvDn
p/oYQcQrtBHsdvdZ/8IRR7/9HJNanbhTuKdkdmVjt4rPoUDc2zqzEZUEG33E2Glh
+VS382WYhn8T/WeSmWHmF69D
-----END PRIVATE KEY-----
"#;

    struct TempFile {
        path: String,
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    impl TempFile {
        fn new_toml(contents: &str) -> TempFile {
            let mut rng = rand::thread_rng();
            let tstamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let dir = env::temp_dir();
            let num: u32 = rng.gen();
            let path = dir.join(format!("org_zpr_cd_test_{}_{}.toml", num, tstamp));
            fs::write(&path, contents).expect("Unable to write file");
            TempFile {
                path: path.to_str().unwrap().to_string(),
            }
        }

        fn new_pem(contents: &str) -> TempFile {
            let mut rng = rand::thread_rng();
            let tstamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let dir = env::temp_dir();
            let num: u32 = rng.gen();
            let path = dir.join(format!("org_zpr_cd_test_{}_{}.pem", num, tstamp));
            fs::write(&path, contents).expect("Unable to write file");
            TempFile {
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
            root_ca = "@ROOT_CA"
            [dock]
            host_or_ip = "localhost"
            port = 2242
            [adapter]
            certificate = "@CERT"
            private_key = "@KEY"
            #blank
        "#;

        let ca_certf = TempFile::new_pem(CA_CERT_DATA);
        let adapter_certf = TempFile::new_pem(ADAPTER_CERT_DATA);
        let adapter_keyf = TempFile::new_pem(ADAPTER_KEY_DATA);

        let toml_txt = toml_txt.replace("@ROOT_CA", ca_certf.get_path());
        let toml_txt = toml_txt.replace("@CERT", adapter_certf.get_path());
        let toml_txt = toml_txt.replace("@KEY", adapter_keyf.get_path());

        let tmpfile = TempFile::new_toml(&toml_txt);
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
        assert_eq!(c.get_cn(), "testnode.zpr");
    }

    #[test]
    fn test_add_configuration() {
        let toml_txt = r#"
            [profile]
            name = "test"
            root_ca = "@ROOT_CA"
            [dock]
            host_or_ip = "localhost"
            port = 2242
            [adapter]
            certificate = "@CERT"
            private_key = "@KEY"
            #blank
        "#;

        let ca_certf = TempFile::new_pem(CA_CERT_DATA);
        let adapter_certf = TempFile::new_pem(ADAPTER_CERT_DATA);
        let adapter_keyf = TempFile::new_pem(ADAPTER_KEY_DATA);

        let toml_txt = toml_txt.replace("@ROOT_CA", ca_certf.get_path());
        let toml_txt = toml_txt.replace("@CERT", adapter_certf.get_path());
        let toml_txt = toml_txt.replace("@KEY", adapter_keyf.get_path());

        let tmpfile = TempFile::new_toml(&toml_txt);
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
        assert_eq!(stats[0].0, "test/testnode.zpr");
        assert_eq!(stats[0].1, "localhost");
        assert_eq!(stats[0].2, "disconnected");
    }

    #[test]
    fn test_cannot_have_duplicate_name() {
        let toml_txt = r#"
            [profile]
            name = "test"
            root_ca = "@ROOT_CA"
            [dock]
            host_or_ip = "localhost"
            port = 2242
            [adapter]
            certificate = "@CERT"
            private_key = "@KEY"
            #blank
        "#;

        let ca_certf = TempFile::new_pem(CA_CERT_DATA);
        let adapter_certf = TempFile::new_pem(ADAPTER_CERT_DATA);
        let adapter_keyf = TempFile::new_pem(ADAPTER_KEY_DATA);

        let toml_txt = toml_txt.replace("@ROOT_CA", ca_certf.get_path());
        let toml_txt = toml_txt.replace("@CERT", adapter_certf.get_path());
        let toml_txt = toml_txt.replace("@KEY", adapter_keyf.get_path());

        let tmpfile1 = TempFile::new_toml(&toml_txt);
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
            root_ca = "@ROOT_CA"
            [dock]
            host_or_ip = "another.localhost"
            port = 2243
            [adapter]
            certificate = "@CERT"
            private_key = "@KEY"
            #blank
        "#;
        let toml_txt = toml_txt.replace("@ROOT_CA", ca_certf.get_path());
        let toml_txt = toml_txt.replace("@CERT", adapter_certf.get_path());
        let toml_txt = toml_txt.replace("@KEY", adapter_keyf.get_path());

        let tmpfile2 = TempFile::new_toml(&toml_txt);
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
            root_ca = "@ROOT_CA"
            [dock]
            host_or_ip = "localhost"
            port = 2242
            [adapter]
            certificate = "@CERT"
            private_key = "@KEY"
            #blank
        "#;

        let ca_certf = TempFile::new_pem(CA_CERT_DATA);
        let adapter_certf = TempFile::new_pem(ADAPTER_CERT_DATA);
        let adapter_keyf = TempFile::new_pem(ADAPTER_KEY_DATA);

        let toml_txt = toml_txt.replace("@ROOT_CA", ca_certf.get_path());
        let toml_txt = toml_txt.replace("@CERT", adapter_certf.get_path());
        let toml_txt = toml_txt.replace("@KEY", adapter_keyf.get_path());

        let tmpfile = TempFile::new_toml(&toml_txt);
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
