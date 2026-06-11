//! ZPR Packet Handler command line arg processing.
//!
//! The main entry point is [argparse] which will parse the command line arguments
//! and any config file, returning a PH configuration. See [crate::config::Config] for
//! more details on the configuration.

use clap::Parser;
use std::fs;
use std::io::Read;
use std::path::Path;

use crate::assembly::PhMode;
use crate::main_args::{ArgsError, Command, Control};

use crate::config::{AdapterConfig, Config, NodeConfig};

/// Parse the program arguments, may also parse a configuration file if that has been
/// specified in the arguments.  If all goes well this returns a valid configuration
/// and "mode" for the program.
///
/// The configuration returned will have the correct contents for the [PhMode], but
/// additional checking is still necessary.  For example, file paths specified
/// may not actually exist.
///
/// # Arguments
///
/// `args` - Optional vector of strings representing the command line arguments.
/// If None we parse from `std::env::args_os()`.
pub fn argparse(args: Option<Vec<&str>>) -> std::result::Result<(PhMode, Config), ArgsError> {
    let mut config: Config;
    let ph_mode: PhMode;
    let control = match args {
        Some(args) => Control::parse_from(args),
        None => Control::parse(),
    };

    match control.command {
        Command::Adapter {
            name,
            config_file,
            common,
            node_addr,
            node_public_key_file,
            bootstrap_key,
        } => {
            ph_mode = PhMode::Adapter;
            let config_file: Option<AdapterConfig> = match config_file {
                Some(p) => match load_config::<AdapterConfig>(&p) {
                    Ok(mut ac) => {
                        ac.config_path = fs::canonicalize(p).unwrap();
                        Some(ac)
                    }
                    Err(e) => {
                        return Err(e);
                    }
                },
                None => None,
            };

            config = Config::new_for_adapter(config_file, &common)?;

            // fold in the optional, adapter specific command line args:
            if let Some(cn) = name {
                config.name = cn;
            }
            if let Some(node_addr) = node_addr {
                config.node_addr = Some(node_addr);
            }
            if let Some(npkf) = node_public_key_file {
                if npkf.is_relative() {
                    let npkf = fs::canonicalize(npkf).or_else(|e| {
                        Err(ArgsError::PathError(format!(
                            "path error for node_public_key_file: {:?}",
                            e
                        )))
                    })?;
                    config.node_public_key_file = Some(npkf);
                } else {
                    config.node_public_key_file = Some(npkf);
                }
            }
            if let Some(mut bootstrap_key) = bootstrap_key {
                if bootstrap_key.is_relative() {
                    bootstrap_key = fs::canonicalize(bootstrap_key).or_else(|e| {
                        Err(ArgsError::PathError(format!(
                            "path error for bootstrap key: {:?}",
                            e
                        )))
                    })?;
                }
                config.bootstrap_key_path = Some(bootstrap_key);
            }
        }

        Command::Node {
            config_file,
            auth_private_key,
            common,
        } => {
            ph_mode = PhMode::Node;
            let config_file: Option<NodeConfig> = match config_file {
                Some(p) => match load_config::<NodeConfig>(&p) {
                    Ok(mut ac) => {
                        ac.config_path = fs::canonicalize(p).unwrap();
                        Some(ac)
                    }
                    Err(e) => {
                        return Err(e);
                    }
                },
                None => None,
            };
            config = Config::new_for_node(config_file, auth_private_key, &common)?;
        }
    }
    config.finalize()?;
    if let Err(e) = config.check_valid(ph_mode) {
        return Err(e);
    }
    Ok((ph_mode, config))
}

// Load a config, either adapter or node, from a TOML file.
fn load_config<T>(path: &Path) -> Result<T, ArgsError>
where
    T: serde::de::DeserializeOwned,
{
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut toml_text = String::new();
    let len = reader.read_to_string(&mut toml_text)?;
    if len == 0 {
        return Err(ArgsError::ParseError(format!(
            "Empty configuration file {:?}",
            path
        )));
    }
    let ac: T = match toml::from_str(&toml_text) {
        Ok(ac) => ac,
        Err(e) => {
            return Err(ArgsError::ParseError(format!(
                "Error parsing configuration file {:?}: {}",
                path, e
            )));
        }
    };
    Ok(ac)
}

#[cfg(test)]
mod test {

    use super::*;
    use rand::Rng;
    use serial_test::{parallel, serial};
    use std::env;
    use std::fs;
    use std::net::{IpAddr, SocketAddr};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

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
            let mut rng = rand::rng();
            let tstamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let dir = env::temp_dir();
            let num: u32 = rng.random();
            let path = dir.join(format!("org_zpr_ph_test_main_{}_{}.toml", num, tstamp));
            fs::write(&path, contents).expect("Unable to write file");
            TempFile {
                path: path.to_str().unwrap().to_string(),
            }
        }

        fn touch() -> TempFile {
            Self::new_toml("")
        }

        fn get_path(&self) -> &Path {
            return Path::new(&self.path);
        }

        #[allow(dead_code)]
        fn get_dir(&self) -> &Path {
            return Path::new(&self.path).parent().unwrap();
        }
    }

    #[test]
    fn test_main_args_load_config_adapter() {
        let tomltxt = r#"
        [global]
        control_path = "/var/run/zpr/control.sock"
        self_addr = "192.168.0.1:12345"
        ca_file = "tests/ca.pem"
        certificate_file = "tests/certificate.pem"
        private_key_file = "tests/private_key.pem"
        tun_if = "tun23"
        zpr_addr = [ "10.0.0.1" ]
        logging = [ ["zdp", "INFO"] ]


        [adapter]
        node_addr = "192.168.0.2:5000"
        node_public_key_file = "tests/node_public_key.pem"
        "#;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let config: AdapterConfig = load_config(tmpfile.get_path()).unwrap();

        assert_eq!(
            config.global.control_path,
            Some(PathBuf::from("/var/run/zpr/control.sock"))
        );
        assert_eq!(
            config.global.self_addr,
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 1)),
                12345
            ))
        );
        assert_eq!(config.global.ca_file, Some(PathBuf::from("tests/ca.pem")));
        assert_eq!(
            config.global.certificate_file,
            Some(PathBuf::from("tests/certificate.pem"))
        );
        assert_eq!(
            config.global.private_key_file,
            Some(PathBuf::from("tests/private_key.pem"))
        );
        assert_eq!(config.global.tun_if, Some("tun23".to_string()));
        assert_eq!(
            config.global.logging,
            Some(Vec::from([("zdp".to_string(), "INFO".to_string())]))
        );
        assert_eq!(
            config.adapter.node_addr,
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 2)),
                5000
            ))
        );
        assert_eq!(
            config.global.zpr_addr,
            Some(Vec::from([IpAddr::V4(std::net::Ipv4Addr::new(
                10, 0, 0, 1
            ))]))
        );
        assert_eq!(
            config.adapter.node_public_key_file,
            Some(PathBuf::from("tests/node_public_key.pem"))
        );
    }

    #[test]
    fn test_main_args_load_config_node() {
        let tomltxt = r#"
        [global]
        control_path = "/var/run/zpr/control.sock"
        self_addr = "192.168.0.1:12345"
        ca_file = "tests/ca.pem"
        certificate_file = "tests/certificate.pem"
        private_key_file = "tests/private_key.pem"
        tun_if = "tun23"
        logging = [ ["all", "TRACE"] ]

        "#;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let config: NodeConfig = load_config(tmpfile.get_path()).unwrap();

        assert_eq!(
            config.global.control_path,
            Some(PathBuf::from("/var/run/zpr/control.sock"))
        );
        assert_eq!(
            config.global.self_addr,
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 1)),
                12345
            ))
        );
        assert_eq!(config.global.ca_file, Some(PathBuf::from("tests/ca.pem")));
        assert_eq!(
            config.global.certificate_file,
            Some(PathBuf::from("tests/certificate.pem"))
        );
        assert_eq!(
            config.global.private_key_file,
            Some(PathBuf::from("tests/private_key.pem"))
        );
        assert_eq!(config.global.tun_if, Some("tun23".to_string()));
        assert_eq!(
            config.global.logging,
            Some(Vec::from([("all".to_string(), "TRACE".to_string())]))
        );
    }

    #[test]
    #[parallel(env)]
    fn test_main_args_argparse_adapter_config() {
        let mut tomltxt = r#"
        [global]
        control_path = "$CONTROLFILE"
        capture_path = "$CAPTUREFILE"
        self_addr = "192.168.0.1:12345"
        ca_file = "$CAFILE"
        certificate_file = "$CERTFILE"
        private_key_file = "$PKFILE"
        tun_if = "tun23"
        zpr_addr = [ "10.0.0.1" ]
        logging = [ ["link_state", "DEBUG"] ]


        [adapter]
        node_addr = "192.168.0.2:5000"
        node_public_key_file = "$NPKFILE"
        "#;

        let ca_file = TempFile::touch();
        let control_file = TempFile::touch();
        let capture_file = TempFile::touch();
        let cert_file = TempFile::touch();
        let pk_file = TempFile::touch();
        let npk_file = TempFile::touch();

        let tmp = tomltxt
            .replace("$CERTFILE", cert_file.get_path().to_str().unwrap())
            .replace("$CONTROLFILE", control_file.get_path().to_str().unwrap())
            .replace("$CAPTUREFILE", capture_file.get_path().to_str().unwrap())
            .replace("$PKFILE", pk_file.get_path().to_str().unwrap())
            .replace("$NPKFILE", npk_file.get_path().to_str().unwrap())
            .replace("$CAFILE", ca_file.get_path().to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let args = vec!["ph", "adapter", "-c", tmpfile.get_path().to_str().unwrap()];

        let (pmode, config) = argparse(Some(args)).unwrap();

        assert_eq!(pmode, PhMode::Adapter);

        assert_eq!(config.control_path, control_file.get_path());
        assert_eq!(
            config.self_addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 1)), 12345)
        );
        assert_eq!(config.ca_file, Some(ca_file.get_path().into()));
        assert_eq!(config.certificate_file, Some(cert_file.get_path().into()));
        assert_eq!(
            config.noise_private_key_source(),
            format!("file://{}", pk_file.get_path().display())
        );
        assert_eq!(config.tun_if, Some("tun23".to_string()));
        assert_eq!(
            config.logging,
            Vec::from([("link_state".to_string(), "DEBUG".to_string())])
        );

        assert_eq!(
            config.node_addr,
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 2)),
                5000
            ))
        );
        assert_eq!(
            config.zpr_addr,
            Vec::from([IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))])
        );
        assert_eq!(
            config.node_public_key_file,
            Some(npk_file.get_path().into())
        );
    }

    #[test]
    #[parallel(env)]
    fn test_main_args_adapter_config_requires_adapter_section() {
        let tomltxt = r#"
        [global]
        control_path = "/var/run/zpr/control.sock"
        self_addr = "192.168.0.1:12345"
        ca_file = "tests/ca.pem"
        certificate_file = "tests/certificate.pem"
        private_key_file = "tests/private_key.pem"
        tun_if = "tun23"
        "#;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let args = vec!["ph", "adapter", "-c", tmpfile.get_path().to_str().unwrap()];
        match argparse(Some(args)) {
            Err(ArgsError::ParseError(_)) => {}
            _ => panic!("Expected ParseError"),
        }
    }

    // You can leave the adapter section blank and provide the details on
    // the command line.
    #[test]
    #[parallel(env)]
    fn test_main_args_adapter_config_blank_adapter() {
        let mut tomltxt = r#"
        [global]
        control_path = "/tmp/control.sock"
        capture_path = "/tmp/capture.sock"
        self_addr = "192.168.0.1:12345"
        ca_file = "$CAFILE"
        certificate_file = "$CERTFILE"
        private_key_file = "$PKFILE"
        tun_if = "tun23"

        [adapter]
        "#;

        let cert_file = TempFile::touch();
        let pk_file = TempFile::touch();
        let ca_file = TempFile::touch();

        let tmp = tomltxt
            .replace("$CERTFILE", cert_file.get_path().to_str().unwrap())
            .replace("$PKFILE", pk_file.get_path().to_str().unwrap())
            .replace("$CAFILE", ca_file.get_path().to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let node_pk_file = TempFile::touch();
        let node_pk_fname = String::from(node_pk_file.get_path().to_str().unwrap());

        let args = vec![
            "ph",
            "adapter",
            "-c",
            tmpfile.get_path().to_str().unwrap(),
            "--node-addr",
            "192.168.0.2:5000",
            "--zpr-addr",
            "10.0.0.1",
            "--node-public-key-file",
            &node_pk_fname,
        ];

        let (pmode, config) = argparse(Some(args)).unwrap();

        assert_eq!(pmode, PhMode::Adapter);

        assert_eq!(
            config.node_addr,
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 2)),
                5000
            ))
        );
        assert_eq!(
            config.zpr_addr,
            Vec::from([IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))])
        );
        assert_eq!(
            config.node_public_key_file,
            Some(PathBuf::from(&node_pk_fname))
        );
    }

    // Leave out some stuff in the config file, but specify on command line.
    #[test]
    #[parallel(env)]
    fn test_main_args_argparse_adapter_config_override_globs() {
        let mut tomltxt = r#"
        [global]
        control_path = "$CONTROLFILE"
        capture_path = "$CAPTUREFILE"
        ca_file = "$CAFILE"
        certificate_file = "$CERTFILE"
        private_key_file = "$PKFILE"
        zpr_addr = [ "10.0.0.1" ]

        [adapter]
        node_addr = "192.168.0.2:5000"
        node_public_key_file = "$NPKFILE"
        "#;

        let ca_file = TempFile::touch();
        let cert_file = TempFile::touch();
        let control_file = TempFile::touch();
        let capture_file = TempFile::touch();
        let pk_file = TempFile::touch();
        let npk_file = TempFile::touch();

        let tmp = tomltxt
            .replace("$CERTFILE", cert_file.get_path().to_str().unwrap())
            .replace("$CONTROLFILE", control_file.get_path().to_str().unwrap())
            .replace("$CAPTUREFILE", capture_file.get_path().to_str().unwrap())
            .replace("$PKFILE", pk_file.get_path().to_str().unwrap())
            .replace("$NPKFILE", npk_file.get_path().to_str().unwrap())
            .replace("$CAFILE", ca_file.get_path().to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let args = vec![
            "ph",
            "adapter",
            "-c",
            tmpfile.get_path().to_str().unwrap(),
            "--self-addr",
            "192.168.0.1:12345",
            "--tun-if",
            "tun23",
            "-l",
            "peer_mgmt=DEBUG zdp=TRACE",
        ];

        let (pmode, config) = argparse(Some(args)).unwrap();

        assert_eq!(pmode, PhMode::Adapter);

        assert_eq!(config.control_path, control_file.get_path());
        assert_eq!(
            config.self_addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 1)), 12345)
        );
        assert_eq!(config.ca_file, Some(ca_file.get_path().into()));
        assert_eq!(config.certificate_file, Some(cert_file.get_path().into()));
        assert_eq!(
            config.noise_private_key_source(),
            format!("file://{}", pk_file.get_path().display())
        );
        assert_eq!(config.tun_if, Some("tun23".to_string()));
        assert_eq!(
            config.logging,
            Vec::from([
                ("peer_mgmt".to_string(), "DEBUG".to_string()),
                ("zdp".to_string(), "TRACE".to_string())
            ])
        );

        assert_eq!(
            config.node_addr,
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 2)),
                5000
            ))
        );
        assert_eq!(
            config.zpr_addr,
            Vec::from([IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))])
        );
        assert_eq!(
            config.node_public_key_file,
            Some(npk_file.get_path().into())
        );
    }

    #[test]
    #[parallel(env)]
    fn test_main_args_argparse_adapter_config_minimal() {
        // Not quite minimal since we need to set control path to make CI happy.
        let mut tomltxt = r#"
        [global]
        ca_file = "$CAFILE"
        certificate_file = "$CERTFILE"
        private_key_file = "$PKFILE"
        control_path = "/tmp/control.sock"
        capture_path = "/tmp/capture.sock"
        zpr_addr = [ "10.0.0.1" ]

        [adapter]
        node_addr = "192.168.0.2:5000"
        node_public_key_file = "$NPKFILE"
        "#;

        let ca_file = TempFile::touch();
        let cert_file = TempFile::touch();
        let pk_file = TempFile::touch();
        let npk_file = TempFile::touch();

        let tmp = tomltxt
            .replace("$CERTFILE", cert_file.get_path().to_str().unwrap())
            .replace("$PKFILE", pk_file.get_path().to_str().unwrap())
            .replace("$NPKFILE", npk_file.get_path().to_str().unwrap())
            .replace("$CAFILE", ca_file.get_path().to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let args = vec!["ph", "adapter", "-c", tmpfile.get_path().to_str().unwrap()];

        let (pmode, config) = argparse(Some(args)).unwrap();

        assert_eq!(pmode, PhMode::Adapter);

        assert!(!config.control_path.to_string_lossy().is_empty());
        assert_eq!(
            config.self_addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0)
        );
        assert_eq!(config.ca_file, Some(ca_file.get_path().into()));
        assert_eq!(config.certificate_file, Some(cert_file.get_path().into()));
        assert_eq!(
            config.noise_private_key_source(),
            format!("file://{}", pk_file.get_path().display())
        );
        assert!(config.tun_if.is_none());
        assert!(config.logging.is_empty());

        assert_eq!(
            config.node_addr,
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 2)),
                5000
            ))
        );
        assert_eq!(
            config.zpr_addr,
            Vec::from([IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))])
        );
        assert_eq!(
            config.node_public_key_file,
            Some(npk_file.get_path().into())
        );
    }

    #[test]
    #[parallel(env)]
    fn test_main_args_argparse_node_config_minimal() {
        // Not quite minimal since we need to set control path to make CI happy.
        let mut tomltxt = r#"
        [global]
        ca_file = "$CAFILE"
        certificate_file = "$CERTFILE"
        private_key_file = "$PKFILE"
        control_path = "/tmp/control.sock"
        capture_path = "/tmp/capture.sock"
        zpr_addr = [ "10.0.0.1" ]
        "#;

        let ca_file = TempFile::touch();
        let cert_file = TempFile::touch();
        let pk_file = TempFile::touch();

        let tmp = tomltxt
            .replace("$CERTFILE", cert_file.get_path().to_str().unwrap())
            .replace("$PKFILE", pk_file.get_path().to_str().unwrap())
            .replace("$CAFILE", ca_file.get_path().to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let args = vec!["ph", "node", "-c", tmpfile.get_path().to_str().unwrap()];

        let (pmode, config) = argparse(Some(args)).unwrap();

        assert_eq!(pmode, PhMode::Node);

        assert!(!config.control_path.to_string_lossy().is_empty());
        assert_eq!(
            config.self_addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0)
        );
        assert_eq!(config.ca_file, Some(ca_file.get_path().into()));
        assert_eq!(config.certificate_file, Some(cert_file.get_path().into()));
        assert_eq!(
            config.noise_private_key_source(),
            format!("file://{}", pk_file.get_path().display())
        );
        assert!(config.tun_if.is_none());
        assert!(config.logging.is_empty());
    }

    #[test]
    #[parallel(env)]
    fn test_main_args_argparse_node_config_no_toml() {
        // The files references on command line need to exist
        let ca_file = TempFile::touch();
        let ca_file_fname = String::from(ca_file.get_path().to_str().unwrap());
        let cert_file = TempFile::touch();
        let cert_file_fname = String::from(cert_file.get_path().to_str().unwrap());
        let pk_file = TempFile::touch();
        let pk_file_fname = String::from(pk_file.get_path().to_str().unwrap());

        let args = vec![
            "ph",
            "node",
            "--ca-file",
            &ca_file_fname,
            "--certificate-file",
            &cert_file_fname,
            "--private-key-file",
            &pk_file_fname,
            "--control-path",
            "/tmp/control.sock",
            "--capture-path",
            "/tmp/capture.sock",
            "--zpr-addr",
            "10.0.0.1",
        ];

        let (pmode, config) = argparse(Some(args)).unwrap();

        assert_eq!(pmode, PhMode::Node);

        assert!(!config.control_path.to_string_lossy().is_empty());
        assert_eq!(
            config.self_addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0)
        );
        assert_eq!(config.ca_file, Some(PathBuf::from(&ca_file_fname)));
        assert_eq!(
            config.certificate_file,
            Some(PathBuf::from(&cert_file_fname))
        );
        assert_eq!(
            config.noise_private_key_source(),
            format!("file://{}", pk_file_fname)
        );
        assert!(config.tun_if.is_none());
        assert!(config.logging.is_empty());
    }

    #[test]
    #[serial(env)] // serialize with other tests because we modify process environment
    fn test_main_args_argparse_adapter_key_in_env() {
        let mut tomltxt = r#"
        [global]
        ca_file = "$CAFILE"
        certificate_file = "$CERTFILE"
        control_path = "/tmp/control.sock"
        capture_path = "/tmp/capture.sock"
        zpr_addr = [ "10.0.0.1" ]

        [adapter]
        node_addr = "192.168.0.2:5000"
        node_public_key_file = "$NPKFILE"
        "#;

        let ca_file = TempFile::touch();
        let cert_file = TempFile::touch();
        let npk_file = TempFile::touch();

        let tmp = tomltxt
            .replace("$CERTFILE", cert_file.get_path().to_str().unwrap())
            .replace("$NPKFILE", npk_file.get_path().to_str().unwrap())
            .replace("$CAFILE", ca_file.get_path().to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let args = vec!["ph", "adapter", "-c", tmpfile.get_path().to_str().unwrap()];

        let noise_key = "GExPGh5RE/nKo8WoN8EqknDDNIEjWBL6PZm08Uhvn0w=";
        unsafe {
            // SAFETY: this test is executed serially
            env::set_var("NOISE_PRIVATE_KEY", noise_key);
        }
        let presult = argparse(Some(args));
        unsafe {
            // SAFETY: this test is executed serially
            env::remove_var("NOISE_PRIVATE_KEY");
        }

        let (pmode, config) = presult.unwrap();
        assert_eq!(pmode, PhMode::Adapter);
        assert_eq!(
            config.noise_private_key_source(),
            format!("key://{}", noise_key)
        )
    }

    // Adapter without ca_file passes config validation.
    #[test]
    #[parallel(env)]
    fn test_adapter_no_ca_file_passes_validation() {
        let mut tomltxt = r#"
        [global]
        certificate_file = "$CERTFILE"
        private_key_file = "$PKFILE"
        control_path = "/tmp/control.sock"
        capture_path = "/tmp/capture.sock"

        [adapter]
        node_addr = "192.168.0.2:5000"
        node_public_key_file = "$NPKFILE"
        "#;

        let cert_file = TempFile::touch();
        let pk_file = TempFile::touch();
        let npk_file = TempFile::touch();

        let tmp = tomltxt
            .replace("$CERTFILE", cert_file.get_path().to_str().unwrap())
            .replace("$PKFILE", pk_file.get_path().to_str().unwrap())
            .replace("$NPKFILE", npk_file.get_path().to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);
        let args = vec!["ph", "adapter", "-c", tmpfile.get_path().to_str().unwrap()];

        let (pmode, config) = argparse(Some(args)).unwrap();
        assert_eq!(pmode, PhMode::Adapter);
        assert!(config.ca_file.is_none());
    }

    // Adapter without certificate_file but with name passes config validation.
    #[test]
    #[parallel(env)]
    fn test_adapter_no_cert_with_name_passes_validation() {
        let mut tomltxt = r#"
        [global]
        private_key_file = "$PKFILE"
        control_path = "/tmp/control.sock"
        capture_path = "/tmp/capture.sock"

        [adapter]
        name = "my-adapter"
        node_addr = "192.168.0.2:5000"
        node_public_key_file = "$NPKFILE"
        "#;

        let pk_file = TempFile::touch();
        let npk_file = TempFile::touch();

        let tmp = tomltxt
            .replace("$PKFILE", pk_file.get_path().to_str().unwrap())
            .replace("$NPKFILE", npk_file.get_path().to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);
        let args = vec!["ph", "adapter", "-c", tmpfile.get_path().to_str().unwrap()];

        let (pmode, config) = argparse(Some(args)).unwrap();
        assert_eq!(pmode, PhMode::Adapter);
        assert!(config.certificate_file.is_none());
        assert_eq!(config.name, "my-adapter");
    }

    // Adapter without certificate_file and without name fails config validation, even with private key.
    #[test]
    #[parallel(env)]
    fn test_adapter_no_cert_no_name_fails_validation() {
        let mut tomltxt = r#"
        [global]
        private_key_file = "$PKFILE"
        control_path = "/tmp/control.sock"
        capture_path = "/tmp/capture.sock"

        [adapter]
        node_addr = "192.168.0.2:5000"
        node_public_key_file = "$NPKFILE"
        "#;

        let pk_file = TempFile::touch();
        let npk_file = TempFile::touch();

        let tmp = tomltxt
            .replace("$PKFILE", pk_file.get_path().to_str().unwrap())
            .replace("$NPKFILE", npk_file.get_path().to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);
        let args = vec!["ph", "adapter", "-c", tmpfile.get_path().to_str().unwrap()];

        match argparse(Some(args)) {
            Err(ArgsError::Missing(msg)) => {
                assert!(msg.contains("name"), "expected 'name' in error, got: {msg}");
            }
            other => panic!("expected Missing error, got: {:?}", other),
        }
    }

    // CLI --name overrides config [adapter].name.
    #[test]
    #[parallel(env)]
    fn test_adapter_cli_name_overrides_config_name() {
        let mut tomltxt = r#"
        [global]
        private_key_file = "$PKFILE"
        control_path = "/tmp/control.sock"
        capture_path = "/tmp/capture.sock"

        [adapter]
        name = "config-name"
        node_addr = "192.168.0.2:5000"
        node_public_key_file = "$NPKFILE"
        "#;

        let pk_file = TempFile::touch();
        let npk_file = TempFile::touch();

        let tmp = tomltxt
            .replace("$PKFILE", pk_file.get_path().to_str().unwrap())
            .replace("$NPKFILE", npk_file.get_path().to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);
        let args = vec![
            "ph",
            "adapter",
            "-c",
            tmpfile.get_path().to_str().unwrap(),
            "--name",
            "cli-name",
        ];

        let (_, config) = argparse(Some(args)).unwrap();
        assert_eq!(config.name, "cli-name");
    }

    // CLI --name with config-file bootstrap_key and no certificate_file: bootstrap CN equals CLI name.
    #[test]
    #[parallel(env)]
    fn test_adapter_cli_name_bootstrap_cn_ordering() {
        let bootstrap_key_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/rsa-key.pem");

        let mut tomltxt = r#"
        [global]
        private_key_file = "$PKFILE"
        control_path = "/tmp/control.sock"
        capture_path = "/tmp/capture.sock"

        [adapter]
        node_addr = "192.168.0.2:5000"
        node_public_key_file = "$NPKFILE"
        bootstrap_key = "$BSKEY"
        "#;

        let pk_file = TempFile::touch();
        let npk_file = TempFile::touch();

        let tmp = tomltxt
            .replace("$PKFILE", pk_file.get_path().to_str().unwrap())
            .replace("$NPKFILE", npk_file.get_path().to_str().unwrap())
            .replace("$BSKEY", bootstrap_key_path.to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);
        let args = vec![
            "ph",
            "adapter",
            "-c",
            tmpfile.get_path().to_str().unwrap(),
            "--name",
            "cli-adapter-name",
        ];

        let (_, config) = argparse(Some(args)).unwrap();
        assert_eq!(config.name, "cli-adapter-name");
        let bootstrap = config.bootstrap.as_ref().expect("bootstrap should be set");
        assert_eq!(bootstrap.cn(), "cli-adapter-name");
    }
}
