use std::path::{Path, PathBuf};
use std::time::Duration;

use openssl::pkey::Private;
use openssl::rsa::Rsa;
use prost::Message;

use crate::config_api::ConfigApi;
use crate::context::CompilationCtx;
use crate::crypto::{sha256_of_file, sign_pkcs1v15_sha256};
use crate::errors::CompilationError;
use crate::lex::tokenize;
use crate::parser::parse;
use crate::policybuilder::PolicyBuilder;
use crate::polio;
use crate::weaver::weave;

/// Updeate this if we change the container format. This is checked by visa service during deserialization.
pub const CONTAINER_VERSION: u32 = 1121;

/// Create one of these with the [CompilationBuilder].
pub struct Compilation {
    pub verbose: bool,
    werror: bool,
    pub source_zpl: PathBuf,
    pub source_config: PathBuf,
    pub output_file: PathBuf,
    pub parse_only: bool,
    private_key: Option<Rsa<Private>>,
}

impl Compilation {
    /// Returns a new [CompilationBuilder] using the passed ZPL source file and
    /// reasonable defaults.
    pub fn builder(source: PathBuf) -> CompilationBuilder {
        CompilationBuilder::new(source)
    }

    /// Create a policy from the ZPL source and configuration.
    pub fn compile(&self) -> Result<(), CompilationError> {
        let cctx = CompilationCtx::new(self.verbose, self.werror);
        if self.verbose {
            println!(
                "compiling {:?} with config {:?}",
                self.source_zpl, self.source_config
            );
        }
        let cfg = ConfigApi::new_from_toml_file(&self.source_config, &cctx).map_err(|e| {
            CompilationError::ConfigError(format!(
                "failed to load configuration from {:?}: {}",
                self.source_config, e
            ))
        })?;

        let tz = tokenize(&self.source_zpl, &cctx)?;
        if self.verbose {
            println!("parsed {} tokens:", tz.tokens.len());
            for t in &tz.tokens {
                println!("   {:?}", t);
            }
            println!();
        }

        let pr = parse(tz.tokens, &cctx)?;
        let mut policy = pr.policy;
        let policy_digest = sha256_of_file(&self.source_zpl)?;
        policy.digest = Some(policy_digest);

        let fabric = weave(&self, &cfg, &policy, &cctx)?;
        if self.verbose {
            println!();
            println!("fabric production:\n{}", fabric);
        }

        cctx.info("parse successful");
        if self.parse_only {
            return Ok(());
        }

        let mut builder = PolicyBuilder::new(self.verbose);
        builder.with_max_visa_lifetime(Duration::from_secs(60 * 60 * 12)); // 12 hours (TODO: Should come from config)

        builder.with_fabric(&fabric, &cctx)?;

        let pol = builder.build()?;
        cctx.info("build successful");

        let pcontainer = self.contain_policy(&pol, &cctx)?;
        self.write_container(&pcontainer, &self.output_file, &cctx)?;
        Ok(())
    }

    /// Write the policy container to the output file, serializing with protocol buffers.
    fn write_container(
        &self,
        container: &polio::PolicyContainer,
        file: &Path,
        ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        let mut buf = Vec::new();
        buf.reserve(container.encoded_len());
        container.encode(&mut buf).map_err(|e| {
            CompilationError::EncodingError(format!("failed to encode policy container: {}", e))
        })?;
        std::fs::write(file, &buf).map_err(|e| {
            CompilationError::FileError(format!(
                "failed to write policy container to {:?}: {}",
                file, e
            ))
        })?;
        ctx.info(&format!("wrote {}", &file.display()));
        Ok(())
    }

    /// Create the container struct and optionally sign the policy with the private key.
    fn contain_policy(
        &self,
        pol: &polio::Policy,
        ctx: &CompilationCtx,
    ) -> Result<polio::PolicyContainer, CompilationError> {
        let mut buf = Vec::new();
        buf.reserve(pol.encoded_len());
        pol.encode(&mut buf).map_err(|e| {
            CompilationError::EncodingError(format!("failed to encode policy: {}", e))
        })?;

        let signature: Vec<u8>;

        match self.private_key {
            Some(ref key) => {
                signature = sign_pkcs1v15_sha256(key, &buf)?;
            }
            None => {
                ctx.warn(
                    "policy not signed, use `--key <pemfile>` to specify a private key for signing",
                )?;
                signature = Vec::new();
            }
        }

        let container = polio::PolicyContainer {
            container_version: CONTAINER_VERSION,
            policy_date: pol.policy_date.clone(),
            policy_version: pol.policy_version,
            policy_revision: pol.policy_revision.clone(),
            policy_metadata: pol.policy_metadata.clone(),
            policy: buf,
            signature,
        };

        Ok(container)
    }
}

/// The entry point for the compilation process, this builder is used to configure
/// the various settings for the compiler.
#[derive(Default)]
pub struct CompilationBuilder {
    source_zpl: PathBuf,
    source_config: Option<PathBuf>,
    verbose: bool,
    werror: bool,
    private_key: Option<Rsa<Private>>,
    parse_only: bool,
    output_directory: Option<PathBuf>,
    out_filename: Option<String>,
}

impl CompilationBuilder {
    /// Takes the ZPL source file. By default the configuration file is assumed
    /// to have the same base name but with a `.zplc` extension instead of `.zpl`.
    pub fn new(source: PathBuf) -> Self {
        Self {
            source_zpl: source,
            ..Default::default()
        }
    }

    /// Enable verbose console output from the compilation process.
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// If set true, treat warnings as errors and halt compilation when they occur.
    pub fn werror(mut self, werror: bool) -> Self {
        self.werror = werror;
        self
    }

    /// Just builds the fabric in memory, does not try to create the policy protobuf binary.
    pub fn parse_only(mut self, parse_only: bool) -> Self {
        self.parse_only = parse_only;
        self
    }

    /// Set the path to the configuration to use with the compilation.
    /// This is optional. If not set, the configuration file is assumed to have
    /// the same base name as the source file but with a `.zplc` extension.
    pub fn config(mut self, config: &Path) -> Self {
        self.source_config = Some(config.into());
        self
    }

    pub fn sign_with_key(mut self, key: Rsa<Private>) -> Self {
        self.private_key = Some(key);
        self
    }

    pub fn output_directory(mut self, output_directory: &Path) -> Self {
        self.output_directory = Some(output_directory.into());
        self
    }

    pub fn output_filename(mut self, out_filename: &str) -> Self {
        self.out_filename = Some(out_filename.into());
        self
    }

    /// Create the [Compilation] object with the settings configured.
    pub fn build(self) -> Compilation {
        // Default config is same name as source replace .zpl extension with .zplc extension
        let config = match self.source_config {
            Some(config) => config,
            None => {
                let mut config = self.source_zpl.clone();
                config.set_extension("zplc");
                config
            }
        };

        let mut output_file = match self.output_directory {
            Some(outdir) => {
                if !outdir.is_dir() {
                    panic!(
                        "output directory {:?} does not exist or is not a directory",
                        outdir
                    );
                }
                let ofile = self.source_zpl.with_extension("bin");
                outdir.join(ofile.file_name().unwrap())
            }
            None => self.source_zpl.with_extension("bin"),
        };

        // If user has selected an alternate output file, substitute that in now.
        if let Some(out_filename) = self.out_filename {
            let base = output_file.parent().unwrap();
            output_file = base.join(out_filename);
        }

        Compilation {
            verbose: self.verbose,
            werror: self.werror,
            source_zpl: self.source_zpl,
            source_config: config,
            output_file,
            private_key: self.private_key,
            parse_only: self.parse_only,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::env;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir {
        path: PathBuf,
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.path)
                .expect("failed to remove compilation test temp dir");
        }
    }

    impl TempDir {
        fn new(name_hint: &str) -> Self {
            let mut temp_dir = env::temp_dir();
            temp_dir.push(format!(
                "compilation-test-{}-{}-{}",
                name_hint,
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            ));
            std::fs::create_dir_all(&temp_dir).expect("failed to create temp dir for zpc output");
            TempDir { path: temp_dir }
        }
    }

    const BASIC_CONFIG: &str = r#"
    [nodes.n0]
    key = "none"
    zpr_address = "fd5a:5052:90de::1"
    interfaces = [ "in1" ]
    in1.netaddr = "127.0.0.1:5000"
    provider = [["foo", "fee"]]

    [visa_service]
    dock_node = "n0"

    [trusted_services.default]
    cert_path = ""

    [protocols.http]
    protocol = "iana.TCP"
    port = 80

    [services.Webby]
    protocol = "http"
    "#;

    #[test]
    fn simple_compile() {
        let zpl = r#"
        define Webby as service with cn
        allow cn: devices to access Webby
        "#;

        let tempdir = TempDir::new("simple_compile");
        let zpl_file = tempdir.path.join("test.zpl");
        std::fs::write(&zpl_file, zpl).expect("failed to write zpl file");

        let cfg_file = tempdir.path.join("test.zplc");
        std::fs::write(&cfg_file, BASIC_CONFIG).expect("failed to write config file");

        let compilation = Compilation::builder(zpl_file)
            .config(&cfg_file)
            .verbose(true)
            .build();

        let result = compilation.compile();
        assert!(
            result.is_ok(),
            "compilation failed: {}",
            result.unwrap_err()
        );
    }

    // In this case with is required since there is no provider in config.
    #[test]
    fn define_requires_with() {
        let zpl = r#"
        define Webby as service
        allow cn: devices to access Webby
        "#;

        let tempdir = TempDir::new("define_requires_with");
        let zpl_file = tempdir.path.join("test.zpl");
        std::fs::write(&zpl_file, zpl).expect("failed to write zpl file");

        let cfg_file = tempdir.path.join("test.zplc");
        std::fs::write(&cfg_file, BASIC_CONFIG).expect("failed to write config file");

        let compilation = Compilation::builder(zpl_file)
            .config(&cfg_file)
            .verbose(true)
            .build();

        let result = compilation.compile();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("service with no attributes"),
            "unexpected error message: {}",
            err_msg
        );
    }

    // In this case with is not required since we have attributes in conifg.
    #[test]
    fn define_ok_without_with() {
        let zplc = r#"
        [nodes.n0]
        key = "none"
        zpr_address = "fd5a:5052:90de::1"
        interfaces = [ "in1" ]
        in1.netaddr = "127.0.0.1:5000"
        provider = [["foo", "fee"]]

        [visa_service]
        dock_node = "n0"

        [trusted_services.default]
        cert_path = ""

        [protocols.http]
        protocol = "iana.TCP"
        port = 80

        [services.Webby]
        protocol = "http"
        provider = [["cn", ""]]
        "#;

        let zpl = r#"
        define Webby as service
        allow cn: devices to access Webby
        "#;

        let tempdir = TempDir::new("define_ok_without_with");
        let zpl_file = tempdir.path.join("test.zpl");
        std::fs::write(&zpl_file, zpl).expect("failed to write zpl file");

        let cfg_file = tempdir.path.join("test.zplc");
        std::fs::write(&cfg_file, zplc).expect("failed to write config file");

        let compilation = Compilation::builder(zpl_file)
            .config(&cfg_file)
            .verbose(true)
            .build();

        let result = compilation.compile();
        assert!(
            result.is_ok(),
            "compilation failed: {}",
            result.unwrap_err()
        );
    }

    #[test]
    fn cannot_use_cn_as_tag() {
        let zpl = r#"
        define Webby as service with cn
        allow cn devices to access Webby
        "#;

        let tempdir = TempDir::new("cannot_use_cn_as_tag");
        let zpl_file = tempdir.path.join("test.zpl");
        std::fs::write(&zpl_file, zpl).expect("failed to write zpl file");

        let cfg_file = tempdir.path.join("test.zplc");
        std::fs::write(&cfg_file, BASIC_CONFIG).expect("failed to write config file");

        let compilation = Compilation::builder(zpl_file)
            .config(&cfg_file)
            .verbose(true)
            .build();

        let result = compilation.compile();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("cn attribute used as a tag"),
            "unexpected error message: {}",
            err_msg
        );
    }

    #[test]
    fn test_svc_attrs_must_be_defined() {
        let zpl = r#"
        define Webby as service with unknown_attr
        allow cn: devices to access services
        "#;

        let tempdir = TempDir::new("test_svc_attrs_must_be_defined");
        let zpl_file = tempdir.path.join("test.zpl");
        std::fs::write(&zpl_file, zpl).expect("failed to write zpl file");

        let cfg_file = tempdir.path.join("test.zplc");
        std::fs::write(&cfg_file, BASIC_CONFIG).expect("failed to write config file");

        let compilation = Compilation::builder(zpl_file)
            .config(&cfg_file)
            .verbose(true)
            .build();

        let result = compilation.compile();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("unknown_attr not found"),
            "unexpected error message: {}",
            err_msg
        );
    }

    #[test]
    fn test_allow_attrs_must_be_defined() {
        let zpl = r#"
        define Webby as service with cn
        allow unknown_attr: devices to access services
        "#;

        let tempdir = TempDir::new("test_allow_attrs_must_be_defined");
        let zpl_file = tempdir.path.join("test.zpl");
        std::fs::write(&zpl_file, zpl).expect("failed to write zpl file");

        let cfg_file = tempdir.path.join("test.zplc");
        std::fs::write(&cfg_file, BASIC_CONFIG).expect("failed to write config file");

        let compilation = Compilation::builder(zpl_file)
            .config(&cfg_file)
            .verbose(true)
            .build();

        let result = compilation.compile();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("unknown_attr not found"),
            "unexpected error message: {}",
            err_msg
        );
    }
}
