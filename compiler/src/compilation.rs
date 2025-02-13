use std::path::{Path, PathBuf};
use std::time::Duration;

use openssl::pkey::Private;
use openssl::rsa::Rsa;
use prost::Message;

use crate::config::load_config;
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
        if self.verbose {
            println!(
                "compiling {:?} with config {:?}",
                self.source_zpl, self.source_config
            );
        }
        let cfg = load_config(&self.source_config).map_err(|e| {
            CompilationError::ConfigError(format!(
                "failed to load configuration from {:?}: {}",
                self.source_config, e
            ))
        })?;

        let tokens = tokenize(&self.source_zpl)?;
        if self.verbose {
            println!("parsed {} tokens:", tokens.len());
            for t in &tokens {
                println!("   {:?}", t);
            }
            println!();
        }

        let mut policy = parse(tokens, self.verbose)?;
        let policy_digest = sha256_of_file(&self.source_zpl)?;
        policy.digest = Some(policy_digest);

        let fabric = weave(&self, &cfg, &policy)?;
        if self.verbose {
            println!();
            println!("fabric production:\n{}", fabric);
        }

        println!("ℤ parse successful");
        if self.parse_only {
            return Ok(());
        }

        let mut builder = PolicyBuilder::new(self.verbose);
        builder.with_max_visa_lifetime(Duration::from_secs(60 * 60 * 12)); // 12 hours (TODO: Should come from config)

        builder.with_fabric(&fabric)?;

        let pol = builder.build()?;
        println!("ℤ build successful");

        let pcontainer = self.contain_policy(&pol)?;
        self.write_container(&pcontainer, &self.output_file)?;

        Ok(())
    }

    /// Write the policy container to the output file, serializing with protocol buffers.
    fn write_container(
        &self,
        container: &polio::PolicyContainer,
        file: &Path,
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
        println!("ℤ wrote {}", &file.display());
        Ok(())
    }

    /// Create the container struct and optionally sign the policy with the private key.
    fn contain_policy(
        &self,
        pol: &polio::Policy,
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
                println!("warning: policy not signed, use `--key <pemfile>` to specify a private key for signing");
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
            source_zpl: self.source_zpl,
            source_config: config,
            output_file,
            private_key: self.private_key,
            parse_only: self.parse_only,
        }
    }
}
