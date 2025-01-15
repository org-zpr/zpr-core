use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::load_config;
use crate::crypto::sha256_of_file;
use crate::errors::CompilationError;
use crate::lex::tokenize;
use crate::parser::parse;
use crate::fabric::weave;
use crate::policybuilder::PolicyBuilder;

/// Create one of these with the [CompilationBuilder].
pub struct Compilation {
    pub verbose: bool,
    pub source_zpl: PathBuf,
    pub source_config: PathBuf,
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
        for t in &tokens {
            println!("   {:?}", t);
        }
        println!();

        let mut policy = parse(tokens)?;
        let policy_digest = sha256_of_file(&self.source_zpl)?;
        policy.digest = Some(policy_digest);

        let fabric = weave(&self, &cfg, &policy)?;
        println!("FABRIC:\n{}", fabric);

        let mut builder = PolicyBuilder::new();
        builder.with_max_visa_lifetime(Duration::from_secs(60 * 60 * 12)); // 12 hours (TODO: Should come from config)

        builder.with_fabric(&fabric)?;

        let _pol = builder.build()?;

        println!("build successful -- now what?");
        // TODO: put into signed container.

        Ok(())
    }
}

/// The entry point for the compilation process, this builder is used to configure
/// the various settings for the compiler.
#[derive(Default)]
pub struct CompilationBuilder {
    source_zpl: PathBuf,
    source_config: Option<PathBuf>,
    verbose: bool,
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

    /// Set the path to the configuration to use with the compilation.
    /// This is optional. If not set, the configuration file is assumed to have
    /// the same base name as the source file but with a `.zplc` extension.
    #[allow(dead_code)]
    pub fn config(mut self, config: &Path) -> Self {
        self.source_config = Some(config.into());
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
        Compilation {
            verbose: self.verbose,
            source_zpl: self.source_zpl,
            source_config: config,
        }
    }
}
