use std::path::PathBuf;

use crate::errors::CompilationError;
use crate::lex::tokenize;
use crate::parser::parse;

pub struct Compilation {
    pub verbose: bool,
    pub source_zpl: PathBuf,
    pub source_config: PathBuf,
}

impl Compilation {
    pub fn builder(source: PathBuf) -> CompilationBuilder {
        CompilationBuilder::new(source)
    }

    pub fn compile(&self) -> Result<(), CompilationError>{
        if self.verbose {
            println!(
                "compiling {:?} with config {:?}",
                self.source_zpl, self.source_config
            );
        }
        let tokens = tokenize(&self.source_zpl)?;
        for t in &tokens {
            println!("   {:?}", t);
        }
        println!();

        let _policy = parse(tokens)?;
        Ok(())
    }
}

#[derive(Default)]
pub struct CompilationBuilder {
    source_zpl: PathBuf,
    source_config: Option<PathBuf>,
    verbose: bool,
}

impl CompilationBuilder {
    pub fn new(source: PathBuf) -> Self {
        Self {
            source_zpl: source,
            ..Default::default()
        }
    }

    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    #[allow(dead_code)]
    pub fn config(mut self, config: PathBuf) -> Self {
        self.source_config = Some(config);
        self
    }

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
