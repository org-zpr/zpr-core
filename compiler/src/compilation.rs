use std::path::PathBuf;
use thiserror::Error;

use crate::lex::tokenize;
use crate::parser::parse;



#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum CompilationError {
    #[error("unexpected tab char at line {0}, column {1}")]
    UnexpectedTab(usize, usize),

    #[error("mismatched quote at line {0}, column {1}")]
    MismatchedQuote(usize, usize),

    #[error("unterminated quote at line {0}, column {1}")]
    UnterminatedQuote(usize, usize),

    #[error("illegal quote at line {0}, column {1}")]
    IllegalQuote(usize, usize),

    #[error("illegal colon at line {0}, column {1}")]
    IllegalColon(usize, usize),

    #[error("unexpected token at line {0}, column {1}")]
    UnexpectedToken(usize, usize),

    #[error("unexpected keyword at line {1}, column {2}: {0}")]
    UnexpectedKeyword(String, usize, usize),

    #[error("redefinition of {0} at line {1}, column {2}")]
    Redefinition(String, usize, usize),

    #[error("[ line {1}, column {2} ]  {0}")]
    ParseError(String, usize, usize),

    #[error("IoError: {0}")]
    Io(#[from] std::io::Error),
}



pub struct Compilation {
    pub verbose: bool,
    pub source_zpl: PathBuf,
    pub source_config: PathBuf,
}


impl Compilation {
    pub fn builder(source: PathBuf) -> CompilationBuilder {
        CompilationBuilder::new(source)
    }

    pub fn compile(&self) {
        if self.verbose {
            println!("compiling {:?} with config {:?}", self.source_zpl, self.source_config);
        }
        match tokenize(&self.source_zpl) {
            Ok(tokens) => {
                for t in &tokens {
                    println!("   {:?}", t);
                }
                println!();

                match parse(tokens) {
                    Ok(_policy) => {
                        println!("OK!");
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: {}", e);
            }
        }
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