use colored::Colorize;

use crate::errors::CompilationError;

pub struct CompilationCtx {
    /// True if user requests verbose output
    pub verbose: bool,

    /// True if warnings should be promoted to errors
    werror: bool,
}

impl CompilationCtx {
    pub fn new(verbose: bool, werror: bool) -> Self {
        CompilationCtx { verbose, werror }
    }

    /// Show an informational message.
    pub fn info(&self, msg: &str) {
        println!("{} {}", "ℤ".cyan(), msg);
    }

    /// Show a warning.  May raise an error if warnings are promoted to errors.
    pub fn warn(&self, msg: &str) -> Result<(), CompilationError> {
        println!("{}: {}", "warning".yellow().bold(), msg.bold());
        if self.werror {
            Err(CompilationError::Warning(msg.to_string()))
        } else {
            Ok(())
        }
    }
}

impl Default for CompilationCtx {
    fn default() -> Self {
        CompilationCtx {
            verbose: true,
            werror: false,
        }
    }
}
