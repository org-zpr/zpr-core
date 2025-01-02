use thiserror::Error;

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
