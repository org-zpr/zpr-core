use thiserror::Error;

/// The various errors that may occur during parsing and compilation.
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

    #[error("[ line {1}, column {2} ]  syntax error in {0}")]
    SyntaxError(String, usize, usize),

    #[error("[ line {1}, column {2} ]  multiple class names in {0}")]
    MultipleClassNames(String, usize, usize),

    #[error("[ line {1}, column {2} ]  conflicting values for attribute {0}")]
    AttributeValueConflict(String, usize, usize),

    #[error("attribute error: {0}")]
    AttributeError(String),

    #[error("[ line {1}, column {2} ] {0}")]
    ZPLError(String, usize, usize),

    #[error("IoError: {0}")]
    Io(#[from] std::io::Error),

    #[error("FileError: {0}")]
    FileError(String),

    #[error("TomlError: {0}")]
    TomlError(#[from] toml::de::Error),

    #[error("configuration error: {0}")]
    ConfigError(String),

    #[error("encoding error: {0}")]
    EncodingError(String),

    #[error("crypto error: {0}")]
    CryptoError(String),
}
