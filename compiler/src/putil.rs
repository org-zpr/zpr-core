use crate::errors::CompilationError;
use crate::lex::{Token, TokenType};

// Given the next token in the list, we error out if that token is not of the expected type.
pub fn require_tt(
    parent_tok: &Token,
    next_tok: Option<&Token>,
    expect: &str,
    statement_type: &str,
    expect_tt: TokenType,
) -> Result<(), CompilationError> {
    match next_tok {
        Some(tok) => {
            if tok.tt == expect_tt {
                Ok(())
            } else {
                Err(CompilationError::ParseError(
                    format!("expected {expect}, found {:?}", tok.tt),
                    tok.line,
                    tok.col,
                ))
            }
        }
        None => Err(CompilationError::ParseError(
            format!("malformed {} (expected {})", statement_type, expect),
            parent_tok.line,
            parent_tok.col,
        )),
    }
}

// Expect the next token in the list to be a literal, and if so we return a copy of the value.
pub fn return_literal(
    parent_tok: &Token,
    next_tok: Option<&Token>,
    expect_desc: &str,
    statement_type: &str,
) -> Result<String, CompilationError> {
    let value = match next_tok {
        Some(tok) => match &tok.tt {
            TokenType::Literal(s) => s,
            _ => {
                return Err(CompilationError::ParseError(
                    format!("expected {} to follow {}", expect_desc, statement_type),
                    tok.line,
                    tok.col,
                ));
            }
        },
        None => {
            return Err(CompilationError::ParseError(
                format!("malformed {}", statement_type),
                parent_tok.line,
                parent_tok.col,
            ));
        }
    };
    Ok(value.clone())
}

// Could be more sophisticated.
pub fn pluralize(s: &str) -> String {
    format!("{}s", s)
}
