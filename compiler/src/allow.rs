//! allow.rs - parser for allow statements

use std::collections::HashMap;

use crate::errors::CompilationError;
use crate::lex::{TokenType, Token};
use crate::ptypes::{Attribute, AllowClause, Class, Clause};
use crate::putil;



// First token is an ALLOW which is checked by caller.
pub fn parse_allow(
    allow_statement: &[Token],
    classes_idx: &HashMap<String, String>,
) -> Result<AllowClause, CompilationError> {
    if allow_statement.len() < 1 {
        panic!("parse_allow called with empty statement");
    }
    if allow_statement[0].tt != TokenType::Allow {
        panic!("parse_allow called with non-ALLOW statement");
    }
    let mut tokens = allow_statement.into_iter().peekable();
    let _allow = tokens.next().unwrap(); // consume the ALLOW token

    let root_tok = &allow_statement[0];


    // Our simplified grammer:
    // allow <endpoint-clause> WITH <user-clause> TO ACCESS <service-clause>

    let mut endpoint_clause = Clause::default();
    let mut remaining_tokens = parse_allow_endpoint_clause(
        root_tok,
        tokens,
        classes_idx,
        &mut endpoint_clause)?;

    let mut rtokens = remaining_tokens.iter().peekable();

    // The endpoint parser will break on the WITH token. So now we need to parse the
    // user clause.
    let mut user_clause = Clause::default();
    remaining_tokens = parse_allow_user_clause(
        root_tok,
        rtokens,
        classes_idx,
        &mut user_clause)?;
    rtokens = remaining_tokens.iter().peekable();

    // The user clause parse will break on the TO token.
    // "access" is next
    putil::require_tt(root_tok, rtokens.next(), "ACCESS", "allow", TokenType::Access)?;

    // parse service bits

    // we need access to the defines in order to differentiate between class names and attribute names.

    Err(CompilationError::Io(std::io::Error::new(
        std::io::ErrorKind::Other,
        "not implemented",
    )))
}


// allow <endpoint-clause> to access
//       ^^^^^^^^^^^^^^^^^
//
// The endpoint must be either a built in class (user, service, endpoint) or a defined class.
//
//     tag tag CLASS with FOO
//     name:val tag etc CLASS with FOO
//     CLASS with blah
//
// Process each token expecting either a tag or tuple or classname.
// Once we get a classname we expect an optional WITH section which ends with the "to access" tokens.
fn parse_allow_endpoint_clause<'a, I>(root_tok: &Token, tokens: I, classes: &HashMap<String, String>, endpoint_clause: &mut Clause) -> Result<Vec<Token>, CompilationError>
where
    I: Iterator<Item = &'a Token>,
{
    let mut remaining_tokens: Vec<Token> = Vec::new();
    let mut finish = false;
    let mut parent_class: Option<String> = None;

    for tok in tokens {
        if !finish {
            match &tok.tt {
                TokenType::To => {
                    return Err(CompilationError::ParseError(
                        "expected WITH before TO".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                TokenType::And | TokenType::Comma => {
                    // These are delimiter tokens.
                    // ...
                }
                TokenType::Tuple((name, value)) => {
                    endpoint_clause.with.push(Attribute::attr(name, value));
                }
                TokenType::Literal(s) => {
                    // This could be a class name or a tag name.
                    if let Some(class) = classes.get(s) {
                        // We have a class name.
                        if parent_class.is_some() {
                            return Err(CompilationError::ParseError(
                                "multiple endpoint class names".to_string(),
                                tok.line,
                                tok.col,
                            ));
                        }
                        parent_class = Some(class.clone());
                        endpoint_clause.class = class.clone();
                    } else {
                        endpoint_clause.with.push(Attribute::tag(s));
                    }
                }
                TokenType::With => {
                    // We must have already parsed a class name.
                    if parent_class.is_none() {
                        return Err(CompilationError::ParseError(
                            "expected class name before WITH".to_string(),
                            tok.line,
                            tok.col,
                        ));
                    }
                    // This indicates end of this clause, I beleive.
                    finish = true;
                }
                _ => {
                    return Err(CompilationError::ParseError(
                        format!("syntax error ({:?})", tok.tt),
                        tok.line,
                        tok.col,
                    ));
                }
            }
        } else {
            // Just copy over all the remaining tokens out of the iterator.
            remaining_tokens.push(tok.clone());
        }
    }

    if parent_class.is_none() {
        return Err(CompilationError::ParseError(
            "expected endpoint class name".to_string(),
            root_tok.line,
            root_tok.col,
        ));
    }

    Ok(remaining_tokens)
}




fn parse_allow_user_clause<'a, I>(root_tok: &Token, tokens: I, classes: &HashMap<String, String>, user_clause: &mut Clause) -> Result<Vec<Token>, CompilationError>
where
    I: Iterator<Item = &'a Token>,
{
    let mut remaining_tokens: Vec<Token> = Vec::new();
    let mut finish = false;
    let mut parent_class: Option<String> = None;

    for tok in tokens {
        if !finish {
            match &tok.tt {
                TokenType::To => {
                    if parent_class.is_none() {
                        return Err(CompilationError::ParseError(
                            "expected user class name before TO".to_string(),
                            tok.line,
                            tok.col,
                        ));
                    }
                    // Assume ACCESS will be coming next.
                    finish = true;
                }
                TokenType::And | TokenType::Comma => {
                    // These are delimiter tokens.
                    // ...
                }
                TokenType::Tuple((name, value)) => {
                    user_clause.with.push(Attribute::attr(name, value));
                }
                TokenType::Literal(s) => {
                    // This could be a class name or a tag name.
                    if let Some(class) = classes.get(s) {
                        // We have a class name.
                        if parent_class.is_some() {
                            return Err(CompilationError::ParseError(
                                "multiple user class names".to_string(),
                                tok.line,
                                tok.col,
                            ));
                        }
                        parent_class = Some(class.clone());
                        user_clause.class = class.clone();
                    } else {
                        user_clause.with.push(Attribute::tag(s));
                    }
                }
                TokenType::With => {
                    return Err(CompilationError::ParseError(
                        "unexpected WITH in user clause".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                _ => {
                    return Err(CompilationError::ParseError(
                        format!("syntax error ({:?})", tok.tt),
                        tok.line,
                        tok.col,
                    ));
                }
            }
        } else {
            // Just copy over all the remaining tokens out of the iterator.
            remaining_tokens.push(tok.clone());
        }
    }

    if parent_class.is_none() {
        return Err(CompilationError::ParseError(
            "expected endpoint class name".to_string(),
            root_tok.line,
            root_tok.col,
        ));
    }

    Ok(remaining_tokens)
}