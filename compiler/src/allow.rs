//! allow.rs - parser for allow statements

use std::collections::HashMap;
use std::iter::Peekable;

use crate::errors::CompilationError;
use crate::lex::{Token, TokenType};
use crate::ptypes::{AllowClause, Attribute, Clause};
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
    //
    //   allow <endpoint-clause> WITH <user-clause> TO ACCESS <service-clause>
    //
    // In real ZPL you could omit one of the endpoint or user classes. But not in this parser.
    // For example, you must rewrite-
    //     allow user to access service foo
    //   as
    //     allow endpoints with user to access service foo

    let mut ps = PState::new(root_tok);

    // Parse the endpoint clause. This clause is delimited by the WITH token (unlike a user clause)
    ps.parse_tags_attrs_and_classname(
        &mut tokens,
        classes_idx,
        TokenType::With,
        "endpoint clause",
    )?;

    // The class we just parsed needs to be a defined endpoint type.
    // But we only have the index here, not the actual class with the flavor. So we will leave that to
    // caller to check.

    let endpoint_clause = ps.to_clause("endpoint")?;

    // Next parse a user clause
    putil::require_tt(root_tok, tokens.next(), "WITH", "allow", TokenType::With)?;

    ps = PState::new(root_tok);
    ps.parse_tags_attrs_and_classname(&mut tokens, classes_idx, TokenType::To, "user clause")?;
    let user_clause = ps.to_clause("user")?;

    // Next token sequence better be TO ACCESS.
    // TODO: Maybe better to have single token TO_ACCESS ?
    putil::require_tt(root_tok, tokens.next(), "TO", "allow", TokenType::To)?;
    putil::require_tt(
        root_tok,
        tokens.next(),
        "ACCESS",
        "allow",
        TokenType::Access,
    )?;

    // Need a service clause now -- parse to end of statement.
    ps = PState::new(root_tok);
    ps.parse_tags_attrs_and_classname(&mut tokens, classes_idx, TokenType::EOS, "service clause")?;
    let service_clause = ps.to_clause("service")?;

    Ok(AllowClause {
        endpoint: endpoint_clause,
        user: user_clause,
        service: service_clause,
    })
}

struct PState {
    root_tok: Token,
    class_name: Option<String>,
    class_name_token: Option<Token>,
    attrs: Vec<Attribute>,
}

impl PState {
    fn new(root_tok: &Token) -> PState {
        PState {
            root_tok: root_tok.clone(),
            class_name: None,
            class_name_token: None,
            attrs: Vec::new(),
        }
    }

    fn to_clause(&self, kind: &str) -> Result<Clause, CompilationError> {
        if self.class_name.is_none() {
            return Err(CompilationError::ParseError(
                format!("expected a class name in a {} clause", kind),
                self.root_tok.line,
                self.root_tok.col,
            ));
        }
        Ok(Clause {
            class: self.class_name.clone().unwrap(), // flavor is not checked
            class_tok: self.class_name_token.clone(),
            with: self.attrs.clone(),
        })
    }

    fn parse_tags_attrs_and_classname<'a, I>(
        &mut self,
        tokens: &mut Peekable<I>,
        classes: &HashMap<String, String>,
        break_at: TokenType,
        context: &str,
    ) -> Result<(), CompilationError>
    where
        I: Iterator<Item = &'a Token>,
    {
        loop {
            if let Some(tokref) = tokens.peek() {
                if break_at == tokref.tt {
                    break;
                }
                match &tokref.tt {
                    TokenType::And | TokenType::Comma => {
                        // These are delimiter tokens.
                        tokens.next();
                    }
                    TokenType::Tuple((name, value)) => {
                        // This is an attribute.
                        let attr = Attribute::attr(&name, &value);
                        self.attrs.push(attr);
                        tokens.next();
                    }
                    TokenType::Literal(s) => {
                        // This could be a class name or a tag name.
                        if let Some(class) = classes.get(s) {
                            // We already have a class name.
                            if self.class_name.is_some() {
                                let tok = tokens.next().unwrap();
                                return Err(CompilationError::ParseError(
                                    format!("multiple class names in {}", context),
                                    tok.line,
                                    tok.col,
                                ));
                            }
                            self.class_name = Some(class.clone());
                            let tok = tokens.next().unwrap();
                            self.class_name_token = Some(tok.clone());
                        } else {
                            self.attrs.push(Attribute::tag(&s));
                            tokens.next();
                        }
                    }
                    TokenType::With => {
                        // We must have already parsed a class name.
                        if self.class_name.is_none() {
                            let tok = tokens.next().unwrap();
                            return Err(CompilationError::ParseError(
                                format!("expected class name before WITH in {}", context),
                                tok.line,
                                tok.col,
                            ));
                        }
                        tokens.next();
                    }
                    _ => {
                        let tok = tokens.next().unwrap();
                        return Err(CompilationError::ParseError(
                            format!("syntax error in {} ({:?})", context, tok.tt),
                            tok.line,
                            tok.col,
                        ));
                    }
                };
            } else {
                break; // iterator is empty
            }
        }

        if self.class_name.is_none() {
            return Err(CompilationError::ParseError(
                format!("expected a class name in {}", context),
                self.root_tok.line,
                self.root_tok.col,
            ));
        }

        Ok(())
    }
}
