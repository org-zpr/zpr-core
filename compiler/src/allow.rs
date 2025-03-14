//! allow.rs - parser for allow statements

use std::collections::HashMap;
use std::iter::Peekable;

use crate::errors::CompilationError;
use crate::lex::{Token, TokenType};
use crate::ptypes::{AllowClause, Attribute, Class, ClassFlavor, Clause};
use crate::putil;
use crate::zpl;

#[derive(Debug, Default)]
struct ParseAllowState {
    root_tok: Token,
    device_clause: Option<Clause>,
    user_clause: Option<Clause>,
    service_clause: Option<Clause>,
}

impl ParseAllowState {
    fn new(root_tok: Token) -> ParseAllowState {
        ParseAllowState {
            root_tok,
            ..Default::default()
        }
    }

    /// This consumes all the clauses or panics.
    fn to_allow_clause(&mut self, id: usize) -> AllowClause {
        AllowClause {
            id,
            device: self.device_clause.take().expect("device clause not set"),
            user: self.user_clause.take().expect("user clause not set"),
            service: self.service_clause.take().expect("service clause not set"),
        }
    }
}

/// First token is an ALLOW which is checked by caller.
///
/// Format of the allow statement is:
///
/// allow <device-clause> with <user-clause> to access <service-clause>
///
/// If there are both device and user clauses they are separated by 'with'.
/// You can omit either user or device clauses:
///
/// allow <user-clause> to access <service-clause>
/// allow <device-clause> to access <service-clause>
///
/// `classes_idx` maps class names and AKA names to their canonical names (eg, "services" -> "service").
/// `classs_map` maps class canonical name to [Class] struct.
pub fn parse_allow(
    allow_statement: &[Token],
    statement_id: usize,
    classes_idx: &HashMap<String, String>,
    classes_map: &HashMap<String, Class>,
) -> Result<AllowClause, CompilationError> {
    if allow_statement.is_empty() {
        panic!("parse_allow called with empty statement");
    }
    if allow_statement[0].tt != TokenType::Allow {
        panic!("parse_allow called with non-ALLOW statement");
    }

    let root_tok = &allow_statement[0];
    let mut parse_state = ParseAllowState::new(root_tok.clone());
    let mut tokens = allow_statement[1..].iter().peekable();
    let mut ps = PState::new(&parse_state.root_tok);

    // To parse this we start parsing and break if we hit a WITH or a TO.
    ps.parse_tags_attrs_and_classname(
        &mut tokens,
        classes_idx,
        &&ParseOpts::stop_at_any(&vec![TokenType::To, TokenType::With]),
        "device or user clause",
    )?;

    match tokens.peek() {
        Some(tok) => {
            let cn = ps.class_name.as_ref().unwrap();

            // If we hit a TO then we expect either a DEVICE or USER clause
            match tok.tt {
                TokenType::To => {
                    // Must have eitherr a device or user clause.
                    match classes_map.get(cn).unwrap().flavor {
                        ClassFlavor::User => {
                            // Device clause is skipped, so use default.
                            parse_state.device_clause = Some(Clause::new(
                                zpl::DEF_CLASS_DEVICE_NAME,
                                parse_state.root_tok.clone(),
                            ));
                            let uc = ps.to_clause("user")?;
                            parse_state.user_clause = Some(uc);
                        }
                        ClassFlavor::Device => {
                            // User clause is skipped, so use default.
                            parse_state.user_clause = Some(Clause::new(
                                zpl::DEF_CLASS_USER_NAME,
                                parse_state.root_tok.clone(),
                            ));
                            let dc = ps.to_clause("device")?;
                            parse_state.device_clause = Some(dc);
                        }
                        _ => {
                            return Err(CompilationError::AllowStmtParseError(
                                format!("not a user or device clause: '{}'", cn),
                                parse_state.root_tok.line,
                                parse_state.root_tok.col,
                            ));
                        }
                    }
                }

                // If we hit a WITH then we expect a DEVICE clause.
                TokenType::With => {
                    // Hit WITH which means we must have parsed a device clause, and we expect a user clause to follow.
                    if classes_map.get(cn).unwrap().flavor == ClassFlavor::Device {
                        let dc = ps.to_clause("device")?;
                        parse_state.device_clause = Some(dc);
                    } else {
                        return Err(CompilationError::AllowStmtParseError(
                            format!("not a device clause: '{}'", cn),
                            parse_state.root_tok.line,
                            parse_state.root_tok.col,
                        ));
                    }
                }

                // Hmm what's this?
                _ => {
                    return Err(CompilationError::AllowStmtParseError(
                        format!("expected a TO or WITH, found '{:?}'", tok.tt),
                        parse_state.root_tok.line,
                        parse_state.root_tok.col,
                    ));
                }
            }
        }
        None => {
            // end of tokens!
            return Err(CompilationError::AllowStmtParseError(
                "expected a TO or WITH not EOF".to_string(),
                parse_state.root_tok.line,
                parse_state.root_tok.col,
            ));
        }
    }

    // If we get this far, we have parsed up to a WITH or a TO.
    // If it's a WITH then we expect a user clause next.
    // If it's a TO then we expect a service clause next.
    let tok = tokens.next().unwrap();
    match tok.tt {
        TokenType::With => {
            if parse_state.device_clause.is_none() {
                panic!("assertion fails - no device clause");
            }
            // Ok, now parse a USER clause, returns having found but not parsed 'TO'.
            if !try_parse_allow_user_clause(
                &mut parse_state,
                &mut tokens,
                classes_idx,
                classes_map,
            )? {
                // Hmm, a non error failure?
                return Err(CompilationError::AllowStmtParseError(
                    "expected a user clause to follow WITH".to_string(),
                    tok.line,
                    tok.col,
                ));
            }
            // pop the TO off, leaving the 'access'.
            putil::require_tt(
                &parse_state.root_tok,
                tokens.next(),
                "TO",
                "allow",
                TokenType::To,
            )?;
        }
        TokenType::To => { /* continue to parse service clause */ }
        _ => {
            // We already peek'd the iterator above, so this case should not happen.
            panic!("assertion fails - expected WITH or TO token");
        }
    }

    if parse_state.user_clause.is_none() {
        panic!("assertion fails - no user clause");
    }

    // The remaining tokens should start with "access ..." which we pass to the service class parser.
    parse_allow_service_clause(&mut parse_state, &mut tokens, classes_idx, classes_map)?;

    let ac = parse_state.to_allow_clause(statement_id);
    validate_clause(&ac, classes_map)?;
    Ok(ac)
}

// The place to catch semantic errors before returning the clause.
fn validate_clause(
    ac: &AllowClause,
    classes_map: &HashMap<String, Class>,
) -> Result<(), CompilationError> {
    if ac.user.with_attr_count(classes_map) + ac.device.with_attr_count(classes_map) == 0 {
        return Err(CompilationError::AllowStmtParseError(
            "user and/or device must specify at least one discriminating attribute".to_string(),
            ac.user.class_tok.line,
            ac.user.class_tok.col,
        ));
    }
    Ok(())
}

/// Parse from <user-clause> up to the 'TO' (of 'TO ACCESS')
/// If this succeeds, it sets the user clause in the [ParseAllowState].
fn try_parse_allow_user_clause<'a, I>(
    pa_state: &mut ParseAllowState,
    tokens: &mut Peekable<I>,
    classes_idx: &HashMap<String, String>,
    classes_map: &HashMap<String, Class>,
) -> Result<bool, CompilationError>
where
    I: Iterator<Item = &'a Token>,
{
    let mut ps = PState::new(&pa_state.root_tok);

    ps.parse_tags_attrs_and_classname(
        tokens,
        classes_idx,
        &ParseOpts::stop_at(TokenType::To),
        "user clause",
    )?;

    // This is a good parse if we actually got a user flavor class.
    let cn = ps.class_name.as_ref().unwrap();
    if classes_map.get(cn).unwrap().flavor == ClassFlavor::User {
        let uc = ps.to_clause("user")?;
        pa_state.user_clause = Some(uc);
        Ok(true)
    } else {
        Ok(false) // not a user clause
    }
}

/// Parse the final bit of the allow statement which is the service clause.
/// The passed tokens MUST start with "ACCESS".
fn parse_allow_service_clause<'a, I>(
    pa_state: &mut ParseAllowState,
    tokens: &mut Peekable<I>,
    classes_idx: &HashMap<String, String>,
    classes_map: &HashMap<String, Class>,
) -> Result<(), CompilationError>
where
    I: Iterator<Item = &'a Token>,
{
    // Pop off the "ACCESS" token...
    putil::require_tt(
        &pa_state.root_tok,
        tokens.next(),
        "ACCESS",
        "allow",
        TokenType::Access,
    )?;

    // Need a service clause now -- parse to end of statement.
    let mut ps = PState::new(&pa_state.root_tok);
    ps.parse_tags_attrs_and_classname(
        tokens,
        classes_idx,
        &ParseOpts::default(),
        "service clause",
    )?;

    let cn = ps.class_name.as_ref().unwrap();
    if classes_map.get(cn).unwrap().flavor != ClassFlavor::Service {
        return Err(CompilationError::AllowStmtParseError(
            format!("not a service class: '{}'", cn),
            pa_state.root_tok.line,
            pa_state.root_tok.col,
        ));
    }
    let service_clause = ps.to_clause("service")?;
    pa_state.service_clause = Some(service_clause);

    Ok(())
}

struct PState {
    root_tok: Token,
    class_name: Option<String>,
    class_name_token: Option<Token>,
    attrs: Vec<Attribute>,
}

struct ParseOpts {
    // stop parsing if we see (but do not consume) one of these tokens
    break_at: Vec<TokenType>,

    // Stop after this many occurrances of break_at token. Note only last occurance is not consumed.
    break_at_count: usize,
}

impl ParseOpts {
    fn stop_at(break_at: TokenType) -> Self {
        Self {
            break_at: vec![break_at],
            break_at_count: 1,
        }
    }
    fn stop_at_any(tokens: &[TokenType]) -> Self {
        Self {
            break_at: tokens.to_vec(),
            break_at_count: 1,
        }
    }
    fn is_stop_token(&self, tt: &TokenType) -> bool {
        self.break_at.contains(tt)
    }
}

impl Default for ParseOpts {
    fn default() -> Self {
        Self {
            break_at: vec![TokenType::EOS],
            break_at_count: 1,
        }
    }
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
            return Err(CompilationError::AllowStmtParseError(
                format!("expected a class name in a {} clause", kind),
                self.root_tok.line,
                self.root_tok.col,
            ));
        }
        Ok(Clause {
            class: self.class_name.clone().unwrap(), // flavor is not checked
            class_tok: self.class_name_token.as_ref().unwrap().clone(), // always set if class_name is set
            with: self.attrs.clone(),
        })
    }

    fn parse_tags_attrs_and_classname<'a, I>(
        &mut self,
        tokens: &mut Peekable<I>,
        classes: &HashMap<String, String>,
        opts: &ParseOpts,
        context: &str,
    ) -> Result<(), CompilationError>
    where
        I: Iterator<Item = &'a Token>,
    {
        let mut tcount = 0;
        let mut break_count = 0;
        while let Some(tokref) = tokens.peek() {
            tcount += 1;
            if opts.is_stop_token(&tokref.tt) {
                break_count += 1;
                if break_count >= opts.break_at_count {
                    break;
                }
            }
            match &tokref.tt {
                TokenType::And | TokenType::Comma => {
                    // These are delimiter tokens.
                    tokens.next();
                }
                TokenType::Tuple((name, value)) => {
                    // This is an attribute.
                    let attr = Attribute::attr(name, value);
                    self.attrs.push(attr);
                    tokens.next();
                }
                TokenType::Literal(s) => {
                    // This could be a class name or a tag name.
                    if let Some(class) = classes.get(s) {
                        if self.class_name.is_some() {
                            // We already have a class name.
                            let tok = tokens.next().unwrap();
                            return Err(CompilationError::MultipleClassNames(
                                format!("found class '{class}' but class already set: {context}"),
                                tok.line,
                                tok.col,
                            ));
                        }
                        self.class_name = Some(class.clone());
                        let tok = tokens.next().unwrap();
                        self.class_name_token = Some(tok.clone());
                    } else {
                        self.attrs.push(Attribute::tag(s));
                        tokens.next();
                    }
                }
                TokenType::With => {
                    // We used to support a postfix form of attributes but no longer.
                    // If we see this we report an error to help people covert old ZPL.
                    let tok = tokens.next().unwrap();
                    return Err(CompilationError::AllowStmtParseError(
                        format!(
                            "postfix attribute form using WITH no longer supported: {}",
                            context
                        ),
                        tok.line,
                        tok.col,
                    ));
                }
                _ => {
                    let tok = tokens.next().unwrap();
                    return Err(CompilationError::SyntaxError(
                        format!("{} ({:?})", context, tok.tt),
                        tok.line,
                        tok.col,
                    ));
                }
            };
        }
        if tcount == 0 {
            return Err(CompilationError::AllowStmtParseError(
                format!("{} is empty", context),
                self.root_tok.line,
                self.root_tok.col,
            ));
        }

        if self.class_name.is_none() {
            return Err(CompilationError::AllowStmtParseError(
                format!("expected a class name in {}", context),
                self.root_tok.line,
                self.root_tok.col,
            ));
        }

        Ok(())
    }
}
