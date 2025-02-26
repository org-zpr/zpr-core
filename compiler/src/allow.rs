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
            device: self
                .device_clause
                .take()
                .expect("device clause not set"),
            user: self.user_clause.take().expect("user clause not set"),
            service: self.service_clause.take().expect("service clause not set"),
        }
    }
}

// First token is an ALLOW which is checked by caller.
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

    // A place to stash tokens -- used if we end up having to parse the
    // full two clauses of endpint and user.
    let tokens_remain: Vec<Token>;

    let mut tokens = allow_statement[1..].iter().peekable();
    if !try_parse_allow_no_endpoint_clause(&mut parse_state, &mut tokens, classes_idx, classes_map)?
    {
        // Attempt 1 did not parse, so try again this time assuming no user clause.
        tokens = allow_statement[1..].iter().peekable();
        if !try_parse_allow_no_user_clause(&mut parse_state, &mut tokens, classes_idx, classes_map)?
        {
            // Attempt 2 did not parse, so now we try to parse both a user and endpoint clause.
            // This must succeed or it is compilation fail.
            tokens_remain = parse_allow_endpoint_and_user_clauses(
                &mut parse_state,
                allow_statement,
                classes_idx,
                classes_map,
            )?;
            tokens = tokens_remain.iter().peekable();
        }
    }

    // At this point we have a valid endpoint and user clause.  Just need to parse the final service clause.
    if parse_state.device_clause.is_none() {
        panic!("assertion fails - no endpoint clause");
    }
    if parse_state.user_clause.is_none() {
        panic!("assertion fails - no user clause");
    }

    // The remaining tokens should start with "to access ..." which we pass to the service class parser.
    parse_allow_service_clause(&mut parse_state, &mut tokens, classes_idx, classes_map)?;

    Ok(parse_state.to_allow_clause(statement_id))
}

/// Assume there is only a user clause (no endpoint clause).
///
/// Attempt to parse the allow statement user and endpoint clauses while assuming
/// there is no endpoint clause (so will be default).  If this succeeds, it sets the
/// user and endpoint clauses in the [ParseAllowState].
fn try_parse_allow_no_endpoint_clause<'a, I>(
    pa_state: &mut ParseAllowState,
    tokens: &mut Peekable<I>,
    classes_idx: &HashMap<String, String>,
    classes_map: &HashMap<String, Class>,
) -> Result<bool, CompilationError>
where
    I: Iterator<Item = &'a Token>,
{
    let mut ps = PState::new(&pa_state.root_tok);

    match ps.parse_tags_attrs_and_classname(
        tokens,
        classes_idx,
        &ParseOpts::stop_at(TokenType::To),
        "possible user clause",
    ) {
        Ok(_) => {
            // This is a good parse if we actually got a user flavor class.
            let cn = ps.class_name.as_ref().unwrap();
            if classes_map.get(cn).unwrap().flavor == ClassFlavor::User {
                // We guessed correctly. Endpoint clause is missing.
                pa_state.device_clause = Some(Clause::new(
                    zpl::DEF_CLASS_ENDPOINT_NAME,
                    pa_state.root_tok.clone(),
                ));
                let uc = ps.to_clause("user")?;
                pa_state.user_clause = Some(uc);
                Ok(true)
            } else {
                Ok(false)
            }
        }
        Err(_) => {
            // Parse did not work but may be just because there is actually an endpoint clause present.
            Ok(false)
        }
    }
}

/// Assume there is only an endpoint clause (no user clause).
///
/// Attempt to parse the allow statement user and endpoint clauses while assuming
/// there is no user clause (so will be default).  If this succeeds, it sets the
/// user and endpoint clauses in the [ParseAllowState].
fn try_parse_allow_no_user_clause<'a, I>(
    pa_state: &mut ParseAllowState,
    tokens: &mut Peekable<I>,
    classes_idx: &HashMap<String, String>,
    classes_map: &HashMap<String, Class>,
) -> Result<bool, CompilationError>
where
    I: Iterator<Item = &'a Token>,
{
    let mut ps = PState::new(&pa_state.root_tok);

    match ps.parse_tags_attrs_and_classname(
        tokens,
        classes_idx,
        &ParseOpts::stop_at(TokenType::To),
        "possible endpoint clause",
    ) {
        Ok(_) => {
            // This is a good parse if we actually got an endpoint flavor class.
            let cn = ps.class_name.as_ref().unwrap();
            if classes_map.get(cn).unwrap().flavor == ClassFlavor::Endpoint {
                // We guessed correctly. User clause is missing.
                pa_state.user_clause = Some(Clause::new(
                    zpl::DEF_CLASS_USER_NAME,
                    pa_state.root_tok.clone(),
                ));
                let ec = ps.to_clause("device")?;
                pa_state.device_clause = Some(ec);
                Ok(true)
            } else {
                Ok(false)
            }
        }
        Err(_) => {
            // Parse failed, so we will need to try to parse all three clauses.
            Ok(false)
        }
    }
}

/// Will parse case when both an endpoint and user clause is specified in the
/// allow statement.
///
/// Is a little tricky since the endpoint clause may have its own WITH clause
/// otherwise/and the WITH clause is what separates the endpoint and user clauses so
/// when we get to the first WITH we don't know if this is a seperator or not.
///
/// Do to this complexity, unlike the other parse helper functions, this one takes
/// in the full allow statement and then returns the tokens remaining.
fn parse_allow_endpoint_and_user_clauses(
    pa_state: &mut ParseAllowState,
    allow_statement: &[Token],
    classes_idx: &HashMap<String, String>,
    classes_map: &HashMap<String, Class>,
) -> Result<Vec<Token>, CompilationError> {
    // Third and final try, try to parse endpoint and user clauses.

    // Parse an endpoint clause. This MAY be terminated by a WITH token, or it may use with
    // to add attributes and then have a WITH token later.
    //
    // We try the probably less common case first: the endpoint clause has its own WITH.

    let mut tokens = allow_statement[1..].iter().peekable();
    let mut ps = PState::new(&pa_state.root_tok);

    match ps.parse_tags_attrs_and_classname(
        &mut tokens,
        classes_idx,
        &ParseOpts::stop_at_after_times(TokenType::With, 2),
        "device clause",
    ) {
        Ok(_) => {
            // great!
        }
        Err(ref e) if matches!(e, CompilationError::MultipleClassNames(_, _, _)) => {
            // Pretty sure this is only error that indicates we attempted wrong parse.
            tokens = allow_statement[1..].iter().peekable();
            let mut ps = PState::new(&pa_state.root_tok);
            ps.parse_tags_attrs_and_classname(
                &mut tokens,
                classes_idx,
                &ParseOpts::stop_at(TokenType::With),
                "device clause",
            )?;
        }
        Err(e) => {
            return Err(e);
        }
    }

    // The class we just parsed needs to be a defined endpoint type.
    let cn = ps.class_name.as_ref().unwrap();
    if classes_map.get(cn).unwrap().flavor != ClassFlavor::Endpoint {
        return Err(CompilationError::ParseError(
            format!("not an endpoint class: '{}'", cn),
            pa_state.root_tok.line,
            pa_state.root_tok.col,
        ));
    }
    let ec = ps.to_clause("device")?;
    pa_state.device_clause = Some(ec);

    // Previous parse stopped at WITH.
    putil::require_tt(
        &pa_state.root_tok,
        tokens.next(),
        "WITH",
        "allow",
        TokenType::With,
    )?;

    ps = PState::new(&pa_state.root_tok);
    ps.parse_tags_attrs_and_classname(
        &mut tokens,
        classes_idx,
        &ParseOpts::stop_at(TokenType::To),
        "user clause",
    )?;

    let cn = ps.class_name.as_ref().unwrap();
    if classes_map.get(cn).unwrap().flavor != ClassFlavor::User {
        return Err(CompilationError::ParseError(
            format!("not a user class: '{}'", cn),
            pa_state.root_tok.line,
            pa_state.root_tok.col,
        ));
    }
    let uc = ps.to_clause("user")?;
    pa_state.user_clause = Some(uc);

    // Gather up (and copy) remaining tokens and return them.
    Ok(tokens.cloned().collect())
}

/// Parse the final bit of the allow statement which is the service clause.
/// The passed tokens MUST start with "TO ACCESS".
fn parse_allow_service_clause<'a, I>(
    pa_state: &mut ParseAllowState,
    tokens: &mut Peekable<I>,
    classes_idx: &HashMap<String, String>,
    classes_map: &HashMap<String, Class>,
) -> Result<(), CompilationError>
where
    I: Iterator<Item = &'a Token>,
{
    // Next token sequence better be TO ACCESS.
    // TODO: Maybe better to have single token TO_ACCESS ?
    putil::require_tt(
        &pa_state.root_tok,
        tokens.next(),
        "TO",
        "allow",
        TokenType::To,
    )?;
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
        return Err(CompilationError::ParseError(
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
    // stop parsing if we see (but do not consume) this token
    break_at: TokenType,

    // Stop after this many occurrances of break_at token. Note only last occurance is not consumed.
    break_at_count: usize,
}

impl ParseOpts {
    fn stop_at(break_at: TokenType) -> Self {
        Self {
            break_at,
            break_at_count: 1,
        }
    }
    fn stop_at_after_times(break_at: TokenType, break_at_count: usize) -> Self {
        Self {
            break_at,
            break_at_count,
        }
    }
}

impl Default for ParseOpts {
    fn default() -> Self {
        Self {
            break_at: TokenType::EOS,
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
            return Err(CompilationError::ParseError(
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
            if opts.break_at == tokref.tt {
                break_count += 1;
                if break_count >= opts.break_at_count {
                    break;
                }
                //tokens.next(); // else keep going
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
                        // We already have a class name.
                        if self.class_name.is_some() {
                            let tok = tokens.next().unwrap();
                            return Err(CompilationError::MultipleClassNames(
                                context.to_string(),
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
                    // We must have already parsed a class name.
                    //
                    // If we have already parsed a class name, then this WITH may be saying that
                    // we will now get some attributes for the class.  OR, in the case of an
                    // endpoint class, the WITH may signal the start of the USER class.
                    //
                    // If we are in an endpoint class, and this is the second WITH then we
                    // definately are at the terminal WITH.
                    //
                    //
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
                    return Err(CompilationError::SyntaxError(
                        format!("{} ({:?})", context, tok.tt),
                        tok.line,
                        tok.col,
                    ));
                }
            };
        }
        if tcount == 0 {
            return Err(CompilationError::ParseError(
                format!("{} is empty", context),
                self.root_tok.line,
                self.root_tok.col,
            ));
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
