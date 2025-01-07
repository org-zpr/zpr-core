//! allow.rs - parser for allow statements

use std::collections::HashMap;
use std::iter::Peekable;

use crate::errors::CompilationError;
use crate::lex::{Token, TokenType};
use crate::ptypes::{AllowClause, Attribute, Clause, Class, ClassFlavor};
use crate::putil;

// First token is an ALLOW which is checked by caller.
pub fn parse_allow(
    allow_statement: &[Token],
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

    // The full syntax with three clauses looks like this:
    //
    //   allow <endpoint-clause> WITH <user-clause> TO ACCESS <service-clause>
    //
    // But it is possible to omit with the endpoint or user clause which we interpret as
    // all endpoints or all users.
    //
    // First we assume endpoint clause is omitted, and just try to parse a user clause
    // up to a TO ACCESS.
    //
    // This fails if first clause type is not USER.  When that happens we assume that
    // user clause is omitted so try to parse an endpoint clause up to a TO ACCESS.
    //
    // This fails if we find a WITH followed by a USER clause.  In that case we parse
    // all three clauses.
    //

    let mut endpoint_clause: Option<Clause> = None;
    let mut user_clause: Option<Clause> = None;



    // Assume there is no endpoint clause and attempt to parse a user clause that terminates with TO ACCESS.

    let mut tokens = allow_statement[1..].iter().peekable();
    let mut ps = PState::new(root_tok);

    match ps.parse_tags_attrs_and_classname(
        &mut tokens,
        classes_idx,
        &ParseOpts::stop_at(TokenType::To),
        "possible user clause",
    ) {
        Ok(_) => {
            // This is a good parse if we actually got a user flavor class.
            let cn = ps.class_name.as_ref().unwrap();
            if classes_map.get(cn).unwrap().flavor == ClassFlavor::User {
                // We guessed correctly. Endpoint clause is missing.
                endpoint_clause = Some(Clause {
                    class: "endpoint".to_string(),
                    class_tok: Some(root_tok.clone()),
                    with: Vec::new(),
                });
                let uc = ps.to_clause("user")?;
                user_clause = Some(uc);
            }
        }
        Err(_) => {
            // Parse did not work but may be just because there is actually an endpoint clause present.
        }
    }


    if user_clause.is_none() {
        // Second try - Assume there is no user clause and attempt to parse an endpoint clause up to TO ACCESS.

        tokens = allow_statement[1..].iter().peekable();
        let mut ps = PState::new(root_tok);

        match ps.parse_tags_attrs_and_classname(
            &mut tokens,
            classes_idx,
            &ParseOpts::stop_at(TokenType::To),
            "possible endpoint clause",
        ) {
            Ok(_) => {
                // This is a good parse if we actually got an endpoint flavor class.
                let cn = ps.class_name.as_ref().unwrap();
                if classes_map.get(cn).unwrap().flavor == ClassFlavor::Endpoint {
                    // We guessed correctly. User clause is missing.
                    user_clause = Some(Clause {
                        class: "user".to_string(),
                        class_tok: Some(root_tok.clone()),
                        with: Vec::new(),
                    });
                    let ec = ps.to_clause("endpoint")?;
                    endpoint_clause = Some(ec);
                }
            }
            Err(_) => {
                // Parse failed, so we will need to try to parse all three clauses.
            }
        }
    }

    if user_clause.is_none() {
        // Third and final try, try to parse endpoint and user clauses.

        // Parse an endpoint clause. This MAY be terminated by a WITH token, or it may use with
        // to add attributes and then have a WITH token later.
        //
        // We try the probably less common case first: the endpoint clause has its own WITH.
        tokens = allow_statement[1..].iter().peekable();
        let mut ps = PState::new(root_tok);

        match ps.parse_tags_attrs_and_classname(
            &mut tokens,
            classes_idx,
            &ParseOpts::stop_at_after_times(TokenType::With, 2),
            "endpoint clause",
        ) {
            Ok(_) => {
                // great!
            }
            Err(ref e) if matches!(e, CompilationError::MultipleClassNames(_, _, _)) => {
                // Pretty sure this is only error that indicates we attempted wrong parse.
                tokens = allow_statement[1..].iter().peekable();
                let mut ps = PState::new(root_tok);
                ps.parse_tags_attrs_and_classname(
                    &mut tokens,
                    classes_idx,
                    &ParseOpts::stop_at(TokenType::With),
                    "endpoint clause",
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
                format!("not an endpoint class: '{}'", cn), root_tok.line, root_tok.col));
        }
        let ec = ps.to_clause("endpoint")?;
        endpoint_clause = Some(ec);


        // Previous parse stopped at WITH.
        putil::require_tt(root_tok, tokens.next(), "WITH", "allow", TokenType::With)?;

        ps = PState::new(root_tok);
        ps.parse_tags_attrs_and_classname(&mut tokens, classes_idx, &ParseOpts::stop_at(TokenType::To), "user clause")?;

        let cn = ps.class_name.as_ref().unwrap();
        if classes_map.get(cn).unwrap().flavor != ClassFlavor::User {
            return Err(CompilationError::ParseError(
                format!("not a user class: '{}'", cn), root_tok.line, root_tok.col));
        }
        let uc = ps.to_clause("user")?;
        user_clause = Some(uc);
    }

    // At this point we have a valid endpoint and user clause.  Just need to parse the final service clause.
    if endpoint_clause.is_none() {
        panic!("program error - no endpoint clause");
    }
    if user_clause.is_none() {
        panic!("program error - no user clause");
    }


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

    println!("XXX == parse_allow - got endpoint & service cluases, and got TO ALLOW...");

    // Need a service clause now -- parse to end of statement.
    ps = PState::new(root_tok);
    ps.parse_tags_attrs_and_classname(&mut tokens, classes_idx, &ParseOpts::default(), "service clause")?;

    let cn = ps.class_name.as_ref().unwrap();
    if classes_map.get(cn).unwrap().flavor != ClassFlavor::Service {
        return Err(CompilationError::ParseError(
            format!("not a service class: '{}'", cn), root_tok.line, root_tok.col));
    }
    let service_clause = ps.to_clause("service")?;

    Ok(AllowClause {
        endpoint: endpoint_clause.unwrap(),
        user: user_clause.unwrap(),
        service: service_clause,
    })
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
            class_tok: self.class_name_token.clone(),
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
                    return Err(CompilationError::ParseError(
                        format!("syntax error in {} ({:?})", context, tok.tt),
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
