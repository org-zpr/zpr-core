use std::collections::HashMap;
use std::fmt;

use crate::lex::{Token, TokenType};
use crate::compilation::CompilationError;


#[derive(Default)]
pub struct Policy {
    pub defines: Vec<Class>,
    pub allows: Vec<AllowClause>,
}

#[derive(Debug, Clone)]
pub struct FPos {
    pub line: usize,
    pub col: usize,
}

impl From<Token> for FPos {
    fn from(tok: Token) -> Self {
        FPos {
            line: tok.line,
            col: tok.col,
        }
    }
}

impl From<&Token> for FPos {
    fn from(tok: &Token) -> Self {
        FPos {
            line: tok.line,
            col: tok.col,
        }
    }
}


pub struct AllowClause {
    pub endpoint: Clause,
    pub user: Clause,
    pub service: Clause,
}

pub struct Clause {
    pub class: String,
    pub with: Vec<Attribute>,
    pub without: Vec<Attribute>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClassFlavor {
    Undefined, // they all start here
    Endpoint,
    User,
    Service,
}


pub struct Class {
    pub flavor: ClassFlavor,
    pub parent: String,
    pub name: String,
    pub aka: String,
    pub pos: FPos, // location of the define token
    pub with_attrs: Vec<Attribute>,
    // TODO: withouts
}

pub struct Attribute {
    pub name: String,
    pub value: Option<String>,
    pub multi_valued: bool,
    pub tag: bool,
    pub optional: bool,
}

impl fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(v) = &self.value {
            write!(f, "{}:{}", self.name, v)
        } else {
            write!(f, "{}", self.name)
        }
    }
}


pub fn parse(tokens: Vec<Token>) -> Result<Policy, CompilationError> {
    // Convert the tokens into statements, which are just sub-lists of the tokens.
    // Currently the compiler only accepts ALLOW statements and DEFINE statements.
    let mut statements = Vec::new();
    let mut current_statement = Vec::new();

    for tok in tokens {
        match tok.tt {
            TokenType::Allow | TokenType::Define => {
                if current_statement.len() > 0 {
                    statements.push(current_statement);
                    current_statement = Vec::new();
                }
                current_statement.push(tok);
            }
            _ => {
                current_statement.push(tok);
            }
        }
    }
    if current_statement.len() > 0 {
        statements.push(current_statement);
    }

    let mut policy = Policy::default();

    let mut classes: HashMap<String, Class> = HashMap::new();

    // Define statements create classes.
    for statement in &mut statements {
        if statement[0].tt == TokenType::Define {
            let class = parse_define(&statement)?;

            // It is an error to redefine a class.
            if classes.contains_key(&class.name) {
                return Err(CompilationError::Redefinition(class.name, statement[0].line, statement[0].col));
            }
            classes.insert(class.name.clone(), class);
        }
    }

    // Take a pass over the defines to resolve all the child/parent relationships and
    // compute the correct flavors.
    resolve_class_flavors(&mut classes)?;


    // Next parse all the allows.
    for statement in &mut statements {
        if statement[0].tt == TokenType::Allow {
            let allow = parse_allow(&statement, &classes)?;
            policy.allows.push(allow);
        }
    }


    // move all the classes in the policy
    for (_, class) in classes.into_iter() {
        println!("defined class: {} (is a {:?})", class.name, class.flavor);
        for attr in &class.with_attrs {
            println!("  with: {}", attr);
        }
        policy.defines.push(class);
    }


    Ok(policy)
}


// First token exists and is a DEFINE which is checked by the caller.
fn parse_define(define_statement: &[Token]) -> Result<Class, CompilationError> {
    if define_statement.len() < 1 {
        panic!("parse_define called with empty statement");
    }
    if define_statement[0].tt != TokenType::Define {
        panic!("parse_define called with non-DEFINE statement");
    }

    let mut tokens = define_statement.into_iter().peekable();
    let _define = tokens.next().unwrap();

    let root_tok = &define_statement[0];


    // define class_name
    //        ^^^^^^^^^^
    let class_name = return_literal(root_tok, tokens.next(), "class name", "define")?;

    // define class_name AKA plural
    //                   ^^^ ^^^^^^
    let aka_name: String;

    if let Some(next_tok) = tokens.peek() {
        match next_tok.tt {
            TokenType::AkA => {
                let aka = tokens.next().unwrap(); // consume the AKA
                aka_name = return_literal(aka, tokens.next(), "aka name", "aka")?;
            }
            _ => {
                // No AKA, so aka_name is just plural.
                aka_name = pluralize(&class_name);
            }
        }
    } else {
        aka_name = pluralize(&class_name);
    }

    // define class_name [ aka foo ] as a parent-class-name with
    //                               ^^
    // 'a' will have been discarded by the lex step.
    require_tt(root_tok, tokens.next(), "AS", "define", TokenType::As)?;

    // define class_name [ aka foo ] as a parent-class-name with
    //                                    ^^^^^^^^^^^^^^^^^
    //
    // baked in classes are: user, service, endpoint (and their plurals)
    let mut parent_class_name = return_literal(root_tok, tokens.next(), "parent class name", "as")?;

    // The flavor of the parent class really cannot be figured out until all
    // the classes are defined. To give meaning full error may need to track
    // the define token or something.
    let flavor = match parent_class_name.as_str() {
        "user" | "users " => {
            parent_class_name = String::from("user");
            ClassFlavor::User
        },
        "service" | "services"  => {
            parent_class_name = String::from("service");
            ClassFlavor::Service
        }
        "endpoint" | "endpoints" => {
            parent_class_name = String::from("endpoint");
            ClassFlavor::Endpoint
        }
        _ => ClassFlavor::Undefined,
    };

    // define class_name [ aka foo ] as a parent-class-name with
    //                                                      ^^^^
    require_tt(root_tok, tokens.next(), "WITH", "define", TokenType::With)?;

    // At this point we need to parse attributes. Each token is some attribute for the class.
    // If we get a TAGS token, then everything after that is a tag until we hit an AND WITH.
    // The MULTIPLE keyword just applies to the next attribute (cannot be a tag).


    let mut class = Class {
        flavor: flavor,
        parent: parent_class_name.clone(),
        name: class_name.clone(),
        aka: aka_name.clone(),
        pos: root_tok.into(),
        with_attrs: Vec::new(),
    };


    let mut multiple = false;
    let mut tags = false;
    let mut optional: bool = false;
    let mut and = false;

    for tok in tokens {
        match &tok.tt {
            TokenType::Tags => {
                if tags {
                    return Err(CompilationError::ParseError("multiple TAGS statements".to_string(), tok.line, tok.col));
                }
                tags = true;
            }
            TokenType::Optional => {
                if optional {
                    return Err(CompilationError::ParseError("multiple OPTIONAL statements".to_string(), tok.line, tok.col));
                }
                optional = true;
            }
            TokenType::Multiple => {
                if multiple {
                    return Err(CompilationError::ParseError("multiple MULTIPLE statements".to_string(), tok.line, tok.col));
                }
                multiple = true;
            }
            TokenType::And => {
                if and {
                    return Err(CompilationError::ParseError("multiple AND statements".to_string(), tok.line, tok.col));
                }
                and = true;
            }
            TokenType::With => {
                // Only valid after an and.
                if !and {
                    return Err(CompilationError::ParseError("WITH must follow AND".to_string(), tok.line, tok.col));
                }
                // Got AND WITH so that turns off modifier flags.
                tags = false;
                optional = false;
                multiple = false;
                and = false;
            }
            TokenType::Comma => { }
            TokenType::Tuple((name, value)) => {
                if tags {
                    return Err(CompilationError::ParseError("attributes not allowed in tags".to_string(), tok.line, tok.col));
                }
                let attr = Attribute {
                    name: name.clone(),
                    value: Some(value.clone()),
                    multi_valued: multiple,
                    tag: false,
                    optional: optional,
                };
                class.with_attrs.push(attr);
                multiple = false;
                and = false;
            }
            TokenType::Literal(s) => {
                let attr = Attribute {
                    name: s.clone(),
                    value: None,
                    multi_valued: multiple,
                    tag: tags,
                    optional: optional,
                };
                class.with_attrs.push(attr);
                multiple = false;
                and = false;
            }
            _ => {
                return Err(CompilationError::ParseError(format!("syntax error ({:?})", tok.tt), tok.line, tok.col));
            }
        }
    }
    Ok(class)

}


fn parse_allow(_allow_statement: &[Token], _classes: &HashMap<String, Class>) -> Result<AllowClause, CompilationError> {
    // parse endpoint bits
    // parse user bits
    // parse service bits

    // we need access to the defines in order to differentiate between class names and attribute names.

    Err(CompilationError::Io(std::io::Error::new(std::io::ErrorKind::Other, "not implemented")))
}

// Given the next token in the list, we error out if that token is not of the expected type.
fn require_tt(parent_tok: &Token, next_tok: Option<&Token>, expect: &str, statement_type: &str, expect_tt: TokenType) -> Result<(), CompilationError> {
    match next_tok {
        Some(tok) => {
            if tok.tt == expect_tt {
                Ok(())
            } else {
                Err(CompilationError::ParseError(format!("expected {}", expect), tok.line, tok.col))
            }
        }
        None => {
            Err(CompilationError::ParseError(format!("malformed {} (expected {})", statement_type, expect),
                parent_tok.line, parent_tok.col))
        }
    }
}

// Expect the next token in the list to be a literal, and if so we return a copy of the value.
fn return_literal(parent_tok: &Token, next_tok: Option<&Token>, expect_desc: &str, statement_type: &str) -> Result<String, CompilationError> {
    let value = match next_tok {
        Some(tok) => {
            match &tok.tt {
                TokenType::Literal(s) => s,
                _ => {
                    return Err(CompilationError::ParseError(format!("expected {} to follow {}", expect_desc, statement_type),
                        tok.line, tok.col));
                }
            }
        }
        None => {
            return Err(CompilationError::ParseError(format!("malformed {}", statement_type), parent_tok.line, parent_tok.col));
        }
    };
    Ok(value.clone())
}


// Could be more sophisticated.
fn pluralize(s: &str) -> String {
    return format!("{}s", s);
}


// Fill in any classes with undefined flavor by walking backwards to their parent classes.
fn resolve_class_flavors(classes: &mut HashMap<String, Class>) -> Result<(), CompilationError> {
    let mut undef_count = 0;
    for (_name, class) in &mut *classes {
        if class.flavor == ClassFlavor::Undefined {
            undef_count += 1;
        }
    }
    while undef_count > 0 {
        let prev_undef_count = undef_count;
        let mut needs_parent = Vec::new();
        for (name, class) in classes.iter_mut() {
            if class.flavor == ClassFlavor::Undefined {
                needs_parent.push(name.clone());
            }
        }
        for name in needs_parent {
            let parentless_ref = classes.get(&name).unwrap();
            let parent_flavor = match classes.get(parentless_ref.parent.as_str()) {
                Some(parent) => parent.flavor.clone(),
                None => {
                    // This is an error, the parent class does not exist.
                    return Err(CompilationError::ParseError(format!("parent class {} of {} does not exist", parentless_ref.parent, name),
                        parentless_ref.pos.line, parentless_ref.pos.col));
                }
            };
            if parent_flavor != ClassFlavor::Undefined {
                let parentless = classes.get_mut(&name).unwrap();
                parentless.flavor = parent_flavor;
                undef_count -= 1;
            }
        }
        if undef_count > 0 && prev_undef_count == undef_count {
            // We did not make any progress, so we have an impass.
            let mut undefined = Vec::new();
            for (name, class) in classes.iter_mut() {
                if class.flavor == ClassFlavor::Undefined {
                    undefined.push(name.clone());
                }
            }
            return Err(CompilationError::ParseError(format!("could not resolve classes: {:?}", undefined), 0, 0));
        }
    }
    Ok(())
}