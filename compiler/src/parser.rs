use std::iter::Peekable;


use crate::lex::{Token, TokenType};
use crate::compilation::CompilationError;


#[derive(Default)]
pub struct Policy {
    pub defines: Vec<Class>,
    pub allows: Vec<AllowClause>,
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

pub enum ClassFlavor {
    Endpoint,
    User,
    Service,
}

pub struct Class {
    pub flavor: ClassFlavor,
    pub parent: Option<String>,
    pub name: String,
    pub aka: String,
}

pub struct Attribute {
    pub name: String,
    pub value: Option<String>,
    pub multi_valued: bool,
    pub tag: bool,
}



// So the production rule for ALLOW takes the list of vectors that starts with an allow KW
// and consumes some of them.

pub fn parse(tokens: Vec<Token>) -> Result<Policy, CompilationError> {
    let mut tokens = tokens.into_iter().peekable();
    let mut policy = Policy::default();

    let mut allow_statements = Vec::new(); // we will gather the allows here and parse after the defines.

    while let Some(next_tok) = tokens.peek() {
        match next_tok.tt {
            TokenType::Define => {
                let define = parse_define(&mut tokens)?;
                policy.defines.push(define);
            }
            TokenType::Allow =>{
                allow_statements.push(next_tok);
                tokens.next();
            }
            _ => {
                return Err(CompilationError::UnexpectedKeyword(String::from("expected allow or define"),
                    next_tok.line, next_tok.col));
            }
        }
    }

    // TODO: create a lookup table for the defines to pass into the allow parser.

    /*
    while let Some(next_tok) = tokens.peek() {
        match next_tok.tt {
            TokenType::Allow => {
                let allow = parse_allow(&mut tokens)?;
                policy.allows.push(allow);
            }
            _ => {
                return Err(CompilationError::UnexpectedToken(next_tok.line, next_tok.col));
            }
        }
    }
    */


    return Ok(policy);
}

/*
fn parse_allow(tokens: &mut std::iter::Peekable<std::vec::IntoIter<Token>>) -> Result<AllowClause, CompilationError> {
    return Ok(allow);
}
    */


fn parse_allow<T: Iterator<Item = Token>>(tokens: &mut Peekable<T>) -> Result<AllowClause, CompilationError> {

    // parse endpoint bits
    // parse user bits
    // parse service bits

    // we need access to the defines in order to differentiate between class names and attribute names.

    Err(CompilationError::Io(std::io::Error::new(std::io::ErrorKind::Other, "not implemented")))
}

fn parse_define<T: Iterator<Item = Token>>(tokens: &mut Peekable<T>) -> Result<Class, CompilationError> {
    Err(CompilationError::Io(std::io::Error::new(std::io::ErrorKind::Other, "not implemented")))
}