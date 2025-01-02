//! ptypes - Parser types

use std::fmt;
use crate::lex::Token;


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

#[derive(Default)]
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

impl Class {
    pub fn defaults() -> Vec<Class> {
        vec![
            Class::default_user(),
            Class::default_service(),
            Class::default_endpoint(),
        ]
    }
    pub fn default_user() -> Class {
        Class {
            flavor: ClassFlavor::User,
            parent: "user".to_string(),
            name: "user".to_string(),
            aka: "users".to_string(),
            pos: FPos { line: 0, col: 0 },
            with_attrs: vec![],
        }
    }
    pub fn default_service() -> Class {
        Class {
            flavor: ClassFlavor::Service,
            parent: "service".to_string(),
            name: "service".to_string(),
            aka: "services".to_string(),
            pos: FPos { line: 0, col: 0 },
            with_attrs: vec![],
        }
    }
    pub fn default_endpoint() -> Class {
        Class {
            flavor: ClassFlavor::Endpoint,
            parent: "endpoint".to_string(),
            name: "endpoint".to_string(),
            aka: "endpoints".to_string(),
            pos: FPos { line: 0, col: 0 },
            with_attrs: vec![],
        }
    }
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
        } else if self.tag {
            write!(f, "#{}", self.name)
        } else {
            write!(f, "{}", self.name)
        }
    }
}

impl Attribute {
    pub fn tag(name: &str) -> Self {
        Attribute {
            name: name.to_string(),
            value: None,
            multi_valued: false,
            tag: true,
            optional: false,
        }
    }
    pub fn attr(name: &str, value: &str) -> Self {
        Attribute {
            name: name.to_string(),
            value: Some(value.to_string()),
            multi_valued: false,
            tag: false,
            optional: false,
        }
    }
}