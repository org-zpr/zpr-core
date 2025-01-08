//! ptypes - Parser types

use crate::lex::Token;
use std::fmt;

/// The datastructure version of the ZPL policy after parsing.
/// Just a bunch of defines and allows.
#[derive(Default)]
pub struct Policy {
    pub defines: Vec<Class>,
    pub allows: Vec<AllowClause>,
}

/// FPos is a "file position" to better report errors in the ZPL parsing.
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

/// A parsed "allow" statement.
#[derive(Clone, Debug)]
pub struct AllowClause {
    pub endpoint: Clause,
    pub user: Clause,
    pub service: Clause,
}

impl fmt::Display for AllowClause {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ALLOW {}\n   WITH {}\n      TO ACCESS {}",
            self.endpoint, self.user, self.service
        )
    }
}

/// A parsed "clause" which appears in allow statements. For example, a user-clause describes
/// the user component of the allow.  The other two are endpoint-clause and service-clause.
/// Each clause may have a set of attributes on it.
#[derive(Default, Clone, Debug)]
pub struct Clause {
    pub class: String,
    pub class_tok: Token,
    pub with: Vec<Attribute>,
    // TODO: pub without: Vec<Attribute>,
}

impl Clause {
    pub fn new(class: &str, class_tok: Token) -> Self {
        Clause {
            class: class.to_string(),
            class_tok,
            with: vec![],
        }
    }
    #[allow(dead_code)]
    pub fn add_attr(&mut self, attr: Attribute) {
        self.with.push(attr);
    }
}

impl fmt::Display for Clause {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} with [", self.class)?;
        for attr in &self.with {
            write!(f, " {},", attr)?;
        }
        write!(f, "]")
    }
}

/// A defined class in ZPL has a type which we call "flavor".
#[derive(Debug, Clone, PartialEq)]
pub enum ClassFlavor {
    Undefined, // they all start here
    Endpoint,
    User,
    Service,
}

/// A class is created from a ZPL define statement.
/// There are also three built in classes: user, service, and endpoint.
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
    /// Returns the built in classes.
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

/// A ZPL attribute. Could be a tule type attibute, eg "role:marketing" or a
/// tag type.  An attribute may be optional or required, and may be multi-valued
/// or single-valued.
#[derive(Debug, Clone)]
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
            write!(f, "{}:{}", self.name, v)?
        } else if self.tag {
            write!(f, "#{}", self.name)?
        } else {
            write!(f, "{}", self.name)?
        }
        if self.multi_valued {
            write!(f, "+")?
        }
        if self.optional {
            return write!(f, "?");
        }
        Ok(())
    }
}

impl Attribute {
    /// Easy way top create a TAG type attribute.
    pub fn tag(name: &str) -> Self {
        Attribute {
            name: name.to_string(),
            value: None,
            multi_valued: false,
            tag: true,
            optional: false,
        }
    }
    /// Easy way to create a tuple type attribute.
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
