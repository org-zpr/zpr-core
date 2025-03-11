//! ptypes - Parser types
use ring::digest::Digest;
use std::collections::HashMap;
use std::fmt;

use crate::lex::Token;
use crate::zpl;

/// The datastructure version of the ZPL policy after parsing.
/// Just a bunch of defines and allows.
#[derive(Default)]
pub struct Policy {
    pub digest: Option<Digest>,
    pub defines: Vec<Class>,
    pub allows: Vec<AllowClause>,
}

/// FPos is a "file position" to better report errors in the ZPL parsing.
#[derive(Debug, Clone, Default)]
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
    pub id: usize, // Within a given zpl policy, each allow clause gets a unique id.
    pub device: Clause,
    pub user: Clause,
    pub service: Clause,
}

impl fmt::Display for AllowClause {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[{}] ALLOW {}\n   WITH {}\n      TO ACCESS {}",
            self.id, self.device, self.user, self.service
        )
    }
}

/// A parsed "clause" which appears in allow statements. For example, a user-clause describes
/// the user component of the allow.  The other two are device-clause and service-clause.
/// Each clause may have a set of attributes on it.
#[derive(Default, Clone, Debug)]
#[allow(dead_code)]
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

    /// Given a clause (and classes map) return the number of "with" attributes that are
    /// required by the clause class (and parent classes if any).
    pub fn with_attr_count(&self, classes_map: &HashMap<String, Class>) -> usize {
        let mut cur_class = &self.class;
        let mut with_count = self.with.len();

        loop {
            let clz = classes_map.get(cur_class).expect("class not found"); // at this point only valid classes are present
            with_count += clz.with_attrs.len();
            if clz.is_builtin() || cur_class == &clz.parent {
                break;
            }
            cur_class = &clz.parent;
        }
        with_count
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
    Device,
    User,
    Service,
}

/// A class is created from a ZPL define statement.
/// There are also three built in classes: user, service, and endpoint.
#[derive(Debug)]
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
            Class::default_device(),
        ]
    }
    pub fn default_user() -> Class {
        Class {
            flavor: ClassFlavor::User,
            parent: zpl::DEF_CLASS_USER_NAME.to_string(),
            name: zpl::DEF_CLASS_USER_NAME.to_string(),
            aka: zpl::DEF_CLASS_USER_AKA.to_string(),
            pos: FPos { line: 0, col: 0 },
            with_attrs: vec![],
        }
    }
    pub fn default_service() -> Class {
        Class {
            flavor: ClassFlavor::Service,
            parent: zpl::DEF_CLASS_SERVICE_NAME.to_string(),
            name: zpl::DEF_CLASS_SERVICE_NAME.to_string(),
            aka: zpl::DEF_CLASS_SERVICE_AKA.to_string(),
            pos: FPos { line: 0, col: 0 },
            with_attrs: vec![],
        }
    }
    pub fn default_device() -> Class {
        Class {
            flavor: ClassFlavor::Device,
            parent: zpl::DEF_CLASS_DEVICE_NAME.to_string(),
            name: zpl::DEF_CLASS_DEVICE_NAME.to_string(),
            aka: zpl::DEF_CLASS_DEVICE_AKA.to_string(),
            pos: FPos { line: 0, col: 0 },
            with_attrs: vec![],
        }
    }
    pub fn is_builtin(&self) -> bool {
        self.name == zpl::DEF_CLASS_USER_NAME
            || self.name == zpl::DEF_CLASS_SERVICE_NAME
            || self.name == zpl::DEF_CLASS_DEVICE_NAME
    }
}

/// A ZPL attribute. Could be a tule type attibute, eg "role:marketing" or a
/// tag type.  An attribute may be optional or required, and may be multi-valued
/// or single-valued.
#[derive(Debug, Clone, PartialEq)]
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

    /// Create required, tuple type attribute without specifying a value.
    pub fn attr_name_only(name: &str) -> Self {
        Attribute {
            name: name.to_string(),
            value: None,
            multi_valued: false,
            tag: false,
            optional: false,
        }
    }

    /// Create and return a new attribute with the same characteristics of this one but with the new name provided.
    pub fn set_name(&self, new_name: &str) -> Self {
        let mut new_a = self.clone();
        new_a.name = new_name.to_string();
        new_a
    }

    /// The the ZPL name for the key of this attribute. The key is just the attribute name
    /// unless this is a tag, in which case the key is "zpr.tag".
    pub fn zpl_key(&self) -> String {
        if self.tag {
            "zpr.tag".to_string()
        } else {
            self.name.clone()
        }
    }

    /// The ZPL value for this attribute. If there is no value an empty string is returned.
    pub fn zpl_value(&self) -> String {
        if self.tag {
            self.name.clone()
        } else if let Some(v) = &self.value {
            v.clone()
        } else {
            "".to_string()
        }
    }
}
