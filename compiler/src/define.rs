//! define.rs - parser for define statements

use std::collections::HashMap;
use std::iter::Peekable;

use crate::errors::CompilationError;
use crate::lex::{Token, TokenType};
use crate::ptypes::{Attribute, Class, ClassFlavor};
use crate::putil;
use crate::zpl;

// First token exists and is a DEFINE which is checked by the caller.
pub fn parse_define(define_statement: &[Token]) -> Result<Class, CompilationError> {
    if define_statement.is_empty() {
        panic!("parse_define called with empty statement");
    }
    if define_statement[0].tt != TokenType::Define {
        panic!("parse_define called with non-DEFINE statement");
    }

    let mut tokens = define_statement.iter().peekable();
    let _define = tokens.next().unwrap();

    let root_tok = &define_statement[0];

    // define class_name
    //        ^^^^^^^^^^
    let class_name = putil::return_literal(root_tok, tokens.next(), "class name", "define")?;

    // define class_name AKA plural
    //                   ^^^ ^^^^^^
    let aka_name: String;

    if let Some(next_tok) = tokens.peek() {
        match next_tok.tt {
            TokenType::AkA => {
                let aka = tokens.next().unwrap(); // consume the AKA
                aka_name = putil::return_literal(aka, tokens.next(), "aka name", "aka")?;
            }
            _ => {
                // No AKA, so aka_name is just plural.
                aka_name = putil::pluralize(&class_name);
            }
        }
    } else {
        aka_name = putil::pluralize(&class_name);
    }

    // define class_name [ aka foo ] as a parent-class-name with
    //                               ^^
    // 'a' will have been discarded by the lex step.
    putil::require_tt(root_tok, tokens.next(), "AS", "define", TokenType::As)?;

    // define class_name [ aka foo ] as a parent-class-name with
    //                                    ^^^^^^^^^^^^^^^^^
    //
    // baked in classes are: user, service, device (was called endpoint) (and their plurals)
    let mut parent_class_name =
        putil::return_literal(root_tok, tokens.next(), "parent class name", "as")?;

    // The flavor of the parent class really cannot be figured out until all
    // the classes are defined. To give meaning full error may need to track
    // the define token or something.
    let flavor = match parent_class_name.as_str() {
        zpl::DEF_CLASS_USER_NAME | zpl::DEF_CLASS_USER_AKA => {
            parent_class_name = String::from(zpl::DEF_CLASS_USER_NAME);
            ClassFlavor::User
        }
        zpl::DEF_CLASS_SERVICE_NAME | zpl::DEF_CLASS_SERVICE_AKA => {
            parent_class_name = String::from(zpl::DEF_CLASS_SERVICE_NAME);
            ClassFlavor::Service
        }
        zpl::DEF_CLASS_DEVICE_NAME | zpl::DEF_CLASS_DEVICE_AKA => {
            parent_class_name = String::from(zpl::DEF_CLASS_DEVICE_NAME);
            ClassFlavor::Device
        }
        _ => ClassFlavor::Undefined,
    };

    // The "with" clause is optional.
    let mut class = Class {
        flavor,
        parent: parent_class_name.clone(),
        name: class_name.clone(),
        aka: aka_name.clone(),
        pos: root_tok.into(),
        with_attrs: Vec::new(),
    };

    match tokens.peek() {
        Some(tok) => {
            if tok.tt == TokenType::With {
                // consume the WITH token
                tokens.next();
                parse_attributes(&mut class, &mut tokens)?;
            } else {
                return Err(CompilationError::DefineStmtParseError(
                    "expected WITH clause".to_string(),
                    tok.line,
                    tok.col,
                ));
            }
        }
        None => {
            // No WITH clause, so we are done.
        }
    }
    Ok(class)
}

// Parse attributes (tail end of the define). Each token is some attribute for the class.
// If we get a TAGS token, then everything after that is a tag until we hit an AND WITH.
// The MULTIPLE keyword just applies to the next attribute (cannot be a tag).
//
// This consumes all the remaining tokens (or errors out) and updates `class` in place.
fn parse_attributes<'a, I>(
    class: &mut Class,
    tokens: &mut Peekable<I>,
) -> Result<(), CompilationError>
where
    I: Iterator<Item = &'a Token>,
{
    let mut multiple = false;
    let mut tags = false;
    let mut tag = false;
    let mut optional: bool = false;
    let mut and = false;

    for tok in tokens {
        match &tok.tt {
            TokenType::Tags => {
                if tags {
                    return Err(CompilationError::DefineStmtParseError(
                        "multiple TAGS statements".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                if tag {
                    return Err(CompilationError::DefineStmtParseError(
                        "TAGS following TAG".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                tags = true;
            }
            TokenType::Tag => {
                // tag is the non-greedy version of tags. Next token is the tag name.
                if tags {
                    return Err(CompilationError::DefineStmtParseError(
                        "TAG following TAGS".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                tag = true;
            }
            TokenType::Optional => {
                if tags || tag {
                    return Err(CompilationError::DefineStmtParseError(
                        "OPTIONAL not allowed after tag/tags".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                if optional {
                    return Err(CompilationError::DefineStmtParseError(
                        "multiple OPTIONAL statements".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                optional = true;
            }
            TokenType::Multiple => {
                if tags || tag {
                    return Err(CompilationError::DefineStmtParseError(
                        "MULTIPLE not allowed after tag/tags".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                if multiple {
                    return Err(CompilationError::DefineStmtParseError(
                        "multiple MULTIPLE statements".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                multiple = true;
            }
            TokenType::And => {
                if and {
                    return Err(CompilationError::DefineStmtParseError(
                        "multiple AND statements".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                if tag {
                    return Err(CompilationError::DefineStmtParseError(
                        "TAG requires a tag name, not AND".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                and = true;
            }
            TokenType::With => {
                // Only valid after an and.
                if !and {
                    return Err(CompilationError::DefineStmtParseError(
                        "WITH must follow AND".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                // Got AND WITH so that turns off modifier flags.
                tags = false;
                tag = false;
                optional = false;
                multiple = false;
                and = false;
            }
            TokenType::Comma => {}
            TokenType::Tuple((name, value)) => {
                if tags || tag {
                    return Err(CompilationError::DefineStmtParseError(
                        "attributes not allowed in tag/tags".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                let attr = Attribute {
                    name: name.clone(),
                    value: Some(value.clone()),
                    multi_valued: multiple,
                    tag: false,
                    optional,
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
                    tag: tags || tag,
                    optional,
                };
                class.with_attrs.push(attr);
                multiple = false;
                and = false;
                tag = false; // not greedy
            }
            _ => {
                return Err(CompilationError::DefineStmtParseError(
                    format!("syntax error ({:?})", tok.tt),
                    tok.line,
                    tok.col,
                ));
            }
        }
    }
    Ok(())
}

// Fill in any classes with undefined flavor by walking backwards to their parent classes.
pub fn resolve_class_flavors(classes: &mut HashMap<String, Class>) -> Result<(), CompilationError> {
    let mut undef_count = 0;
    for class in (*classes).values() {
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
                    return Err(CompilationError::DefineStmtParseError(
                        format!(
                            "parent class {} of {} does not exist",
                            parentless_ref.parent, name
                        ),
                        parentless_ref.pos.line,
                        parentless_ref.pos.col,
                    ));
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
            return Err(CompilationError::DefineStmtParseError(
                format!("could not resolve classes: {:?}", undefined),
                0,
                0,
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::{context::CompilationCtx, lex::tokenize_str};

    #[test]
    fn test_required_tag() {
        let statement = "define marketing-emp as a user with tag full-time";
        let tz = tokenize_str(statement, &CompilationCtx::default()).unwrap();
        let tokens = tz.tokens;
        let class = parse_define(&tokens).unwrap();
        assert_eq!(class.name, "marketing-emp");
    }

    // Test stuff that passes tokenizer but should fail parser.
    #[test]
    fn test_reject_nonesense() {
        let invalids = vec![
            "define marketing-emp as a user with tag multiple foo",
            "define marketing-emp as a user with tags multiple foo",
            "define marketing-emp as a user with tag and foo",
        ];
        let ctx = CompilationCtx::default();
        for statement in invalids {
            let tz = tokenize_str(statement, &ctx).unwrap();
            let tokens = tz.tokens;
            match parse_define(&tokens) {
                Ok(_) => panic!("should have failed on: '{}'", statement),
                Err(_) => {}
            }
        }
    }
}
