use std::collections::HashMap;

use crate::allow::parse_allow;
use crate::define::{parse_define, resolve_class_flavors};
use crate::errors::CompilationError;
use crate::lex::{Token, TokenType};
use crate::ptypes::{Class, Policy};

pub fn parse(tokens: Vec<Token>) -> Result<Policy, CompilationError> {
    // Convert the tokens into statements, which are just sub-lists of the tokens.
    // Currently the compiler only accepts ALLOW statements and DEFINE statements.
    let mut statements = Vec::new();
    let mut current_statement = Vec::new();

    for tok in tokens {
        match tok.tt {
            TokenType::Allow | TokenType::Define => {
                if !current_statement.is_empty() {
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
    if !current_statement.is_empty() {
        statements.push(current_statement);
    }

    let mut policy = Policy::default();

    let mut classes: HashMap<String, Class> = HashMap::new();

    // Add default classes:
    for defclass in Class::defaults() {
        classes.insert(defclass.name.clone(), defclass);
    }

    // Construct an index that adds entries for all the AKAs.
    let mut class_index: HashMap<String, String> = HashMap::new();
    for (name, class) in classes.iter() {
        class_index.insert(name.clone(), name.clone());
        class_index.insert(class.aka.clone(), name.clone());
    }

    // Define statements create classes.
    for statement in &statements {
        if statement[0].tt == TokenType::Define {
            let class = parse_define(statement)?;

            // It is an error to redefine a class.
            if classes.contains_key(&class.name) || class_index.contains_key(&class.name) {
                return Err(CompilationError::Redefinition(
                    class.name,
                    statement[0].line,
                    statement[0].col,
                ));
            }
            let cname = class.name.clone();
            class_index.insert(cname.clone(), cname.clone());
            class_index.insert(class.aka.clone(), cname.clone());
            classes.insert(cname, class);
        }
    }

    // Take a pass over the defines to resolve all the child/parent relationships and
    // compute the correct flavors.
    resolve_class_flavors(&mut classes)?;

    // Next parse all the allows.
    for statement in &statements {
        if statement[0].tt == TokenType::Allow {
            let allow = parse_allow(statement, &class_index, &classes)?;
            println!("{}", allow);
            policy.allows.push(allow);
        }
    }

    // move all the classes in the policy
    for (_, class) in classes.into_iter() {
        // Not sure i need the built in ones?
        if class.name == "user" || class.name == "service" || class.name == "endpoint" {
            continue;
        }
        println!("defined class: {} (is a {:?})", class.name, class.flavor);
        for attr in &class.with_attrs {
            println!("  with: {}", attr);
        }
        policy.defines.push(class);
    }

    Ok(policy)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::lex::tokenize_str;
    use crate::ptypes::ClassFlavor;

    #[test]
    fn test_parse_define() {
        let valids = vec![
            "define employee as a user with an id",
            "define employee as a user with an id \n define marketing-emp as an employee with rule:marketing and tag full-time",
            "define employee as a user with an ID-number, multiple roles and optional tags full-time, part-time, and intern",
            "define employee as a user with an `ID number`, multiple roles and optional tags full-time, part-time, and intern and with color:purple, size:`extra:large`",
            "define gateway as a service with an external-network-connection",
            "define gateway as a service with an external-network-connection \n define internet-gateway as a gateway with external-network-connection:public-internet",
            "define peripheral as a user with function \n define mouse AKA mice as a peripheral with function:pointing"
        ];
        for valid in valids {
            let tokens: Result<Vec<Token>, CompilationError> = tokenize_str(valid).or_else(|e| {
                panic!("failed to tokenize '{}': {:?}", valid, e);
            });
            let _pol = match parse(tokens.unwrap()) {
                Ok(policy) => policy,
                Err(e) => {
                    panic!("failed to parse '{}': {:?}", valid, e);
                }
            };
        }
    }

    #[test]
    fn test_short_policy() {
        let pp = r#"
define employee as a user with an ID-number, multiple roles and
optional tags full-time, part-time, and intern

define marketing-emp as an employee with rule:marketing and tag full-time

allow endpoints with marketing-emp to access services with role:marketing
"#;
        let tokens: Result<Vec<Token>, CompilationError> = tokenize_str(pp).or_else(|e| {
            panic!("failed to tokenize '{}': {:?}", pp, e);
        });
        let pol = match parse(tokens.unwrap()) {
            Ok(policy) => policy,
            Err(e) => {
                panic!("failed to parse '{}': {:?}", pp, e);
            }
        };
        assert_eq!(pol.defines.len(), 2);
        assert_eq!(pol.allows.len(), 1);

        let emp = match pol.defines[0].name.as_str() {
            "employee" => &pol.defines[0],
            "marketing-emp" => &pol.defines[1],
            _ => panic!("unexpected class name: {}", pol.defines[0].name),
        };
        assert_eq!(emp.name, "employee");
        assert_eq!(emp.flavor, ClassFlavor::User);
        assert_eq!(emp.with_attrs.len(), 5);
        for attr in &emp.with_attrs {
            match attr.name.as_str() {
                "ID-number" => {
                    assert_eq!(attr.multi_valued, false);
                    assert_eq!(attr.tag, false);
                    assert_eq!(attr.optional, false);
                }
                "roles" => {
                    assert_eq!(attr.multi_valued, true);
                    assert_eq!(attr.tag, false);
                    assert_eq!(attr.optional, false);
                }
                "full-time" => {
                    assert_eq!(attr.multi_valued, false);
                    assert_eq!(attr.tag, true);
                    assert_eq!(attr.optional, true);
                }
                "part-time" => {
                    assert_eq!(attr.multi_valued, false);
                    assert_eq!(attr.tag, true);
                    assert_eq!(attr.optional, true);
                }
                "intern" => {
                    assert_eq!(attr.multi_valued, false);
                    assert_eq!(attr.tag, true);
                    assert_eq!(attr.optional, true);
                }
                _ => panic!("unexpected attribute name: {}", attr.name),
            }
        }
    }

    #[test]
    fn test_base_allow() {
        let valids = vec!["allow endpoints with users to access services"];
        for valid in valids {
            let tokens: Result<Vec<Token>, CompilationError> = tokenize_str(valid).or_else(|e| {
                panic!("failed to tokenize '{}': {:?}", valid, e);
            });
            let toks = tokens.unwrap();
            assert_eq!(7, toks.len());
            let _pol = match parse(toks) {
                Ok(policy) => policy,
                Err(e) => {
                    panic!("failed to parse '{}': {:?}", valid, e);
                }
            };
        }
    }

    #[test]
    fn test_omit_endpoint() {
        let valids = vec![
            "allow users to access services",
            "allow managed users to access services",
            "allow color:red users to access services",
            "allow users with color:red to access services",
            "allow managed users with color:red to access services",
        ];
        for valid in valids {
            let tokens: Result<Vec<Token>, CompilationError> = tokenize_str(valid).or_else(|e| {
                panic!("failed to tokenize '{}': {:?}", valid, e);
            });
            let _pol = match parse(tokens.unwrap()) {
                Ok(policy) => policy,
                Err(e) => {
                    panic!("failed to parse '{}': {:?}", valid, e);
                }
            };
        }
    }

    #[test]
    fn test_omit_user() {
        let valids = vec![
            "allow endpoints to access services",
            "allow managed endpoints to access services",
            "allow endpoints with color:red to access services",
            "allow managed endpoints with color:red to access services",
        ];
        for valid in valids {
            let tokens: Result<Vec<Token>, CompilationError> = tokenize_str(valid).or_else(|e| {
                panic!("failed to tokenize '{}': {:?}", valid, e);
            });
            let _pol = match parse(tokens.unwrap()) {
                Ok(policy) => policy,
                Err(e) => {
                    panic!("failed to parse '{}': {:?}", valid, e);
                }
            };
        }
    }

    #[test]
    fn test_verbose_endpoint() {
        let valids = vec![
            "allow endpoints with color:green with managed users with color:red to access services",
            "allow color:green endpoints with managed users with color:red to access services",
        ];
        for valid in valids {
            let tokens: Result<Vec<Token>, CompilationError> = tokenize_str(valid).or_else(|e| {
                panic!("failed to tokenize '{}': {:?}", valid, e);
            });
            let _pol = match parse(tokens.unwrap()) {
                Ok(policy) => policy,
                Err(e) => {
                    panic!("failed to parse '{}': {:?}", valid, e);
                }
            };
        }
    }
}
