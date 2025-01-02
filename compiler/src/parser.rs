use std::collections::HashMap;

use crate::errors::CompilationError;
use crate::lex::{Token, TokenType};
use crate::ptypes::{Class, Policy};
use crate::define::{parse_define, resolve_class_flavors};
use crate::allow::parse_allow;



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
    for statement in &mut statements {
        if statement[0].tt == TokenType::Define {
            let class = parse_define(&statement)?;

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
    for statement in &mut statements {
        if statement[0].tt == TokenType::Allow {
            let allow = parse_allow(&statement, &class_index)?;
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::lex::tokenize_str;

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
                Ok(policy) => { policy}
                Err(e) => {
                    panic!("failed to parse '{}': {:?}", valid, e);
                }
            };
        }
    }

}