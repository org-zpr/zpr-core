use std::fs;
use std::path::Path;

use crate::errors::CompilationError;
use crate::zplstr::{ZPLStr, ZPLStrBuilder};

#[derive(Debug, PartialEq, Clone)]
pub enum TokenType {
    Allow,
    Define,
    With,
    Without,
    To,     // to must preceed access
    Access, // access must be preceeded by to
    And,    // "," is AND as is "and" as is ", and"
    Comma,
    As,
    AkA,
    From,
    Tag,
    Tags,
    Optional,
    Multiple,
    Literal(String),
    Tuple((String, String)),
}

#[allow(dead_code)]
pub fn tuple_from_strs(name: &str, value: &str) -> TokenType {
    TokenType::Tuple((String::from(name), String::from(value)))
}

#[derive(Debug, PartialEq, Clone)]
pub struct Token {
    pub tt: TokenType,
    pub line: usize,
    pub col: usize,
}

impl Token {
    pub fn new_from_str(s: &ZPLStr, line: usize, col: usize) -> Token {
        if s.is_tuple() {
            return Token::new(TokenType::Tuple(s.as_tuple()), line, col);
        }
        let ls = s.as_atom().to_lowercase();
        let tok = match ls.as_str() {
            "allow" => TokenType::Allow,
            "define" => TokenType::Define,
            "with" => TokenType::With,
            "without" => TokenType::Without,
            "to" => TokenType::To,
            "access" => TokenType::Access,
            "and" => TokenType::And,
            "," => TokenType::Comma,
            "as" => TokenType::As,
            "aka" => TokenType::AkA,
            "from" => TokenType::From,
            "tag" => TokenType::Tag,
            "tags" => TokenType::Tags,
            "optional" => TokenType::Optional,
            "multiple" => TokenType::Multiple,
            _ => TokenType::Literal(s.as_atom()),
        };
        Token::new(tok, line, col)
    }

    pub fn new(tt: TokenType, line: usize, col: usize) -> Token {
        Token { tt, line, col }
    }
}

pub fn tokenize(zpl_in: &Path) -> Result<Vec<Token>, CompilationError> {
    let zpl = fs::read_to_string(zpl_in)?;
    return tokenize_str(&zpl);
}

pub fn tokenize_str(zpl: &str) -> Result<Vec<Token>, CompilationError> {
    let mut tokens = Vec::new();
    let mut line = 1;
    let mut col = 1;
    let mut chars = zpl.chars().peekable();

    let mut current_word = ZPLStrBuilder::new();
    let mut current_start = (line, col);
    let mut quoting = false;
    let mut quote_char = ' ';

    while let Some(c) = chars.next() {
        match c {
            '\n' => {
                if quoting {
                    // quoted strings should not span lines.
                    return Err(CompilationError::UnterminatedQuote(
                        current_start.0,
                        current_start.1,
                    ));
                }
                if current_word.len() > 0 {
                    if !current_word.is_sugar() {
                        // TODO: is_sugar can be function on builder
                        tokens.push(Token::new_from_str(
                            &current_word.build(),
                            current_start.0,
                            current_start.1,
                        ));
                    }
                    current_word.clear();
                }
                line += 1;
                col = 1;
            }
            '\t' => {
                // tab?
                if current_word.len() > 0 {
                    // Then treat as a delimiter
                    if !current_word.is_sugar() {
                        tokens.push(Token::new_from_str(
                            &current_word.build(),
                            current_start.0,
                            current_start.1,
                        ));
                    }
                    current_word.clear();
                }
                col += 1;
            }
            ' ' => {
                // if we are quoting the literal, keep space, otherwise this is a delimiter
                if current_word.len() > 0 {
                    if quoting {
                        current_word.push(c);
                    } else {
                        if !current_word.is_sugar() {
                            tokens.push(Token::new_from_str(
                                &current_word.build(),
                                current_start.0,
                                current_start.1,
                            ));
                        }
                        current_word.clear();
                    }
                }
                col += 1;
            }
            ',' => {
                // if we are quoting the literal, keep comma, otherwise this is new COMMA token (should this be AND?)
                if current_word.len() > 0 {
                    if quoting {
                        current_word.push(c);
                    } else {
                        if !current_word.is_sugar() {
                            tokens.push(Token::new_from_str(
                                &current_word.build(),
                                current_start.0,
                                current_start.1,
                            ));
                        }
                        current_word.clear();
                        col += 1;
                        tokens.push(Token::new(TokenType::Comma, line, col));
                        col += 1;
                    }
                }
            }
            ':' => {
                // If we are quoting, then this is just a normal colon. Otherwise we treat this as an attribute signifier.
                if current_word.len() == 0 {
                    return Err(CompilationError::IllegalColon(line, col));
                }
                if quoting {
                    current_word.push(c);
                } else {
                    if !current_word.accept_value() {
                        return Err(CompilationError::IllegalColon(line, col));
                    }
                }
                col += 1;
            }
            '\'' | '`' => {
                // The single forward or backward quote.
                // within a literal, two of these is just a way to insert a quote.
                // this could also be the start of a quoted literal
                // or this is the end of a quoted literal
                if current_word.len() == 0 {
                    if !quoting {
                        quoting = true;
                        quote_char = c;
                        current_start = (line, col);
                    } else {
                        // we are quoting already and word is empty, so only a repeat is allowed.
                        if c == quote_char {
                            current_word.push(c);
                            quoting = false;
                        } else {
                            return Err(CompilationError::MismatchedQuote(line, col));
                        }
                    }
                    col += 1;
                } else {
                    // We have a word in buffer
                    if quoting {
                        if c == quote_char {
                            // End of the quoted literal. If next char is a colon, then we continue to parse attr value.
                            if let Some(&next) = chars.peek() {
                                if next == ':' {
                                    quoting = false;
                                    col += 1;
                                    continue;
                                }
                            }
                            if !current_word.is_sugar() {
                                tokens.push(Token::new_from_str(
                                    &current_word.build(),
                                    current_start.0,
                                    current_start.1,
                                ));
                            }
                            current_word.clear();
                            quoting = false;
                        } else {
                            current_word.push(c);
                        }
                    } else {
                        // not quoting so this is allowed for escape or for a quoted tuple value.
                        if let Some(&next) = chars.peek() {
                            if next == c {
                                // this is an escape
                                current_word.push(c);
                                chars.next();
                                col += 1;
                            } else if current_word.is_tuple() && current_word.value_len() == 0 {
                                quoting = true;
                            } else {
                                return Err(CompilationError::IllegalQuote(line, col));
                            }
                        }
                    }
                }
                col += 1;
            }
            _ => {
                if current_word.len() == 0 && !quoting {
                    current_start = (line, col);
                }
                col += 1;

                // Trailing period is discarded
                if c == '.' {
                    if let Some(&next) = chars.peek() {
                        if next.is_whitespace() {
                            // discard the period
                            continue;
                        }
                    }
                }

                current_word.push(c);
            }
        }
    }
    Ok(tokens)
}

#[cfg(test)]
mod test {

    #[test]
    fn test_tuple_literal() {
        let zpl = "define foo as user with color:purple, `role`:`manager`, office:`fris:co`, and tag `foo bar`";
        let tokens = super::tokenize_str(zpl).unwrap();
        println!("{:?}", tokens);
        assert_eq!(tokens.len(), 12);
        let colorpurple = &tokens[5];
        assert_eq!(colorpurple.tt, super::tuple_from_strs("color", "purple"));
        let rolemanager = &tokens[7];
        assert_eq!(rolemanager.tt, super::tuple_from_strs("role", "manager"));
        let officefrisco = &tokens[8];
        assert_eq!(officefrisco.tt, super::tuple_from_strs("office", "fris:co"));
    }
}
