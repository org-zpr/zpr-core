use std::path::Path;
use std::fs;

use crate::compilation::CompilationError;


#[derive(Debug)]
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
}

#[derive(Debug)]
pub struct Token {
    pub tt: TokenType,
    pub line: usize,
    pub col: usize,
}

impl Token {
    pub fn new_from_str(s: &str, line: usize, col: usize) -> Token {
        let ls = s.to_lowercase();
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
            _ => TokenType::Literal(s.to_string()),
        };
        Token::new(tok, line, col)
    }

    pub fn new(tt: TokenType, line: usize, col: usize) -> Token {
        Token {
            tt,
            line,
            col,
        }
    }
}


fn is_sugar(s: &str) -> bool {
    match s {
        "a" | "an"  => true,
        _ => false,
    }
}



pub fn tokenize(zpl_in: &Path) -> Result<Vec<Token>, CompilationError> {
    let zpl = fs::read_to_string(zpl_in)?;
    let mut tokens = Vec::new();
    let mut line = 1;
    let mut col = 1;
    let mut chars = zpl.chars().peekable();

    let mut current_word = String::new();
    let mut current_start = (line, col);
    let mut quoting = false;
    let mut quote_char = ' ';


    while let Some(c) = chars.next() {
        match c {
            '\n' => {
                if quoting {
                    // quoted strings should not span lines.
                    return Err(CompilationError::UnterminatedQuote(current_start.0, current_start.1));
                }
                if current_word.len() > 0 {
                    if !is_sugar(&current_word) {
                        tokens.push(Token::new_from_str(&current_word, current_start.0, current_start.1));
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
                    if !is_sugar(&current_word) {
                        tokens.push(Token::new_from_str(&current_word, current_start.0, current_start.1));
                    }
                    current_word.clear();
                }
                col += 1;
            }
            ' '  => {
                // if we are quoting the literal, keep space, otherwise this is a delimiter
                if current_word.len() > 0 {
                    if quoting {
                        current_word.push(c);
                    } else {
                        if !is_sugar(&current_word) {
                            tokens.push(Token::new_from_str(&current_word, current_start.0, current_start.1));
                        }
                        current_word.clear();
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
                            // End of the quoted literal.
                            if !is_sugar(&current_word) {
                                tokens.push(Token::new_from_str(&current_word, current_start.0, current_start.1));
                            }
                            current_word.clear();
                            quoting = false;
                        } else {
                            current_word.push(c);
                        }
                    } else {
                        // not quoting so this is allowed only for escape.
                        if let Some(&next) = chars.peek() {
                            if next == c {
                                // this is an escape
                                current_word.push(c);
                                chars.next();
                                col += 1;
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