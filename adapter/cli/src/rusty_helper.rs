use rustyline::{
    Context, Helper,
    completion::Pair,
    highlight::CmdKind,
    validate::{ValidationContext, ValidationResult},
};
use std::borrow::Cow;

#[derive(Helper)]
pub struct RustyHelper;

const COMMANDS: &[&str] = &[
    "echo",
    "counters",
    "watch",
    "perf-sample",
    "capture",
    "link",
    "logging",
    "addr",
    "quit",
];

const CAPTURE_SUBCOMMANDS: &[&str] = &[
    "set-file",
    "close-file",
    "set-program",
    "delete-program",
    "flush-file",
    "sequence",
];

const LINK_SUBCOMMANDS: &[&str] = &["show", "configure", "start", "stop", "reset"];

// Implement the Completer trait for RustyHelper
impl rustyline::completion::Completer for RustyHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let (start, prefix, head_command): (usize, &str, &str) = get_word_at_cursor(line, pos);

        let matches = candidate_list(head_command)
            .iter()
            .filter(|c: &&&str| c.starts_with(prefix.to_lowercase().as_str()))
            .map(|&c| Pair {
                display: c.to_string(),
                replacement: format!("{} ", c),
            })
            .collect();

        Ok((start, matches))
    }
}

// Implement the Hinter trait for RustyHelper
impl rustyline::hint::Hinter for RustyHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> Option<String> {
        let (_start, prefix, head_command): (usize, &str, &str) = get_word_at_cursor(line, pos);

        if !prefix.is_empty() {
            if let Some(c) = candidate_list(head_command)
                .iter()
                .find(|c: &&&str| c.starts_with(prefix.to_lowercase().as_str()))
            {
                if c.len() != prefix.len() {
                    return Some(c[prefix.len()..].to_string());
                }
            }
        }

        let last_word = line[..pos].split_whitespace().last().unwrap_or("");
        let info = get_command_parameter_info(last_word);
        if info.is_empty() {
            None
        } else {
            Some(info.to_string())
        }
    }
}

// Implement the Highlighter trait for RustyHelper
impl rustyline::highlight::Highlighter for RustyHelper {
    fn highlight_hint<'h>(&self, hint: &'h str) -> std::borrow::Cow<'h, str> {
        std::borrow::Cow::Owned(format!("\x1b[90m{}\x1b[0m", hint))
    }

    fn highlight<'l>(&self, line: &'l str, pos: usize) -> Cow<'l, str> {
        let (start, prefix, head_command): (usize, &str, &str) = get_word_at_cursor(line, pos);

        if prefix.is_empty() {
            return Cow::Borrowed(line);
        }

        let matched = candidate_list(head_command)
            .iter()
            .any(|c| c.starts_with(prefix.to_lowercase().as_str()));

        if matched {
            Cow::Owned(format!(
                "{}\x1b[32m{}\x1b[0m{}",
                &line[..start],
                &line[start..pos],
                &line[pos..],
            ))
        } else {
            Cow::Borrowed(line)
        }
    }
    fn highlight_char(&self, line: &str, pos: usize, kind: CmdKind) -> bool {
        let _ = (line, pos, kind);
        true
    }
}

// Implement the Validator trait for RustyHelper
impl rustyline::validate::Validator for RustyHelper {
    fn validate(&self, ctx: &mut ValidationContext) -> rustyline::Result<ValidationResult> {
        if shlex::split(ctx.input()).is_none() {
            Ok(ValidationResult::Incomplete)
        } else {
            Ok(ValidationResult::Valid(None))
        }
    }
}

// Helper function to get, word, cursor position, and leading head command stripping any leading whitespace
fn get_word_at_cursor(line: &str, pos: usize) -> (usize, &str, &str) {
    let start: usize = line[..pos].rfind(' ').map_or(0, |i: usize| i + 1);
    let prefix: &str = &line[start..pos];
    let head_command: &str = line[..start].split_whitespace().next().unwrap_or("");
    (start, prefix, head_command)
}

// Which candidates to offer given the head command:
fn candidate_list(head_command: &str) -> &'static [&'static str] {
    match head_command {
        "capture" => CAPTURE_SUBCOMMANDS,
        "link" => LINK_SUBCOMMANDS,
        "" => COMMANDS,
        _ => &[],
    }
}

// Helper function to get the parameter info for a given command
fn get_command_parameter_info(command: &str) -> &str {
    match command {
        "echo" => " : Ping the Packet Handler",
        "counters" => " -r/--reset : Display all counters + uptime; --reset to zero them instead.",
        "watch" => " <interval> (secs) : Poll counters every interval seconds and print deltas.",
        "perf-sample" => " <duration> <frequency> : Performancy sampling",
        "capture" => " <subcommand>",
        "link" => " <subcommand>",
        "logging" => " [<level>=<target>] (>=1 pair) : Change log levels at runtime",
        "addr" => " : get address of adapter's node (IP + port)",
        "quit" => " : Exit the CLI",
        "set-file" => " <file_path> : Set the pcap output file",
        "close-file" => " : Close the pcap output file",
        "set-program" => {
            " [program] : install a BPF filter (default: link[0] == 1 or link[0] == 0)"
        }
        "delete-program" => " : delete the BPF filter",
        "flush-file" => " : Flush outstanding packets to disk",
        "sequence" => " <file_path> <duration> [program] : open, filter, wait, close",
        "show" => " [id] : show one link, or summary if no id",
        "configure" => " <id>",
        "start" => " <id>",
        "stop" => " <id>",
        "reset" => " <id>",
        _ => "",
    }
}
