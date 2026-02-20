//! TUI application state, rendering, and event loop for lntest.

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use std::time::Duration;
use tokio::sync::mpsc;
use tui_input::{Input, InputRequest, backend::crossterm::EventHandler};

use super::args::Config;
use super::cmd::{Cmd, parse_command};
use super::logging::LogBuffer;

/// A single line in the REPL output pane.
pub enum OutputLine {
    /// An echoed command: rendered with a styled prompt prefix and the user input.
    Command(String),
    /// Plain response/error text.
    Text(String),
}

/// All state for the lntest TUI.
pub struct App {
    /// Lines accumulated from the tracing log buffer.
    pub log_lines: Vec<String>,
    /// Lines of REPL output (command echoes + response messages).
    pub output_lines: Vec<OutputLine>,
    /// Current contents of the input line.
    pub input: Input,
    /// Previously entered commands for up/down history navigation.
    pub history: Vec<String>,
    /// Index into `history` when navigating; `None` when at the live prompt.
    pub history_idx: Option<usize>,
    /// Set to `true` to exit the TUI loop on the next iteration.
    pub should_quit: bool,
}

impl App {
    /// Create a new, empty [App].
    pub fn new() -> Self {
        App {
            log_lines: Vec::new(),
            output_lines: Vec::new(),
            input: Input::default(),
            history: Vec::new(),
            history_idx: None,
            should_quit: false,
        }
    }
}

/// Render the full TUI frame: log pane (upper 70%) and REPL pane (lower 30%).
pub fn render(f: &mut ratatui::Frame, app: &App) {
    let chunks =
        Layout::vertical([Constraint::Percentage(70), Constraint::Percentage(30)]).split(f.area());

    // --- Log pane (upper) ---
    let log_area = chunks[0];
    let inner_height = log_area.height.saturating_sub(2) as usize; // subtract borders
    let log_start = app.log_lines.len().saturating_sub(inner_height);
    let visible_logs: Vec<Line> = app.log_lines[log_start..]
        .iter()
        .map(|s| {
            // Color-code by log level prefix
            let color = if s.contains("[ERROR]") {
                Color::Red
            } else if s.contains("[WARN]") {
                Color::Yellow
            } else if s.contains("[INFO]") {
                Color::Green
            } else {
                Color::Gray
            };
            Line::from(Span::styled(s.as_str(), Style::default().fg(color)))
        })
        .collect();

    let log_widget = Paragraph::new(visible_logs)
        .block(Block::default().title(" Logs ").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    f.render_widget(log_widget, log_area);

    // --- REPL pane (lower) ---
    let repl_area = chunks[1];
    let inner_height = repl_area.height.saturating_sub(2) as usize; // subtract borders
    // Reserve 1 line for the input prompt
    let output_lines_to_show = inner_height.saturating_sub(1);
    let output_start = app.output_lines.len().saturating_sub(output_lines_to_show);
    let mut repl_lines: Vec<Line> = app.output_lines[output_start..]
        .iter()
        .map(|line| match line {
            OutputLine::Command(cmd) => Line::from(vec![
                Span::styled(
                    "lntest> ",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    cmd.as_str(),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
            ]),
            OutputLine::Text(s) => Line::from(s.as_str()),
        })
        .collect();
    // Pad with empty lines so the prompt is always at the bottom of the pane
    while repl_lines.len() < output_lines_to_show {
        repl_lines.push(Line::from(""));
    }
    // Add prompt line
    repl_lines.push(Line::from(vec![
        Span::styled("lntest> ", Style::default().fg(Color::Cyan)),
        Span::raw(app.input.value()),
    ]));

    let repl_widget =
        Paragraph::new(repl_lines).block(Block::default().title(" REPL ").borders(Borders::ALL));
    f.render_widget(repl_widget, repl_area);

    // Position the real terminal cursor inside the prompt line
    let prompt_len = "lntest> ".len() as u16;
    let cursor_x = repl_area.x + 1 + prompt_len + app.input.visual_cursor() as u16;
    let cursor_y = repl_area.y + repl_area.height - 2;
    f.set_cursor_position((cursor_x, cursor_y));
}

/// Run the TUI event loop until the user quits.
///
/// Drains the log buffer and output channel on each tick, redraws the frame,
/// then handles keyboard input. Returns when `app.should_quit` becomes true
/// or an I/O error occurs.
pub fn run_tui(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
    log_buf: &LogBuffer,
    output_rx: &mut mpsc::UnboundedReceiver<String>,
    cmd_tx: &mpsc::UnboundedSender<Cmd>,
    output_tx: &mpsc::UnboundedSender<String>,
    cfg: &Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        // Drain log buffer
        log_buf.drain_into(&mut app.log_lines);

        // Drain output channel
        while let Ok(line) = output_rx.try_recv() {
            app.output_lines.push(OutputLine::Text(line));
        }

        terminal.draw(|f| render(f, app))?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                // Ignore key release events (only act on press / repeat)
                if key.kind == KeyEventKind::Release {
                    continue;
                }
                match key.code {
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.should_quit = true;
                    }
                    KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.should_quit = true;
                    }
                    KeyCode::Up => {
                        if !app.history.is_empty() {
                            let new_idx = match app.history_idx {
                                None => app.history.len() - 1,
                                Some(i) => i.saturating_sub(1),
                            };
                            app.history_idx = Some(new_idx);
                            let mut inp: Input = app.history[new_idx].clone().into();
                            inp.handle(InputRequest::GoToEnd);
                            app.input = inp;
                        }
                    }
                    KeyCode::Down => match app.history_idx {
                        None => {}
                        Some(i) if i + 1 < app.history.len() => {
                            let new_idx = i + 1;
                            app.history_idx = Some(new_idx);
                            let mut inp: Input = app.history[new_idx].clone().into();
                            inp.handle(InputRequest::GoToEnd);
                            app.input = inp;
                        }
                        Some(_) => {
                            app.history_idx = None;
                            app.input = Input::default();
                        }
                    },
                    KeyCode::Enter => {
                        let input = app.input.value().trim().to_string();
                        app.input = Input::default();
                        app.history_idx = None;
                        if input.is_empty() {
                            continue;
                        }
                        // Append to history (skip exact duplicates at the end)
                        if app.history.last().map(|s| s.as_str()) != Some(input.as_str()) {
                            app.history.push(input.clone());
                        }
                        // Echo the command in the REPL pane
                        app.output_lines.push(OutputLine::Command(input.clone()));

                        match parse_command(cfg, &input, output_tx) {
                            Ok(Cmd::Disconnect) => {
                                app.should_quit = true;
                            }
                            Ok(cmd) => {
                                if let Err(e) = cmd_tx.send(cmd) {
                                    app.output_lines
                                        .push(OutputLine::Text(format!("failed to send command: {:?}", e)));
                                    app.should_quit = true;
                                }
                            }
                            Err(e) => {
                                app.output_lines.push(OutputLine::Text(e));
                            }
                        }
                    }
                    _ => {
                        // Forward everything else to tui-input for line editing:
                        // ← → Home End Ctrl+A/E Ctrl+W Ctrl+K Alt+← Alt+→ etc.
                        app.input.handle_event(&Event::Key(key));
                    }
                }
            }
        }

        if app.should_quit {
            let _ = cmd_tx.send(Cmd::Disconnect);
            break;
        }
    }
    Ok(())
}
