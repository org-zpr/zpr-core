//! TUI log buffer and tracing subscriber layer for lntest.
//!
//! Captures tracing log records into an in-memory buffer that the TUI log
//! pane drains on each render cycle instead of writing to stdout.

use std::sync::{Arc, Mutex};
use tracing::Level;
use tracing_subscriber::{filter::LevelFilter, prelude::*};

/// Shared, cloneable buffer that accumulates log lines for the TUI log pane.
#[derive(Clone, Default)]
pub struct LogBuffer(Arc<Mutex<Vec<String>>>);

impl LogBuffer {
    /// Append a formatted log line to the buffer.
    pub fn push(&self, line: String) {
        self.0.lock().unwrap().push(line);
    }

    /// Move all buffered lines into `dest`, leaving the buffer empty.
    pub fn drain_into(&self, dest: &mut Vec<String>) {
        let mut buf = self.0.lock().unwrap();
        dest.append(&mut *buf);
    }
}

/// Custom tracing layer that captures log records into a [LogBuffer].
struct TuiLogLayer {
    buf: LogBuffer,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for TuiLogLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let meta = event.metadata();
        let level = meta.level();
        let target = meta.target();

        struct Visitor(String);
        impl tracing::field::Visit for Visitor {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{:?}", value);
                    // Remove surrounding quotes added by debug formatting of &str
                    if self.0.starts_with('"') && self.0.ends_with('"') && self.0.len() >= 2 {
                        self.0 = self.0[1..self.0.len() - 1].to_string();
                    }
                }
            }
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "message" {
                    self.0 = value.to_string();
                }
            }
        }

        let mut visitor = Visitor(String::new());
        event.record(&mut visitor);

        let line = format!("[{level}] {target}: {}", visitor.0);
        self.buf.push(line);
    }
}

/// Install a global tracing subscriber that routes all log output into `buf`.
pub fn enable_logging(buf: LogBuffer) {
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry()
            .with(TuiLogLayer { buf })
            .with(LevelFilter::from_level(Level::DEBUG)),
    )
    .expect("setting default subscriber failed");
}
