//! binp - Binary policy bundle.

use chrono::prelude::*;
use std::time::{SystemTime, UNIX_EPOCH};

pub const SERIAL_VERSION: u32 = 1121;

#[allow(dead_code)]
pub struct Binp {}

impl Binp {}

#[allow(dead_code)]
#[derive(Default)]
pub struct BinpBuilder {
    serial_version: u32,
    policy_date: String,
    policy_version: u64,
    policy_revision: String,
    metadata: String,
}

#[allow(dead_code)]
impl BinpBuilder {
    pub fn new() -> BinpBuilder {
        let utc: DateTime<Utc> = Utc::now();
        let policy_date = utc.to_rfc3339();
        let tsnow = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let policy_version = tsnow.as_secs();

        BinpBuilder {
            serial_version: SERIAL_VERSION,
            policy_date,
            policy_version,
            ..Default::default()
        }
    }

    pub fn build(&self) -> Binp {
        Binp {}
    }

    pub fn policy_revision(&mut self, revision: &str) {
        self.policy_revision = revision.to_string();
    }

    pub fn with_metadata(&mut self, metadata: &str) {
        self.metadata = metadata.to_string();
    }

    pub fn get_policy_date(&self) -> &str {
        &self.policy_date
    }
}
