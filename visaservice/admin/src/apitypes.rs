use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct PolicyListEntry {
    pub config_id: u64,
    pub version: String,
}

#[derive(Serialize)]
pub struct PolicyBundle {
    pub config_id: u64, // ignored when installing
    pub version: String, // use empty string if you don't care
    pub format: String,
    pub container: String,
}
