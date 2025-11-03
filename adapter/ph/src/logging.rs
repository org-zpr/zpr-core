//! Logging-related stuff.

use std::collections::HashMap;
use tracing::Level;
use tracing_subscriber::filter::targets::Targets;
use tracing_subscriber::{Registry, filter, fmt, prelude::*, reload};

/// Target of a log message, for filtering.
pub mod targets {
    // Design note: my intent is for targets to indicate, to which
    // subsystem/API they are reporting on "behalf of".  This is usually,
    // but not always, the "subject" of the message.  An example where these
    // differ is a callee in subsystem X who logs the result of an API call
    // to subsystem Y.  Though the "subject" is an object managed by Y, the
    // log target should be X, since the message is reporting on behalf of
    // an action in X.  (But if Y itself logs the result, it should do so
    // under target Y.) This helps provide a complete picture to someone
    // debugging X why X is behaving in a certain way, without needing to
    // also enable logging for Y (and all other APIs which X happens to use).

    // More succinctly, the "golden rule" here is, if someone is trying to
    // debug subsystem X, log target X should give them a complete
    // understanding of why X is acting the way it is (even if the bug
    // ultimately lies with a dependency of X).

    pub const ALL: &str = "all";
    pub const CAPTURE: &str = "capture";
    pub const DATAPATH: &str = "datapath";
    pub const FLOW_MGMT: &str = "flow_mgmt";
    pub const KEY_MGMT: &str = "key_mgmt";
    pub const LINK_STATE: &str = "link_state";
    pub const MGMT_EVENTS: &str = "mgmt_events";
    pub const NET_OS: &str = "net_os";
    pub const PEER_MGMT: &str = "peer_mgmt";
    pub const REPORTING: &str = "reporting";
    pub const RPC: &str = "rpc";
    pub const STARTUP: &str = "startup";
    pub const VISA_MGMT: &str = "visa_mgmt";
    pub const ZDP: &str = "zdp";

    pub use libnode::logging::targets::*;

    pub const ALL_TARGETS: &[&str] = &[
        ALL,
        CAPTURE,
        DATAPATH,
        FLOW_MGMT,
        KEY_MGMT,
        LINK_STATE,
        MGMT_EVENTS,
        NET_OS,
        PEER_MGMT,
        REPORTING,
        RPC,
        STARTUP,
        VISA_MGMT,
        VS_RPC,
        VSS_RPC,
        ZDP,
    ];
}

pub mod levels {

    pub const OFF: &str = "OFF";
    pub const ERROR: &str = "ERROR";
    pub const WARN: &str = "WARN";
    pub const INFO: &str = "INFO";
    pub const DEBUG: &str = "DEBUG";
    pub const TRACE: &str = "TRACE";

    pub const ALL_LEVELS: &[&str] = &[ERROR, WARN, INFO, DEBUG, TRACE, OFF];
}

/// Creates the filter for the specified targets
fn create_target_filter(logging_map: &HashMap<String, String>) -> Targets {
    let mut targets = Targets::new();

    let default_lvl: Level = match logging_map.get(targets::ALL) {
        Some(value) => get_level(value.as_str()),
        None => Level::INFO,
    };

    targets = targets.with_default(default_lvl);

    for elem in logging_map.iter() {
        targets = targets.with_target(elem.0.clone(), get_level(elem.1.as_str()));
    }

    targets
}

/// Creates the tracing_subscriber and the initial hashmap
/// Returns the reload handler, which allows the filters to be
/// changed at runtime and the hashmap with the current targets
/// and levels
pub fn initialize(
    logging_vec: &mut Vec<(String, String)>,
) -> (
    reload::Handle<filter::Filtered<fmt::Layer<Registry>, Targets, Registry>, Registry>,
    HashMap<String, String>,
) {
    let mut logging_map = HashMap::new();
    for elem in logging_vec {
        logging_map.insert(elem.0.clone(), elem.1.clone());
    }

    let (reload_layer, reload_handle) =
        reload::Layer::new(fmt::layer().with_filter(create_target_filter(&logging_map)));
    tracing_subscriber::registry().with(reload_layer).init();

    (reload_handle, logging_map)
}

/// Creates a new filter and updates the existing Layer
pub fn reload_filter(
    reload_handle: &reload::Handle<
        filter::Filtered<fmt::Layer<Registry>, Targets, Registry>,
        Registry,
    >,
    logging_map: &HashMap<String, String>,
) {
    reload_handle
        .modify(|filter| *filter.filter_mut() = create_target_filter(logging_map))
        .unwrap();
}

/// Gets the log level from a string
/// This is highly permissive, but the only information that will be passed
/// in will one of levels::ALL_LEVELS, so it is less permissive than it seems
fn get_level(level: &str) -> Level {
    match level {
        levels::DEBUG => Level::DEBUG,
        levels::TRACE => Level::TRACE,
        levels::WARN => Level::WARN,
        levels::OFF => Level::ERROR,
        levels::ERROR => Level::ERROR,
        _ => Level::INFO,
    }
}
