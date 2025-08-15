//! Logging-related stuff.

use tracing::Level;
use tracing_subscriber::filter::targets::Targets;
use tracing_subscriber::{fmt, prelude::*};

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
    pub const NONE: &str = "none";
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
        NONE,
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

fn create_target_filter<T>(
    logging_vec: &Vec<(String, String)>
) -> Targets
where
    String: From<T>,
    T: for<'a> std::cmp::PartialEq<&'a str>,
{
    let mut targets = Targets::new();

    targets = targets.with_default(Level::INFO);

    // let lvl = match verbose {
    //     false => Level::DEBUG,
    //     true => Level::TRACE,
    // };

    // let mut empty = true;

    // for target in debug.into_iter() {
    //     empty = false;
    //     if target == targets::ALL {
    //         targets = targets.with_default(lvl);
    //     } else if target == targets::NONE {
    //         if lvl == Level::TRACE {
    //             targets = targets.with_default(lvl);
    //         } else {
    //             targets = targets.with_default(Level::INFO);
    //         }
    //     } else {
    //         targets = targets.with_target(target, lvl);
    //     }
    // }

    // // Prints trace level debugging even if user did not use --debug flag
    // if empty && lvl == Level::TRACE {
    //     targets = targets.with_default(lvl);
    // }

    // let debugged_targets = targets.clone();

    // for target in quiet.into_iter() {
    //     if target == targets::ALL {
    //         targets = targets.with_default(Level::ERROR);
    //     } else if target == targets::NONE {
    //         targets = debugged_targets.clone();
    //     } else {
    //         targets = targets.with_target(target, Level::ERROR);
    //     }
    // }

    targets
}
pub fn initialize(logging_vec: &Vec<(String, String)>) {
    // tracing_subscriber::registry()
    //     .with(fmt::layer())
    //     .with(create_target_filter(debug, quiet, verbose))
    //     .init();
}
// pub fn initialize(
//     debug: &Vec<String>,
//     quiet: &Vec<String>,
//     verbose: &bool,
// ) -> reload::Handle<fmt::Layer<Registry>, Registry> {
//     let (reload_layer, reload_handle) = reload::Layer::new(fmt::layer());
//     tracing_subscriber::registry()
//         .with(reload_layer)
//         .with(create_target_filter(debug, quiet, verbose))
//         .init();
//     // let filtered_layer = fmt::Layer::default().with_filter(create_target_filter(debug, quiet, verbose));
//     // let (filtered_layer, reload_handle) = reload::Layer::new(filtered_layer);
//     // tracing_subscriber::registry()
//     //     .with(filtered_layer)
//     //     .init();

//     reload_handle
// }

// pub fn reload(
//     debug: &Vec<String>,
//     quiet: &Vec<String>,
//     verbose: &bool,
//     reload_handle: &reload::Handle<fmt::Layer<Registry>, Registry>,
// ) {
//     let new_targets = fmt::layer().with_filter(create_target_filter(debug, quiet, verbose));
//     // reload_handle.reload(new_targets).expect("failed to load new targets");

//     // reload_handle.modify(create_target_filter(debug, quiet, verbose));

// }
