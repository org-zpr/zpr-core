#![cfg_attr(feature = "ci", deny(warnings))]

// Core modules
pub mod assembly;
pub mod batch_io;
pub mod config;
pub mod fastpath;
pub mod packet;
pub mod queues;

// Public modules
pub mod adapter_manager_worker;
pub mod adapter_tables;
pub mod address_pool;
pub mod admin_worker;
pub mod auth;
pub mod capture_worker;
pub mod classifier;
pub mod compress;
pub mod counters;
pub mod defs;
pub mod fastpath_io;
pub mod fastpath_worker;
pub mod flow_control;
pub mod forwarding_tables;
pub mod km;
pub mod km_cert_exchange;
pub mod km_multiplexor;
pub mod km_noise;
pub mod link_state;
pub mod logging;
pub mod main_args;
pub mod mgmt;
pub mod mgmt_dispatch_worker;
pub mod mgmt_processor_worker;
pub mod packet_queue;
pub mod packet_steering;
pub mod pcap_writer;
pub mod peer_table;
pub mod pki;
pub mod prelude;
pub mod sample_ring;
#[cfg(not(feature = "capnp-ancillary"))]
pub mod set_capture_file_worker;
pub mod signal_worker;
pub mod special_peers;
pub mod sys;
pub mod tc;
pub mod test_packet;
pub mod tlv;
pub mod tun_ctl;
pub mod two_way_queue;
pub mod visa_mgmt;
pub mod visa_table;
pub mod vs_worker;
pub mod vss_worker;
pub mod zdp;
pub mod zdp_ll;
pub mod zdpr;
pub mod zdpr_worker;
pub mod zprtun;

#[cfg(test)]
mod km_testdata;

/// Re-export test modules for fuzzing when feature is enabled
#[cfg(feature = "fuzzing")]
pub use assembly::test;

#[cfg(feature = "fuzzing")]
pub mod fuzz_harness;
