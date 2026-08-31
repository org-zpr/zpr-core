#![cfg_attr(feature = "ci", deny(warnings))]

// Core modules
pub mod assembly;
pub mod fastpath;
pub mod packet;
pub mod queues;
pub mod batch_io;
pub mod config;

// Private modules
mod adapter_manager_worker;
mod adapter_tables;
mod address_pool;
mod admin_worker;
mod auth;
mod capture_worker;
mod classifier;
mod compress;
mod counters;
mod defs;
mod fastpath_io;
mod fastpath_worker;
mod flow_control;
mod forwarding_tables;
mod km;
mod km_cert_exchange;
mod km_multiplexor;
mod km_noise;
mod link_state;
mod logging;
mod main_args;
mod mgmt;
mod mgmt_dispatch_worker;
mod mgmt_processor_worker;
mod packet_queue;
mod packet_steering;
mod pcap_writer;
mod peer_table;
mod pki;
mod prelude;
mod sample_ring;
#[cfg(not(feature = "capnp-ancillary"))]
mod set_capture_file_worker;
mod signal_worker;
mod special_peers;
mod sys;
mod tc;
mod test_packet;
mod tlv;
mod tun_ctl;
mod two_way_queue;
mod visa_mgmt;
mod visa_table;
mod vs_worker;
mod vss_worker;
mod zdp;
mod zdp_ll;
mod zdpr;
mod zdpr_worker;
mod zprtun;

#[cfg(test)]
mod km_testdata;

/// Re-export test modules for fuzzing when feature is enabled
#[cfg(feature = "fuzzing")]
pub use assembly::test;

#[cfg(feature = "fuzzing")]
pub mod fuzz_harness;

