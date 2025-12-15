//! Shared implementations of types related to the policy Capn Proto.

mod attribute;
mod error;
mod join;
mod writer;

pub use attribute::{AttrDomain, Attribute};
pub use error::{AttributeError, PolicyTypeError};
pub use join::{JoinPolicy, PFlags, Scope, ScopeFlag, Service, ServiceType};
pub use writer::{WriteTo, write_attributes};
