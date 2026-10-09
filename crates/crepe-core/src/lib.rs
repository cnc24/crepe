//! Shared, dependency-light network types, events and stable errors.
mod error;
mod types;
pub use error::{Error, Result};
pub use types::*;

mod evidence;
pub use evidence::{PacketEvidence, PacketRef};
