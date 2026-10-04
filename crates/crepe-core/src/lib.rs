//! Shared, dependency-light network types, events and stable errors.
mod error;
mod types;
pub use error::{Error, Result};
pub use types::*;
