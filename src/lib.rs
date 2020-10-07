/// module for interpret r1cs as ML Extension used by linear sumcheck
pub mod data_structures;

/// error package
mod error;
pub use error::Error;

/// testing utilities
#[cfg(test)]
pub(crate) mod test_utils;