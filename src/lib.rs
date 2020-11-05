#[macro_use]
#[allow(unused_imports)]
extern crate ark_relations;

#[cfg(test)]
#[macro_use]
extern crate bench_utils;

use ark_ff::{Field};
use ark_std::marker::PhantomData;

pub mod ahp;

pub use error::Error;

/// module for interpret r1cs as ML Extension used by linear sumcheck
pub mod data_structures;

/// error package
mod error;
/// testing utilities
#[cfg(test)]
pub(crate) mod test_utils;

pub struct Spartan<F: Field>(
    #[doc(hidden)] PhantomData<F>
);



