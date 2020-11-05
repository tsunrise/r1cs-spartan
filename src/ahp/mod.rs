use ark_ff::Field;
use ark_std::marker::PhantomData;

pub mod prover;
pub mod verifier;
pub mod indexer;

#[cfg(test)]
mod tests;

pub struct AHPForSpartan<F: Field> (
    #[doc(hidden)] PhantomData<F>
);