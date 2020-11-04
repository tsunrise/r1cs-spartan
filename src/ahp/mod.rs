use ark_ff::Field;
use ark_std::marker::PhantomData;

pub mod prover;
pub mod verifier;
pub mod indexer;

pub struct AHPForSpartan<F: Field> (
    #[doc(hidden)] PhantomData<F>
);