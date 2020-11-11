use ark_ec::PairingEngine;
use ark_std::marker::PhantomData;

pub mod indexer;
pub mod prover;
pub mod verifier;

#[cfg(test)]
mod tests;

pub struct AHPForSpartan<E: PairingEngine>(#[doc(hidden)] PhantomData<E>);
