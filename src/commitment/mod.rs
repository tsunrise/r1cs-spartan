use ark_std::marker::PhantomData;

pub mod data_structures;
pub mod setup;
pub mod commit;
pub mod open;
pub mod verify;

use ark_ec::{PairingEngine, ProjectiveCurve};

pub struct MLPolyCommit<E: PairingEngine> {
    #[doc(hidden)]
    _marker: PhantomData<E>,
}


