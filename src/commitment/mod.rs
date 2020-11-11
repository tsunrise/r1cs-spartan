use ark_std::marker::PhantomData;

use ark_ec::PairingEngine;

pub struct CommitmentScheme<E: PairingEngine> {
    #[doc(hidden)]
    _marker: PhantomData<E>,
}
