
use ark_std::marker::PhantomData;

use ark_ff::Field;

pub mod setup;

pub struct CommitmentScheme<F: Field> {
    #[doc(hidden)] _marker: PhantomData<F>
}




