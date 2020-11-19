use ark_std::marker::PhantomData;

pub mod data_structures;
pub mod setup;
pub mod commit;
pub mod open;
pub mod verify;

use ark_ec::{PairingEngine, AffineCurve, ProjectiveCurve};
use ark_ff::Field;

pub struct MLPolyCommit<E: PairingEngine> {
    #[doc(hidden)]
    _marker: PhantomData<E>,
}

impl<E: PairingEngine> MLPolyCommit<E> {
    fn test(g1: E::G1Affine, g2: E::G2Affine, x: E::Fr) {
        let y = g1.mul(x);

        let z = g2.mul(x);
        let p = E::pairing(y,z);
        let p2 = E::pairing(y.mul(x), z.mul(x));
        let p3: E::Fqk = p2 * &p2;
        if p == p2 {

        }


    }
}
