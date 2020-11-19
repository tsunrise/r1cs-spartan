use ark_ec::{PairingEngine, ProjectiveCurve};
use crate::commitment::MLPolyCommit;
use crate::commitment::commit::Commitment;
use crate::commitment::data_structures::VerifierParameter;
use crate::commitment::open::Proof;
use ark_ff::One;
use crate::error::SResult;


impl<E: PairingEngine> MLPolyCommit<E> {
    pub fn verify(vp: VerifierParameter<E>,commitment: Commitment<E>, point: &[E::Fr], eval: E::Fr, proof: Proof<E>)
    ->SResult<bool>{
        let left =
            E::pairing(commitment.g_product - &vp.g.mul(eval), vp.h);
        let mut right = E::Fqk::one();
        for i in 0 .. vp.nv {
            right *= &E::pairing(vp.g_mask_random[i] - &vp.g.mul(point[i]), proof.proofs[i].1);
        }
        Ok(left == right)
    }
}

#[cfg(test)]
mod sanity {
    use ark_ff::test_rng;
    use crate::commitment::MLPolyCommit;
    use crate::test_utils::TestCurve;
    use linear_sumcheck::data_structures::MLExtensionArray;
    use ark_ff::{UniformRand, One};
    use ark_ec::PairingEngine;
    use linear_sumcheck::data_structures::ml_extension::MLExtension;

    type E = TestCurve;
    type Fr = <TestCurve as PairingEngine>::Fr;
    #[test]
    fn sanity(){
        let nv = 5;
        let mut rng1 = test_rng();
        let (pp, vp, _) = MLPolyCommit::<E>::keygen(nv, &mut rng1).unwrap();
        let poly =
            MLExtensionArray::from_vec((0..(1<<nv))
                .map(|_|Fr::rand(&mut rng1)).collect()).unwrap();
        let point: Vec<_> = (0..nv).map(|_|Fr::rand(&mut rng1)).collect();
        let com = MLPolyCommit::commit(&pp, poly.clone()).expect("cannot commit");
        let (ev, pf, q) = MLPolyCommit::open(&pp, poly.clone(), &point).expect("cannot open");
        {
            // test if q is correct
            let rp: Vec<_> = (0..nv).map(|_|Fr::rand(&mut rng1)).collect();  // random point
            let fx = poly.eval_at(&rp).unwrap();
            let ft = poly.eval_at(&point).unwrap();
            let mut rhs = Fr::one();
            for i in 0..nv {
                let k = nv - i;
                let q_i: Vec<_> = (0..(1 << k)).map(|a|q[k][a >> 1]).collect();
                let q_i = MLExtensionArray::from_vec(q_i).unwrap();
                rhs += (rp[i] - point[i]) * q_i
                    .eval_at(&rp[i..]).unwrap();
            }
            assert!(fx - ft == rhs);
        }


        let result = MLPolyCommit::verify(vp, com, &point, ev, pf).expect("cannot verify");
        assert!(result);
    }
}
