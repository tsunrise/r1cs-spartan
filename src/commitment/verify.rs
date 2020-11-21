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
        assert_eq!(left, right);
        Ok(left == right)
    }
}

#[cfg(test)]
mod sanity {
    use ark_ff::{test_rng, One};
    use crate::commitment::MLPolyCommit;
    use crate::test_utils::TestCurve;
    use linear_sumcheck::data_structures::MLExtensionArray;
    use ark_ff::{UniformRand, Zero};
    use ark_ec::{PairingEngine, ProjectiveCurve};
    use linear_sumcheck::data_structures::ml_extension::MLExtension;
    use ark_ec::group::Group;

    type E = TestCurve;
    type Fr = <TestCurve as PairingEngine>::Fr;
    #[test]
    fn sanity(){
        let nv = 5;
        let mut rng1 = test_rng();
        let (pp, vp, s) = MLPolyCommit::<E>::keygen(nv, &mut rng1).unwrap();
        let poly =
            MLExtensionArray::from_vec((0..(1<<nv))
                .map(|_|Fr::rand(&mut rng1)).collect()).unwrap();
        let point: Vec<_> = (0..nv).map(|_|Fr::rand(&mut rng1)).collect();
        let com = MLPolyCommit::commit(&pp, poly.clone()).expect("cannot commit");
        let (ev, pf, q) = MLPolyCommit::open(&pp, poly.clone(), &point).expect("cannot open");
        {
            // test if q is correct
            let fx = poly.eval_at(&s).unwrap();
            let ft = poly.eval_at(&point).unwrap();
            let mut rhs = Fr::zero();
            let g = pp.g;
            let h = pp.h;
            let lhs_pair = E::pairing(com.g_product - g.mul(ft), h);
            let mut rhs_pair = <E as PairingEngine>::Fqk::one();
            for i in 0..nv {
                let k = nv - i;
                let q_i: Vec<_> = (0..(1 << k)).map(|a|q[k][a >> 1]).collect();
                let q_i = MLExtensionArray::from_vec(q_i).unwrap();
                rhs += (s[i] - point[i]) * q_i.eval_at(&s[i..]).unwrap();
                assert_eq!(h.mul(q_i.eval_at(&s[i..]).unwrap()), pf.proofs[i].1, "open error");
                rhs_pair *= E::pairing(g.mul(s[i] - point[i]), h.mul(q_i.eval_at(&s[i..]).unwrap()));
            }
            assert!(fx - ft == rhs); // hmm, q seems correct
            assert_eq!(lhs_pair, rhs_pair); // this one should also pass
        }


        let result = MLPolyCommit::verify(vp, com, &point, ev, pf).expect("cannot verify");
        assert!(result);
    }
}
