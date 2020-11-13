use ark_ec::{PairingEngine, ProjectiveCurve};
use crate::commitment::MLPolyCommit;
use rand::RngCore;
use crate::commitment::data_structures::{PublicParameter, EvaluationHyperCubeOnG1, EvaluationHyperCubeOnG2};
use ark_ff::UniformRand;
use crate::data_structures::eq::eq_extension;
use crate::error::SResult;
use linear_sumcheck::data_structures::ml_extension::MLExtension;
use ark_std::collections::LinkedList;
use ark_std::iter::FromIterator;

impl<E: PairingEngine> MLPolyCommit<E> {
    pub fn keygen<R: RngCore>(nv: usize, rng: &mut R) -> SResult<PublicParameter<E>> {
        let g: E::G1Projective = E::G1Projective::rand(rng);
        let h: E::G2Projective = E::G2Projective::rand(rng);
        let mut powers_of_g = Vec::new();
        let mut powers_of_h = Vec::new();
        let t: Vec<_> = (0..nv).map(|_|E::Fr::rand(rng)).collect();
        let mut eq = LinkedList::from_iter(eq_extension(&t)?);
        let mut base = eq.pop_front().unwrap().into_table()?;
        for k in 1 .. (nv+1) {
            let pp_k_g: EvaluationHyperCubeOnG1<E> = (0..(1<<k))
                .map(|x|g.mul(base[x]))
                .collect();
            let pp_k_h: EvaluationHyperCubeOnG2<E> = (0..(1<<k))
                .map(|x|h.mul(base[x]))
                .collect();
            powers_of_g.push(pp_k_g);
            powers_of_h.push(pp_k_h);
            if k != nv{
                let next_item: Vec<E::Fr> = eq.pop_front().unwrap().into_table()?;
                base = base.into_iter()
                    .zip(next_item.into_iter()).map(|(a, b)|{
                    a * &b
                }).collect();
            }
        }
        Ok(PublicParameter{
            g,
            h,
            powers_of_g,
            powers_of_h
        })
    }
}

#[cfg(test)]
mod tests{
    use rand::RngCore;
    use ark_ec::{PairingEngine, ProjectiveCurve};
    use crate::error::SResult;
    use crate::commitment::data_structures::{PublicParameter, EvaluationHyperCubeOnG1, EvaluationHyperCubeOnG2};
    use ark_ff::{UniformRand, test_rng};
    use ark_std::collections::LinkedList;
    use ark_std::iter::FromIterator;
    use crate::data_structures::eq::eq_extension;
    use linear_sumcheck::data_structures::ml_extension::{MLExtension, ArithmeticCombination};
    use crate::commitment::MLPolyCommit;
    use crate::test_utils::TestCurve;

    pub fn dummy_keygen<R: RngCore, E: PairingEngine>(nv: usize, rng: &mut R) -> SResult<PublicParameter<E>> {
        let g: E::G1Projective = E::G1Projective::rand(rng);
        let h: E::G2Projective = E::G2Projective::rand(rng);
        let mut powers_of_g = Vec::new();
        let mut powers_of_h = Vec::new();
        let t: Vec<_> = (0..nv).map(|_|E::Fr::rand(rng)).collect();
        for k in 1 .. (nv+1) {
            let ext = eq_extension(&t[0..k])?;
            let mut comb = ArithmeticCombination::new(k);
            comb.add_product(ext.into_iter())?;
            let pp_k_g: EvaluationHyperCubeOnG1<E> = (0..(1<<k)).map(|x|g.mul(comb.eval_binary_at(x).unwrap())).collect();
            let pp_k_h: EvaluationHyperCubeOnG2<E> = (0..(1<<k)).map(|x|h.mul(comb.eval_binary_at(x).unwrap())).collect();
            powers_of_g.push(pp_k_g);
            powers_of_h.push(pp_k_h);
        }
        Ok(PublicParameter{
            g,
            h,
            powers_of_g,
            powers_of_h
        })
    }

    #[test]
    fn setup_test() {
        let mut rng1 = test_rng();
        let mut rng2 = test_rng();
        type E = TestCurve;
        let pp_actual = MLPolyCommit::<E>::keygen(6, &mut rng1).unwrap();
        let pp_expected = dummy_keygen::<_, E>(6, &mut rng2).unwrap();

        assert!(pp_actual.g == pp_expected.g);
        assert!(pp_actual.h == pp_expected.h);
        assert!(pp_actual.powers_of_h.eq(&pp_expected.powers_of_h));
        assert!(pp_actual.powers_of_g.eq(&pp_expected.powers_of_g));
    }
}