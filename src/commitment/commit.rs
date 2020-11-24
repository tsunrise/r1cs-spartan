use ark_ec::{PairingEngine, ProjectiveCurve};
use crate::commitment::MLPolyCommit;
use crate::commitment::data_structures::PublicParameter;
use crate::error::SResult;
use linear_sumcheck::data_structures::MLExtensionArray;
use linear_sumcheck::data_structures::ml_extension::MLExtension;
use ark_ec::msm::VariableBaseMSM;
use ark_ff::PrimeField;

pub struct Commitment<E: PairingEngine>{
    pub nv: usize,
    pub g_product: E::G1Projective,
}

impl<E: PairingEngine> MLPolyCommit<E> {
    pub fn commit(pp: &PublicParameter<E>, polynomial: MLExtensionArray<E::Fr>) -> SResult<Commitment<E>> {
        let nv = polynomial.num_variables()?;
        let scalars: Vec<_> = polynomial.into_table()?
            .into_iter().map(|x|x.into_repr()).collect();
        let g_bases: Vec<_> = E::G1Projective::batch_normalization_into_affine(&pp.powers_of_g[0]);
        let g_product: E::G1Projective = VariableBaseMSM::multi_scalar_mul(&g_bases, scalars.as_slice());
        
        Ok(Commitment{nv, g_product})
    }
}

#[cfg(test)]
mod test{
    use crate::commitment::data_structures::PublicParameter;
    use linear_sumcheck::data_structures::MLExtensionArray;
    use crate::error::SResult;
    use crate::commitment::commit::Commitment;
    use crate::test_utils::TestCurve;
    use ark_ec::{PairingEngine, ProjectiveCurve};
    use linear_sumcheck::data_structures::ml_extension::MLExtension;
    use ark_ff::{test_rng, UniformRand};
    use crate::commitment::MLPolyCommit;

    type E = TestCurve;
    type Fr = <E as PairingEngine>::Fr;

    fn naive_commit(pp: &PublicParameter<E>, polynomial: MLExtensionArray<Fr>, rand_t: &[Fr]) -> SResult<Commitment<E>> {
        let nv = polynomial.num_variables()?;
        let g_product = pp.g.mul(polynomial.eval_at(rand_t)?);
        Ok(Commitment{nv, g_product})
    }
    #[test]
    fn commit_test(){
        let mut rng = test_rng();
        let (pp, _, t) = MLPolyCommit::<E>::keygen(4, &mut rng).unwrap();
        let mut rng = test_rng();
        let poly =
            MLExtensionArray::from_vec((0..(1<<4))
                .map(|_|Fr::rand(&mut rng)).collect()).unwrap();
        let commit_expected = naive_commit(&pp, poly.clone(), &t).unwrap();
        let commit_actual = MLPolyCommit::commit(&pp, poly.clone()).unwrap();

        assert_eq!(commit_actual.g_product, commit_expected.g_product);

    }
}