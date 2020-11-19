use ark_ec::{PairingEngine, ProjectiveCurve};
use crate::commitment::MLPolyCommit;
use crate::commitment::data_structures::PublicParameter;
use linear_sumcheck::data_structures::MLExtensionArray;
use crate::error::SResult;
use linear_sumcheck::data_structures::ml_extension::MLExtension;
use ark_ff::{One, Zero, PrimeField};
use ark_ec::msm::VariableBaseMSM;

pub struct Proof<E: PairingEngine> {
    pub g: E::G1Projective,
    pub h: E::G2Projective,

    pub proofs: Vec<(E::G1Projective, E::G2Projective)>
}

impl<E: PairingEngine> MLPolyCommit<E> {
    // evaluate the polynomial and calculate the proof
    pub fn open(pp: &PublicParameter<E>,
                polynomial: MLExtensionArray<E::Fr>,
                point: &[E::Fr]) -> SResult<(E::Fr, Proof<E>, Vec<Vec<E::Fr>>)> {
        let eval_result = polynomial.eval_at(point)?;
        let nv = polynomial.num_variables()?;
        let mut r: Vec<Vec<E::Fr>> = (0..nv+1)
            .map(|_|Vec::new())
            .collect();
        let mut q: Vec<Vec<E::Fr>> = (0..nv+1)
            .map(|_|Vec::new())
            .collect();

        r[nv] = polynomial.into_table()?;

        let mut proofs = Vec::new();
        for k in (1..nv+1).rev() {
            let variable_index = nv - k;
            let point_at_k = point[variable_index];
            q[k] = (0..(1 << (k - 1))).map(|_|E::Fr::zero()).collect();
            r[k-1] = (0..(1 << (k - 1))).map(|_|E::Fr::zero()).collect();
            for b in 0..(1<<(k-1)) {
                q[k][b] = r[k][(b << 1) + 1] - &r[k][b << 1];
                r[k-1][b] = r[k][b << 1] * &(E::Fr::one() - &point_at_k) + &(r[k][(b << 1) + 1] * &point_at_k);
            }
            let scalars: Vec<_> = (0..(1 << k)).map(|x|q[k][x >> 1].into_repr())
                .collect();

            let g_base: Vec<_> = pp.powers_of_g[k - 1].iter()
                .map(|x|x.into_affine()).collect();
            let h_base: Vec<_> = pp.powers_of_h[k - 1].iter()
                .map(|x|x.into_affine()).collect();
            let pi_g = VariableBaseMSM::multi_scalar_mul(&g_base, &scalars);
            let pi_h = VariableBaseMSM::multi_scalar_mul(&h_base, &scalars);
            proofs.push((pi_g, pi_h));
        }

        Ok((eval_result, Proof{
            g: pp.g,
            h: pp.h,
            proofs
        }, q))
    }

}

