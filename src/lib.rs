#[macro_use]
extern crate ark_relations;

/// module for interpret r1cs as ML Extension used by linear sumcheck
pub mod data_structures;

/// error package
mod error;
pub use error::Error;
use ark_ff::{Field, ToBytes};
use ark_std::marker::PhantomData;
use ark_relations::r1cs::{Matrix};
use crate::data_structures::proof::Proof;
use linear_sumcheck::data_structures::{Blake2s512Rng, MLExtensionArray};
use linear_sumcheck::data_structures::random::FeedableRNG;
use rand::RngCore;
use ark_std::io::{Write, Result as IOResult};
use crate::data_structures::eq::eq_extension;
use crate::data_structures::r1cs_reader::MatrixExtension;
use linear_sumcheck::ml_sumcheck::t13::T13Sumcheck;
use linear_sumcheck::ml_sumcheck::{MLSumcheck, MLSumcheckClaim};
use linear_sumcheck::data_structures::ml_extension::MLExtension;
use ark_std::rc::Rc;

/// testing utilities
#[cfg(test)]
pub(crate) mod test_utils;

pub struct Spartan<F: Field>(
    #[doc(hidden)] PhantomData<F>
);

pub struct SessionKey([u8; 512]);
impl ToBytes for SessionKey {
    fn write<W: Write>(&self, mut writer: W) -> IOResult<()> {
        writer.write(&self.0[..])?;
        Ok(())
    }
}

impl<F: Field> Spartan<F> {

    /// setup the protocol and generate the session key
    pub fn setup<R: RngCore>(rng: &mut R) -> SessionKey {
        let mut sk = SessionKey([0u8;512]);
        rng.fill_bytes(&mut sk.0);
        sk
    }

    /// Prove that the r1cs instance is satisfiable with witness w.
    ///
    /// * `matrix_a`: Matrix A
    /// * `matrix_b`: Matrix B
    /// * `matrix_c`: Matrix C
    /// * `v`: public witness
    /// * `w`: private witness
    /// * `sk`: session key that is setup by both prover and verifier
    /// * `verify_validity`: whether need to verify that the witness the true
    pub fn prove(sk: &SessionKey,
             matrix_a: Rc<Matrix<F>>,
             matrix_b: Rc<Matrix<F>>,
             matrix_c: Rc<Matrix<F>>,
             v: &[F],
             w: &[F],
             verify_validity: bool
    ) -> Result<Proof<F>, crate::Error> {

        // sanity check
        let n = v.len() + w.len();
        // for simplicity, this protocol assume width of matrix (n) is a power of 2.
        if !n.is_power_of_two() {
            return Err(crate::Error::InvalidArgument(Some("Matrix width should be a power of 2.".into())));
        }
        let log_n = ark_std::log2(n) as usize;

        // this one serves the randomness oracle
        let mut rng = Blake2s512Rng::setup();
        // set up the random generator by the matrix
        rng.feed(&sk)?;

        // multivariate polynomial commitment scheme on polynomial expressed by evaluation domains
        // has not been implemented yet. Ryan plans to implement it in next few months.
        // leave commit(w) as a todo

        rng.feed(&("replace this as commit(w)".as_bytes()))?;

        let z = MLExtensionArray::from_vec(
            v.iter()
                .chain(w.iter())
                .map(|x|*x)
                .collect())?;

        let matrix_a = MatrixExtension::new(matrix_a, n)?;
        let matrix_b = MatrixExtension::new(matrix_b, n)?;
        let matrix_c = MatrixExtension::new(matrix_c, n)?;

        let sum_az_over_y = matrix_a.sum_over_y(&z)?;
        let sum_bz_over_y = matrix_b.sum_over_y(&z)?;
        let sum_cz_over_y = matrix_c.sum_over_y(&z)?;

        let tor = Self::generate_tor(log_n, &mut rng);
        let eq = eq_extension(&tor)?;

        let mut g_zt_x_first = vec![sum_az_over_y.clone(), sum_bz_over_y.clone()];
        g_zt_x_first.extend(eq.iter().map(|mle|mle.clone()));
        let mut g_zt_x_second = vec![sum_cz_over_y.negate()?];
        g_zt_x_second.extend(eq.iter().map(|mle|mle.clone()));
        let g_zt_x = vec![&g_zt_x_first[..], &g_zt_x_second[..]];

        let iv = {
            let mut iv = vec![0u8; 256];
            rng.fill_bytes(&mut iv);
            iv
        };

        let (first_sumcheck_claim,
            first_sumcheck_proof,
            first_sumcheck_subclaim) = T13Sumcheck::generate_claim_and_proof(&iv , &g_zt_x)?;

        if verify_validity {
            // sanity check the claim
            if first_sumcheck_claim.asserted_sum() != F::zero() {
                // abort
                return Err(crate::Error::WrongWitness(Some("first sumcheck generated wrong claim".into())));
            }
        }

        // send verifier the claim and proof, verify use proof for Fiat Shamir Transform
        rng.feed_randomness(&first_sumcheck_proof)?;
        // prover got r_x from the subclaim
        let r_x = first_sumcheck_subclaim.fixed_arguments;

        let va = sum_az_over_y.eval_at(&r_x)?;
        let vb = sum_bz_over_y.eval_at(&r_x)?;
        let vc = sum_cz_over_y.eval_at(&r_x)?;

        // send va, vb, vc, and verifier feed randomness
        rng.feed_randomness(&vec![va, vb, vc])?;

        if verify_validity {
            let mut eq_rx = F::one();
            for p in eq.iter() {
                eq_rx *= p.eval_at(&r_x)?;
            }
            if (va * vb - vc) * eq_rx != first_sumcheck_subclaim.evaluation {
                return Err(crate::Error::WrongWitness(Some("first sumcheck has wrong subclaim".into())))
            }
        }

        // verifier send randomness r_a, r_b, r_c
        let r_a = F::rand(&mut rng);
        let r_b = F::rand(&mut rng);
        let r_c = F::rand(&mut rng);

        // sumcheck round 2

        let az_rx_on_y = [matrix_a.eval_on_x(&r_x)?.multiply(r_a)?, z.clone()];
        let bz_rx_on_y = [matrix_b.eval_on_x(&r_x)?.multiply(r_b)?, z.clone()];
        let cz_rx_on_y = [matrix_c.eval_on_x(&r_x)?.multiply(r_c)?, z.clone()];

        let round2_poly = vec![
            &az_rx_on_y[..],
            &bz_rx_on_y[..],
            &cz_rx_on_y[..]
        ];
        let iv_round2 = {
            let mut iv =  vec![0; 256];
            rng.fill_bytes(&mut iv);
            iv
        };
        let (r2claim, r2proof, r2subclaim) =
            T13Sumcheck::generate_claim_and_proof(&iv_round2, &round2_poly)?;
        let r_y = r2subclaim.fixed_arguments;

        if verify_validity {
            if r2claim.asserted_sum() != r_a * va + r_b * vb + r_c * vc {
                return Err(crate::Error::WrongWitness(Some("second sumcheck inconsistent assertion".into())));
            }
        }

        // no need to feed randomness, verifier does not send any further message

        // calculate z(r_y)
        let z_ry = z.eval_at(&r_y)?;
        // send z(r_y)


        if verify_validity {
            let expected = r2subclaim.evaluation;
            let actual =
                az_rx_on_y[0].eval_at(&r_y)? * z_ry
                + bz_rx_on_y[0].eval_at(&r_y)? * z_ry
                + cz_rx_on_y[0].eval_at(&r_y)? * z_ry
            ;
            if expected != actual {
                return Err(crate::Error::WrongWitness(Some("Cannot verify matrix A, B, C".into())))
            }
        }


        ;Ok(Proof{
            commit_w: (),

            first_sumcheck_proof,

            va,
            vb,
            vc,

            second_sumcheck_proof: r2proof,

            eval_z_at_ry: z_ry,
            proof_for_eval_z: (),

        })
    }

    fn generate_tor(log_n: usize, rng: &mut Blake2s512Rng) -> Vec<F> {
        (0..log_n).map(|_|F::rand(rng)).collect()
    }
}

#[cfg(test)]
mod test{
    use crate::data_structures::constraints::TestSynthesizer;
    use ark_relations::r1cs::{ConstraintSystemRef, ConstraintSystem, ConstraintSynthesizer, Variable};
    use ark_ff::test_rng;
    use crate::Spartan;
    use ark_std::rc::Rc;

    #[test]
    fn test_generate_proof() {
        type F = ark_test_curves::bls12_381::Fr;
        const SIZE_Z: usize = 32;
        let synthesizer = TestSynthesizer::<F>::new(SIZE_Z);
        let cs = ConstraintSystem::new_ref();
        cs.set_mode(ark_relations::r1cs::SynthesisMode::Prove {construct_matrices: true});

        // synthesize the r1cs constraint
        synthesizer.generate_constraints(cs.clone()).unwrap();


        let v: Vec<_> = (0..3).map(|x|cs.assigned_value(Variable::Instance(x)).unwrap()).collect();
        let w: Vec<_> = (0..(SIZE_Z)).map(|x|cs.assigned_value(Variable::Witness(x)).unwrap()).collect();

        let matrices = cs.to_matrices().unwrap();

        let mut rng = test_rng();
        let sk = Spartan::<F>::setup(&mut rng);
        let proof = Spartan::<F>::prove(
            &sk,
            Rc::new(matrices.a),
            Rc::new(matrices.b),
            Rc::new(matrices.c),
            &v,
            &w,
            true
        ).unwrap();






    }
}


