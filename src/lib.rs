/// module for interpret r1cs as ML Extension used by linear sumcheck
pub mod data_structures;

/// error package
mod error;
pub use error::Error;
use algebra_core::{Field, ToBytes};
use ark_std::marker::PhantomData;
use r1cs_core::{Matrix, Rc};
use crate::data_structures::proof::Proof;
use linear_sumcheck::data_structures::{Blake2s512Rng, MLExtensionArray};
use linear_sumcheck::data_structures::random::FeedableRNG;
use rand::RngCore;
use ark_std::io::{Write, Result as IOResult};
use crate::data_structures::eq::eq_extension;
use crate::data_structures::r1cs_reader::MatrixExtension;
use linear_sumcheck::ml_sumcheck::t13::T13Sumcheck;
use linear_sumcheck::ml_sumcheck::{MLSumcheck, MLSumcheckClaim};

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
    pub fn prove(sk: &SessionKey,
             matrix_a: Rc<Matrix<F>>,
             matrix_b: Rc<Matrix<F>>,
             matrix_c: Rc<Matrix<F>>,
             v: &[F],
             w: &[F],
    ) -> Result<Proof<F>, crate::Error> {

        // sanity check
        let n = v.len() + w.len();
        // for now, we have to assume size of public witness and private witness are same
        // this assumption is also mentioned in Spartan paper.
        // we need to release this constraint in the future, so add this as todo
        if v.len() != w.len() {
            return Err(crate::Error::InvalidArgument(Some("|v| != |w|".into())));
        }
        // for simplicity, this protocol assume width of matrix (n) is a power of 2.
        if !n.is_power_of_two() {
            return Err(crate::Error::InvalidArgument(Some("Matrix width should be a power of 2.".into())));
        }
        let log_n = algebra_core::log2(n) as usize;

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

        let mut g_zt_x_first = vec![sum_az_over_y, sum_bz_over_y];
        g_zt_x_first.extend(eq.iter().map(|mle|mle.clone()));
        let mut g_zt_x_second = vec![sum_cz_over_y.negate()?];
        g_zt_x_second.extend(eq.iter().map(|mle|mle.clone()));
        let g_zt_x = vec![&g_zt_x_first[..], &g_zt_x_second[..]];

        let (first_sumcheck_claim, first_sumcheck_proof) = T13Sumcheck::generate_claim_and_proof(&g_zt_x)?;
        // sanity check the claim
        if first_sumcheck_claim.asserted_sum() != F::zero() {
            // abort
            return Err(crate::Error::WrongWitness);
        }

        // send verifier the claim and proof
        rng.feed_randomness(&first_sumcheck_claim)?;
        rng.feed_randomness(&first_sumcheck_proof)?;
        // prover got r_x
        let r_x: Vec<_> = (0..log_n).map(|_|F::rand(&mut rng)).collect();




        ;Ok(Proof{
            commit_w: (),

            first_sumcheck_proof: todo!(),

            va: todo!(),
            vb: todo!(),
            vc: todo!(),

            second_sumcheck_proof: todo!(),

            eval_w_at_ry: todo!(),
            proof_for_eval_w: (),

        })
    }

    fn generate_tor(log_n: usize, rng: &mut Blake2s512Rng) -> Vec<F> {
        (0..log_n).map(|_|F::rand(rng)).collect()
    }
}


