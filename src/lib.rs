#[macro_use]
#[allow(unused_imports)]
extern crate ark_relations;

#[cfg(test)]
#[macro_use]
extern crate bench_utils;

use ark_ff::{Field};
use ark_std::marker::PhantomData;

pub mod ahp;

pub use error::Error;
use ark_relations::r1cs::Matrix;
use crate::ahp::indexer::IndexPK;
use crate::ahp::AHPForSpartan;
use crate::error::SResult;
use crate::data_structures::proof::Proof;
use linear_sumcheck::data_structures::Blake2s512Rng;
use linear_sumcheck::data_structures::random::FeedableRNG;

/// module for interpret r1cs as ML Extension used by linear sumcheck
pub mod data_structures;

/// error package
mod error;
/// testing utilities
#[cfg(test)]
pub(crate) mod test_utils;

pub struct Spartan<F: Field>(
    #[doc(hidden)] PhantomData<F>
);

impl<F: Field> Spartan<F> {
    /// generate prover key and verifier key
    pub fn index(matrix_a: Matrix<F>,
                 matrix_b: Matrix<F>,
                 matrix_c: Matrix<F>, v: Vec<F>, w: Vec<F>) -> Result<IndexPK<F>, crate::Error> {
        AHPForSpartan::index(matrix_a, matrix_b, matrix_c, v, w)
    }

    /// prove the circuit, giving the index
    pub fn prove(pk: IndexPK<F>) -> SResult<Proof<F>> {
        let log_n = pk.log_n;

        let mut fs_rng = Blake2s512Rng::setup();
        fs_rng.feed_randomness(&pk.matrix_a)?;
        fs_rng.feed_randomness(&pk.matrix_b)?;
        fs_rng.feed_randomness(&pk.matrix_c)?;
        fs_rng.feed_randomness(&pk.v)?;

        let ps = AHPForSpartan::prover_init(pk);

        let (ps, pm1) = AHPForSpartan::prover_first_round(ps)?;
        fs_rng.feed_randomness(&pm1)?;
        let vm = AHPForSpartan::simulate_verify_first_round(&ps.pk, &mut fs_rng);

        let (ps, pm2) = AHPForSpartan::prover_second_round(ps, vm)?;
        fs_rng.feed_randomness(&pm2)?;
        let vm = AHPForSpartan::simulate_verify_second_round(&ps.pk, &mut fs_rng);

        let (mut ps, pm3) = AHPForSpartan::prover_third_round(ps, vm)?;
        fs_rng.feed_randomness(&pm3)?;
        let mut vm = AHPForSpartan::simulate_verify_third_round();

        let mut sumcheck1_msgs = Vec::with_capacity(log_n);
        for _ in 0..(log_n - 1) {
            let (ps_new, pm) = AHPForSpartan::prove_first_sumcheck_round(ps, vm)?;
            ps = ps_new;
            fs_rng.feed_randomness(&pm)?;
            sumcheck1_msgs.push(pm);
            vm = AHPForSpartan::simulate_verify_first_sumcheck_ongoing_round(&mut fs_rng);
        }

        let (ps, pm) = AHPForSpartan::prove_first_sumcheck_round(ps, vm)?;
        fs_rng.feed_randomness(&pm)?;
        sumcheck1_msgs.push(pm);
        let vm = AHPForSpartan::simulate_verify_first_sumcheck_final_round(&mut fs_rng);

        let (ps, pm4) = AHPForSpartan::prove_fourth_round(ps, vm)?;
        fs_rng.feed_randomness(&pm4)?;
        let vm = AHPForSpartan::simulate_verify_fourth_round(&mut fs_rng);

        let (mut ps, pm5) = AHPForSpartan::prove_fifth_round(ps, vm)?;
        fs_rng.feed_randomness(&pm5)?;
        let mut vm = AHPForSpartan::simulate_verify_fifth_round();

        let mut sumcheck2_msgs = Vec::with_capacity(log_n);
        for _ in 0..(log_n - 1) {
            let (ps_new, pm) = AHPForSpartan::prove_second_sumcheck_round(ps, vm)?;
            ps = ps_new;
            fs_rng.feed_randomness(&pm)?;
            sumcheck2_msgs.push(pm);
            vm = AHPForSpartan::simulate_verify_second_sumcheck_ongoing_round(&mut fs_rng);
        }

        let (ps, pm) = AHPForSpartan::prove_second_sumcheck_round(ps, vm)?;
        fs_rng.feed_randomness(&pm)?;
        sumcheck2_msgs.push(pm);
        let vm = AHPForSpartan::simulate_verify_second_sumcheck_final_round(&mut fs_rng);

        let pm6 = AHPForSpartan::prove_sixth_round(ps, vm)?;

        Ok(Proof{
            prover_first_message: pm1,
            prover_second_message: pm2,
            prover_third_message: pm3,
            first_sumcheck_messages: sumcheck1_msgs,
            prover_fourth_message: pm4,
            prover_fifth_message: pm5,
            second_sumcheck_messages: sumcheck2_msgs,
            prover_sixth_message: pm6
        })


    }
    // pub fn
}





