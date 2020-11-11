#[macro_use]
#[allow(unused_imports)]
extern crate ark_relations;

#[cfg(test)]
#[macro_use]
extern crate bench_utils;

use ark_std::marker::PhantomData;

pub mod ahp;

#[cfg(test)]
mod benchmark;

pub mod commitment;

use crate::ahp::indexer::{IndexPK, IndexVK};
use crate::ahp::AHPForSpartan;
use crate::data_structures::proof::Proof;
use crate::error::{invalid_arg, SResult};
use ark_ec::PairingEngine;
use ark_relations::r1cs::Matrix;
use ark_std::collections::LinkedList;
use ark_std::iter::FromIterator;
use ark_std::log2;
pub use error::Error;
use linear_sumcheck::data_structures::random::FeedableRNG;
use linear_sumcheck::data_structures::Blake2s512Rng;
use linear_sumcheck::ml_sumcheck::ahp::prover::ProverMsg;

/// module for interpret r1cs as ML Extension used by linear sumcheck
pub mod data_structures;

/// error package
mod error;
/// testing utilities
#[cfg(test)]
pub(crate) mod test_utils;

pub struct Spartan<E: PairingEngine>(#[doc(hidden)] PhantomData<E>);

//todo: change to MLArgumentForR1CS
impl<E: PairingEngine> Spartan<E> {
    /// generate prover key and verifier key
    pub fn index(
        matrix_a: Matrix<E::Fr>,
        matrix_b: Matrix<E::Fr>,
        matrix_c: Matrix<E::Fr>,
    ) -> Result<IndexPK<E::Fr>, crate::Error> {
        AHPForSpartan::<E>::index(matrix_a, matrix_b, matrix_c)
    }

    /// prove the circuit, giving the index
    /// * `pk`: prover key
    /// * `v`: public input
    /// * `w`: private input
    pub fn prove(pk: IndexPK<E::Fr>, v: Vec<E::Fr>, w: Vec<E::Fr>) -> SResult<Proof<E>> {
        let log_n = pk.log_n;

        let mut fs_rng = Blake2s512Rng::setup();
        fs_rng.feed_randomness(&pk.matrix_a)?;
        fs_rng.feed_randomness(&pk.matrix_b)?;
        fs_rng.feed_randomness(&pk.matrix_c)?;
        fs_rng.feed_randomness(&v)?;

        let log_v = log2(v.len()) as usize;

        let ps = AHPForSpartan::prover_init(pk, v, w)?;

        let (ps, pm1) = AHPForSpartan::prover_first_round(ps)?;
        fs_rng.feed_randomness(&pm1)?;
        let vm = AHPForSpartan::<E>::sample_first_round(log_v, &mut fs_rng);

        let (ps, pm2) = AHPForSpartan::prover_second_round(ps, vm)?;
        fs_rng.feed_randomness(&pm2)?;
        let vm = AHPForSpartan::<E>::simulate_verify_second_round(&ps.pk, &mut fs_rng);

        let (mut ps, pm3) = AHPForSpartan::prover_third_round(ps, vm)?;
        fs_rng.feed_randomness(&pm3)?;
        let mut vm = AHPForSpartan::<E>::simulate_verify_third_round();

        let mut sumcheck1_msgs = Vec::with_capacity(log_n);
        for _ in 0..(log_n - 1) {
            let (ps_new, pm) = AHPForSpartan::prove_first_sumcheck_round(ps, vm)?;
            ps = ps_new;
            fs_rng.feed_randomness(&pm)?;
            sumcheck1_msgs.push(pm);
            vm = AHPForSpartan::<E>::simulate_verify_first_sumcheck_ongoing_round(&mut fs_rng);
        }

        let (ps, pm) = AHPForSpartan::prove_first_sumcheck_round(ps, vm)?;
        fs_rng.feed_randomness(&pm)?;
        sumcheck1_msgs.push(pm);
        let vm = AHPForSpartan::<E>::simulate_verify_first_sumcheck_final_round(&mut fs_rng);

        let (ps, pm4) = AHPForSpartan::prove_fourth_round(ps, vm)?;
        fs_rng.feed_randomness(&pm4)?;
        let vm = AHPForSpartan::<E>::simulate_verify_fourth_round(&mut fs_rng);

        let (mut ps, pm5) = AHPForSpartan::prove_fifth_round(ps, vm)?;
        fs_rng.feed_randomness(&pm5)?;
        let mut vm = AHPForSpartan::<E>::simulate_verify_fifth_round();

        let mut sumcheck2_msgs = Vec::with_capacity(log_n);
        for _ in 0..(log_n - 1) {
            let (ps_new, pm) = AHPForSpartan::prove_second_sumcheck_round(ps, vm)?;
            ps = ps_new;
            fs_rng.feed_randomness(&pm)?;
            sumcheck2_msgs.push(pm);
            vm = AHPForSpartan::<E>::simulate_verify_second_sumcheck_ongoing_round(&mut fs_rng);
        }

        let (ps, pm) = AHPForSpartan::prove_second_sumcheck_round(ps, vm)?;
        fs_rng.feed_randomness(&pm)?;
        sumcheck2_msgs.push(pm);
        let vm = AHPForSpartan::<E>::simulate_verify_second_sumcheck_final_round(&mut fs_rng);

        let pm6 = AHPForSpartan::prove_sixth_round(ps, vm)?;

        Ok(Proof {
            prover_first_message: pm1,
            prover_second_message: pm2,
            prover_third_message: pm3,
            first_sumcheck_messages: sumcheck1_msgs,
            prover_fourth_message: pm4,
            prover_fifth_message: pm5,
            second_sumcheck_messages: sumcheck2_msgs,
            prover_sixth_message: pm6,
        })
    }
    pub fn verify(vk: IndexVK<E::Fr>, v: Vec<E::Fr>, proof: Proof<E>) -> SResult<bool> {
        let log_n = vk.log_n;
        let mut first_sumcheck_messages =
            LinkedList::from_iter(proof.first_sumcheck_messages.into_iter());
        let mut second_sumcheck_messages =
            LinkedList::from_iter(proof.second_sumcheck_messages.into_iter());

        let mut fs_rng = Blake2s512Rng::setup();
        fs_rng.feed_randomness(&vk.matrix_a)?;
        fs_rng.feed_randomness(&vk.matrix_b)?;
        fs_rng.feed_randomness(&vk.matrix_c)?;
        fs_rng.feed_randomness(&v)?;

        let vs = AHPForSpartan::<E>::verifier_init(vk, v)?;

        let pm = proof.prover_first_message;
        fs_rng.feed_randomness(&pm)?;
        let (vs, _) = AHPForSpartan::verify_first_round(vs, pm, &mut fs_rng)?;

        let pm = proof.prover_second_message;
        fs_rng.feed_randomness(&pm)?;
        let (vs, _) = AHPForSpartan::verify_second_round(vs, pm, &mut fs_rng)?;

        let pm = proof.prover_third_message;
        fs_rng.feed_randomness(&pm)?;
        let (mut vs, _) = AHPForSpartan::verify_third_round(vs, pm)?;

        for _ in 0..(log_n - 1) {
            let pm = Self::try_pop(&mut first_sumcheck_messages)?;
            fs_rng.feed_randomness(&pm)?;
            let (vs_new, _) =
                AHPForSpartan::verify_first_sumcheck_ongoing_round(vs, pm, &mut fs_rng)?;
            vs = vs_new;
        }

        let pm = Self::try_pop(&mut first_sumcheck_messages)?;
        fs_rng.feed_randomness(&pm)?;
        let (vs, _) = AHPForSpartan::verify_first_sumcheck_final_round(vs, pm, &mut fs_rng)?;

        let pm = proof.prover_fourth_message;
        fs_rng.feed_randomness(&pm)?;
        let (vs, _) = AHPForSpartan::verify_fourth_round(vs, pm, &mut fs_rng)?;

        let pm = proof.prover_fifth_message;
        fs_rng.feed_randomness(&pm)?;
        let (mut vs, _) = AHPForSpartan::verify_fifth_round(vs, pm)?;

        for _ in 0..(log_n - 1) {
            let pm = Self::try_pop(&mut second_sumcheck_messages)?;
            fs_rng.feed_randomness(&pm)?;
            let (vs_new, _) =
                AHPForSpartan::verify_second_sumcheck_ongoing_round(vs, pm, &mut fs_rng)?;
            vs = vs_new;
        }

        let pm = Self::try_pop(&mut second_sumcheck_messages)?;
        fs_rng.feed_randomness(&pm)?;
        let (vs, _) = AHPForSpartan::verify_second_sumcheck_final_round(vs, pm, &mut fs_rng)?;

        let pm = proof.prover_sixth_message;
        fs_rng.feed_randomness(&pm)?;

        let result = AHPForSpartan::verify_sixth_round(vs, pm)?;

        Ok(result)
    }

    fn try_pop(sumcheck_messages: &mut LinkedList<ProverMsg<E::Fr>>) -> SResult<ProverMsg<E::Fr>> {
        sumcheck_messages
            .pop_front()
            .ok_or(invalid_arg("malformed sumcheck message"))
    }
}
