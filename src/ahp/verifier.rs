use ark_ff::Field;
use linear_sumcheck::data_structures::ml_extension::MLExtension;
use linear_sumcheck::data_structures::MLExtensionArray;
use rand::RngCore;

use crate::ahp::AHPForSpartan;
use crate::ahp::indexer::{IndexVK, IndexPK};
use crate::ahp::prover::{ProverFirstMessage, ProverSecondMessage, ProverThirdMessage, ProverFourthMessage, ProverFifthMessage, ProverFinalMessage};
use crate::data_structures::eq::eq_extension;
use crate::error::{invalid_arg, SResult};
use linear_sumcheck::ml_sumcheck::ahp::verifier::{VerifierState as MLVerifierState, SubClaim as MLSubclaim};
use linear_sumcheck::ml_sumcheck::ahp::verifier::VerifierMsg as MLVerifierMsg;
use linear_sumcheck::ml_sumcheck::ahp::prover::ProverMsg as MLProverMsg;
use linear_sumcheck::ml_sumcheck::ahp::AHPForMLSumcheck;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, SerializationError, Read, Write};

/// r_v: randomness
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierFirstMessage<F: Field> {
    pub r_v: Vec<F>
}

/// random tor
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierSecondMessage<F: Field> {
    pub tor: Vec<F>
}

/// the last randomness for MLSumcheck
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierThirdMessage<F: Field> {
    pub last_random_point: F
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierFourthMessage<F: Field> {
    pub r_a: F,
    pub r_b: F,
    pub r_c: F,
}

/// the last randomness for second MLSumcheck
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierFifthMessage<F: Field> {
    pub last_random_point: F
}

pub struct VerifierFirstState<F: Field> {
    pub vk: IndexVK<F>
}

pub struct VerifierSecondState<F: Field> {
    pub vk: IndexVK<F>,
    pub r_v: Vec<F>,
    pub commit: Vec<u8>, // todo: replace this with real commitment
}

pub struct VerifierThirdState<F: Field> {
    pub vk: IndexVK<F>,
    pub commit: Vec<u8>,
    pub eq: Vec<MLExtensionArray<F>>,
}

/// first sumcheck state
pub struct VerifierFirstSumcheckState<F: Field> {
    pub vk: IndexVK<F>,
    pub commit: Vec<u8>,
    pub eq: Vec<MLExtensionArray<F>>,
    pub ml_verifier: MLVerifierState<F>
}

pub struct VerifierFourthState<F: Field> {
    pub vk: IndexVK<F>,
    pub commit: Vec<u8>,
    pub eq: Vec<MLExtensionArray<F>>,
    pub first_subclaim: MLSubclaim<F>
}

pub struct VerifierFifthState<F: Field> {
    pub vk: IndexVK<F>,
    pub commit: Vec<u8>,
    pub r_a: F,
    pub r_b: F,
    pub r_c: F,
    pub va: F,
    pub vb: F,
    pub vc: F,
    pub r_x: Vec<F>,
}

pub struct VerifierSecondSumcheckState<F: Field> {
    pub vk: IndexVK<F>,
    pub commit: Vec<u8>,
    pub r_a: F,
    pub r_b: F,
    pub r_c: F,
    pub ml_verifier: MLVerifierState<F>,
    pub r_x: Vec<F>,
}

pub struct VerifierSixthState<F: Field> {
    pub vk: IndexVK<F>,
    pub commit: Vec<u8>,
    pub r_a: F,
    pub r_b: F,
    pub r_c: F,
    pub second_subclaim: MLSubclaim<F>,
    pub r_x: Vec<F>
}

impl<F: Field> AHPForSpartan<F> {
    pub fn verifier_init(vk: IndexVK<F>) -> VerifierFirstState<F> {
        VerifierFirstState { vk }
    }

    /// receive commitment, generate r_v
    pub fn verify_first_round<R: RngCore>(state: VerifierFirstState<F>,
                                          p_msg: ProverFirstMessage, rng: &mut R) ->
                                            SResult<(VerifierSecondState<F>, VerifierFirstMessage<F>)> {
        let commit = p_msg.commitment;
        let vk = state.vk;
        let r_v: Vec<_> = (0..vk.log_v).map(|_| F::rand(rng)).collect();

        let msg = VerifierFirstMessage {
            r_v: r_v.clone()
        };
        let next_state = VerifierSecondState { vk, commit, r_v };
        Ok((next_state, msg))
    }

    pub fn simulate_verify_first_round<R: RngCore>(pk: &IndexPK<F>, rng: &mut R) -> VerifierFirstMessage<F> {
        let r_v: Vec<_> = (0..pk.log_v).map(|_| F::rand(rng)).collect();
        VerifierFirstMessage { r_v }
    }

    /// verify of z_rv_0 is correct, and send random tor
    pub fn verify_second_round<R: RngCore>(state: VerifierSecondState<F>,
                                           p_msg: ProverSecondMessage<F>,
                                           rng: &mut R) -> SResult<(VerifierThirdState<F>,
                                                                      VerifierSecondMessage<F>)> {
        let z_rv_0 = p_msg.z_rv_0;
        // todo: verify z_rv_0 is correct using proof

        let vk = state.vk;
        let v = MLExtensionArray::from_slice(&vk.v)?;
        if v.eval_at(&state.r_v)? != z_rv_0 {
            return Err(invalid_arg("public witness is inconsistent with proof"));
        }

        let tor: Vec<_> = (0..vk.log_n).map(|_| F::rand(rng)).collect();
        let eq = eq_extension(&tor)?;

        let msg = VerifierSecondMessage {
            tor: tor.clone()
        };
        let state = VerifierThirdState {
            vk,
            commit: state.commit,
            eq,
        };
        Ok((state, msg))
    }

    pub fn simulate_verify_second_round<R: RngCore>(pk: &IndexPK<F>, rng: &mut R) -> VerifierSecondMessage<F> {
        let tor: Vec<_> = (0..pk.log_n).map(|_| F::rand(rng)).collect();
        VerifierSecondMessage { tor }
    }

    /// initial first sumcheck verifier
    pub fn verify_third_round(state: VerifierThirdState<F>, p_msg: ProverThirdMessage)
                              -> SResult<(VerifierFirstSumcheckState<F>, Option<MLVerifierMsg<F>>)> {
        let index_info = p_msg.ml_index_info;
        // sanity check the index info
        if index_info.num_variables != state.vk.log_n {
            return Err(invalid_arg("invalid sumcheck proposal"));
        };
        let ml_verifier = AHPForMLSumcheck::verifier_init(&index_info, F::zero());
        let next_state = VerifierFirstSumcheckState {
            vk: state.vk,
            commit: state.commit,
            eq: state.eq,
            ml_verifier
        };

        Ok((next_state, None))
    }

    #[inline]
    pub fn simulate_verify_third_round() -> Option<MLVerifierMsg<F>> {
        None
    }

    /// sumcheck round except for last round
    pub fn verify_first_sumcheck_ongoing_round<R: RngCore>(state: VerifierFirstSumcheckState<F>, p_msg: MLProverMsg<F>, rng: &mut R)
                                                           ->SResult<(VerifierFirstSumcheckState<F>, Option<MLVerifierMsg<F>>)> {
        let (v_msg, ml_verifier) = AHPForMLSumcheck::verify_round(&p_msg, state.ml_verifier, rng)?;
        let next_state = VerifierFirstSumcheckState {ml_verifier, eq: state.eq, commit: state.commit, vk: state.vk};
        Ok((next_state, v_msg))
    }

    pub fn simulate_verify_first_sumcheck_ongoing_round<R: RngCore>(rng: &mut R) -> Option<MLVerifierMsg<F>> {
        Some(AHPForMLSumcheck::random_oracle_round(rng))
    }
    /// last round of first sumcheck verifier. send last randomness to prover.
    ///
    /// message produced by this round will be received by prover's round_tail function
    pub fn verify_first_sumcheck_final_round<R: RngCore>(state: VerifierFirstSumcheckState<F>, p_msg: MLProverMsg<F>, rng: &mut R)
                                                         -> SResult<(VerifierFourthState<F>, VerifierThirdMessage<F>)> {
        let (ml_msg, ml_verifier) = AHPForMLSumcheck::verify_round(&p_msg, state.ml_verifier, rng)?;
        let subclaim = AHPForMLSumcheck::subclaim(ml_verifier)?;
        let final_randomness = ml_msg.unwrap().randomness;
        let msg = VerifierThirdMessage{last_random_point: final_randomness};
        let next_state = VerifierFourthState {
            vk: state.vk,
            commit: state.commit,
            eq: state.eq,
            first_subclaim: subclaim
        };
        Ok((next_state, msg))

    }

    pub fn simulate_verify_first_sumcheck_final_round<R: RngCore>(rng: &mut R) -> VerifierThirdMessage<F> {
        VerifierThirdMessage{
            last_random_point: AHPForMLSumcheck::random_oracle_round(rng).randomness
        }
    }

    /// receive va, rb, vc, and sample ra, rb, rc for next sumcheck
    pub fn verify_fourth_round<R: RngCore>(state: VerifierFourthState<F>,
                                           p_msg: ProverFourthMessage<F>,
                                           rng: &mut R)
                                           -> SResult<(VerifierFifthState<F>, VerifierFourthMessage<F>)> {
        let (va, vb, vc) = (p_msg.va, p_msg.vb, p_msg.vc);
        // verify subclaim
        let first_subclaim = state.first_subclaim;
        let r_x = first_subclaim.point;
        {
            let eq = state.eq;
            let mut eq_rx = F::one();
            for p in eq.iter() {
                eq_rx *= p.eval_at(&r_x)?;
            }
            if (va * vb - vc) * eq_rx != first_subclaim.expected_evaluation {
                return Err(crate::Error::WrongWitness(Some("first sumcheck has wrong subclaim".into())))
            }
        }

        let r_a = F::rand(rng);
        let r_b = F::rand(rng);
        let r_c = F::rand(rng);

        let next_state = VerifierFifthState {
            commit: state.commit,
            vk: state.vk,
            r_a,r_b,r_c,va,vb,vc,r_x
        };

        let msg = VerifierFourthMessage{
            r_a, r_b, r_c
        };

        Ok((next_state, msg))
    }

    pub fn simulate_verify_fourth_round<R: RngCore>(rng: &mut R) -> VerifierFourthMessage<F> {
        VerifierFourthMessage{
            r_a: F::rand(rng),
            r_b: F::rand(rng),
            r_c: F::rand(rng)
        }
    }

    /// start second linear sumcheck
    pub fn verify_fifth_round(state: VerifierFifthState<F>, p_msg: ProverFifthMessage)
                              -> SResult<(VerifierSecondSumcheckState<F>, Option<MLVerifierMsg<F>>)> {
        let index_info = p_msg.index_info;
        // sanity check the index info
        if index_info.num_variables != state.vk.log_n {
            return Err(invalid_arg("invalid sumcheck proposal"));
        };
        let claimed_sum = state.r_a * state.va + state.r_b * state.vb + state.r_c * state.vc;
        let ml_verifier = AHPForMLSumcheck::verifier_init(&index_info, claimed_sum);

        let next_state = VerifierSecondSumcheckState {
            vk: state.vk,
            commit: state.commit,
            r_a: state.r_a,
            r_b: state.r_b,
            r_c: state.r_c,
            ml_verifier,
            r_x: state.r_x
        };

        Ok((next_state, None))
    }

    pub fn simulate_verify_fifth_round() -> Option<MLVerifierMsg<F>> {
        None
    }
    /// doing second sumcheck except for last round
    pub fn verify_second_sumcheck_ongoing_round<R: RngCore>(state: VerifierSecondSumcheckState<F>, p_msg: MLProverMsg<F>, rng: &mut R)
                                                            -> SResult<(VerifierSecondSumcheckState<F>, Option<MLVerifierMsg<F>>)> {
        let (v_msg, ml_verifier) = AHPForMLSumcheck::verify_round(&p_msg, state.ml_verifier, rng)?;
        let next_state = VerifierSecondSumcheckState {
            vk: state.vk,
            commit: state.commit,
            r_a: state.r_a,
            r_b: state.r_b,
            r_c: state.r_c,
            ml_verifier,
            r_x: state.r_x
        };
        Ok((next_state, v_msg))
    }
    #[inline]
    pub fn simulate_verify_second_sumcheck_ongoing_round<R: RngCore>(rng: &mut R) -> Option<MLVerifierMsg<F>> {
        Self::simulate_verify_first_sumcheck_ongoing_round(rng)
    }

    /// last round of sumcheck, send final randomness
    pub fn verify_second_sumcheck_final_round<R: RngCore>(state: VerifierSecondSumcheckState<F>, p_msg: MLProverMsg<F>, rng: &mut R)
                                                          -> SResult<(VerifierSixthState<F>, VerifierFifthMessage<F>)> {
        let (_, ml_verifier) = AHPForMLSumcheck::verify_round(&p_msg, state.ml_verifier, rng)?;
        let subclaim = AHPForMLSumcheck::subclaim(ml_verifier)?;
        let final_randomness = *subclaim.point.last().unwrap();
        let next_state = VerifierSixthState {
            vk: state.vk,
            commit: state.commit,
            r_a: state.r_a,
            r_b: state.r_b,
            r_c: state.r_c,
            second_subclaim: subclaim,
            r_x: state.r_x,
        };

        let msg = VerifierFifthMessage{last_random_point: final_randomness};
        Ok((next_state, msg))
    }

    pub fn simulate_verify_second_sumcheck_final_round<R: RngCore>(rng: &mut R) -> VerifierFifthMessage<F> {
        VerifierFifthMessage{
            last_random_point: AHPForMLSumcheck::random_oracle_round(rng).randomness
        }
    }

    /// receive z(r_y), verify final claim
    pub fn verify_sixth_round(state: VerifierSixthState<F>, p_msg: ProverFinalMessage<F>)
                              -> SResult<bool>
    {
        let z_ry = p_msg.z_ry;
        // todo: verify if z_ry is correct using proof
        let expected = state.second_subclaim.expected_evaluation;
        let (r_a, r_b, r_c) = (state.r_a,state.r_b,state.r_c);
        let r_x = state.r_x;
        let r_y = state.second_subclaim.point;
        let vk = state.vk;
        let a_rx_ry = vk.matrix_a.eval_on_x(&r_x)?.eval_at(&r_y)?;
        let b_rx_ry = vk.matrix_b.eval_on_x(&r_x)?.eval_at(&r_y)?;
        let c_rx_ry = vk.matrix_c.eval_on_x(&r_x)?.eval_at(&r_y)?;

        let actual = r_a * a_rx_ry * z_ry + r_b * b_rx_ry * z_ry + r_c * c_rx_ry * z_ry;
        if expected != actual {
            return Err(crate::Error::WrongWitness(Some("Cannot verify matrix A, B, C".into())))
        }
        Ok(true)
    }



}

