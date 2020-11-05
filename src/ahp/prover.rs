use ark_ff::Field;
use linear_sumcheck::data_structures::ml_extension::{ArithmeticCombination, MLExtension};
use linear_sumcheck::data_structures::MLExtensionArray;
use linear_sumcheck::ml_sumcheck::ahp::AHPForMLSumcheck;
use linear_sumcheck::ml_sumcheck::ahp::indexer::IndexInfo as MLIndexInfo;
use linear_sumcheck::ml_sumcheck::ahp::prover::{ProverMsg as MLProverMsg, ProverState as MLProverState};
use linear_sumcheck::ml_sumcheck::ahp::verifier::VerifierMsg as MLVerifierMsg;

use crate::ahp::AHPForSpartan;
use crate::ahp::indexer::IndexPK;
use crate::ahp::verifier::{VerifierFifthMessage, VerifierFirstMessage, VerifierFourthMessage, VerifierSecondMessage, VerifierThirdMessage};
use crate::data_structures::eq::eq_extension;

pub struct ProverFirstState<F: Field> {
    pk: IndexPK<F>
}

pub struct ProverSecondState<F: Field> {
    pk: IndexPK<F>
}

/// state after sending commitment and z_rv_0
pub struct ProverThirdState<F: Field> {
    pk: IndexPK<F>,
    z: MLExtensionArray<F>,
}

/// state when prover is doing first sumcheck
pub struct ProverFirstSumcheckState<F: Field> {
    pk: IndexPK<F>,
    z: MLExtensionArray<F>,
    sum_az_over_y: MLExtensionArray<F>,
    sum_bz_over_y: MLExtensionArray<F>,
    sum_cz_over_y: MLExtensionArray<F>,
    ml_prover_state: MLProverState<F>,
}

pub struct ProverFifthState<F: Field> {
    pk: IndexPK<F>,
    z: MLExtensionArray<F>,
    r_x: Vec<F>,
}

pub struct ProverSecondSumcheckState<F: Field> {
    z: MLExtensionArray<F>,
    ml_prover_state: MLProverState<F>,
}

/// first message is the commitment
pub struct ProverFirstMessage {
    pub commitment: String // todo: replace this as a commitment
}

pub struct ProverSecondMessage<F: Field> {
    pub z_rv_0: F,
    pub proof_for_z_rv_0: (), // todo: replace this as a proof using commitment
}

/// contains some sumcheck info
pub struct ProverThirdMessage {
    pub ml_index_info: MLIndexInfo
}

/// va, vb, vc
pub struct ProverFourthMessage<F: Field> {
    pub va: F,
    pub vb: F,
    pub vc: F,
}

/// information for second sumcheck
pub struct ProverFifthMessage {
    pub index_info: MLIndexInfo
}

/// z(r_y)
pub struct ProverSixthMessage<F: Field> {
    pub z_ry: F,
    pub proof_for_z_ry: (), // todo: replace this as a proof using commitment
}
/// final message
pub type ProverFinalMessage<F> = ProverSixthMessage<F>;

impl<F: Field> AHPForSpartan<F> {
    /// initialize the prover
    pub fn prover_init(pk: IndexPK<F>) -> ProverFirstState<F> {
        ProverFirstState { pk }
    }
    /// send commitment
    pub fn prover_first_round(state: ProverFirstState<F>)
                              -> Result<(ProverSecondState<F>, ProverFirstMessage), crate::Error> {
        // todo: commit z
        Ok((ProverSecondState { pk: state.pk }, ProverFirstMessage { commitment: "replace this as commit(w)".into() }))
    }
    /// receive r_v, send z_rv_0
    pub fn prover_second_round(state: ProverSecondState<F>, v_msg: VerifierFirstMessage<F>)
                               -> Result<(ProverThirdState<F>, ProverSecondMessage<F>), crate::Error> {
        let pk = state.pk;
        let z = MLExtensionArray::from_vec(
            pk.v.iter()
                .chain(pk.w.iter())
                .map(|x| *x)
                .collect())?;
        let r_v = v_msg.r_v;
        let z_rv_0 = z.eval_at(&r_v)?;
        let state = ProverThirdState {
            pk,
            z,
        };
        let msg = ProverSecondMessage { z_rv_0, proof_for_z_rv_0: () };
        Ok((state, msg))
    }
    /// Receive random tor from verifier and prepare for the first sumcheck.
    /// send sumcheck index information
    pub fn prover_third_round(state: ProverThirdState<F>, v_msg: VerifierSecondMessage<F>)
                              -> Result<(ProverFirstSumcheckState<F>, ProverThirdMessage), crate::Error> {
        let tor = v_msg.tor;
        let eq = eq_extension(&tor)?;
        let pk = state.pk;
        let z = state.z;
        let sum_az_over_y = pk.matrix_a.sum_over_y(&z)?;
        let sum_bz_over_y = pk.matrix_b.sum_over_y(&z)?;
        let sum_cz_over_y = pk.matrix_c.sum_over_y(&z)?;

        let mut g_zt_x_first = vec![sum_az_over_y.clone(), sum_bz_over_y.clone()];
        g_zt_x_first.extend(eq.iter().map(|mle| mle.clone()));
        let mut g_zt_x_second = vec![sum_cz_over_y.negate()?];
        g_zt_x_second.extend(eq.iter().map(|mle| mle.clone()));
        let mut g_zt_x = ArithmeticCombination::new(pk.log_n);
        g_zt_x.add_product(g_zt_x_first.into_iter())?;
        g_zt_x.add_product(g_zt_x_second.into_iter())?;
        let ml_index = AHPForMLSumcheck::convert_to_index(g_zt_x)?;
        let ml_index_info = ml_index.info();
        let ml_prover_state = AHPForMLSumcheck::prover_init(&ml_index);

        let next_state = ProverFirstSumcheckState {
            pk,
            z,
            sum_az_over_y,
            sum_bz_over_y,
            sum_cz_over_y,
            ml_prover_state,
        };
        let msg = ProverThirdMessage {
            ml_index_info
        };
        Ok((next_state, msg))
    }

    /// first sumcheck
    pub fn prove_first_sumcheck_round(mut state: ProverFirstSumcheckState<F>, v_msg: Option<MLVerifierMsg<F>>)
                                      -> Result<(ProverFirstSumcheckState<F>, MLProverMsg<F>), crate::Error> {
        let (mlp_msg, new_prover_state) = AHPForMLSumcheck::prove_round(state.ml_prover_state,
                                                                        &v_msg)?;
        state.ml_prover_state = new_prover_state;
        Ok((state, mlp_msg))
    }

    /// verifier send the final point, prover send va, vb, vc
    pub fn prove_fourth_round(state: ProverFirstSumcheckState<F>, v_msg: VerifierThirdMessage<F>)
                              -> Result<(ProverFifthState<F>, ProverFourthMessage<F>), crate::Error> {
        let mut r_x = state.ml_prover_state.randomness;
        r_x.push(v_msg.last_random_point);

        let va = state.sum_az_over_y.eval_at(&r_x)?;
        let vb = state.sum_bz_over_y.eval_at(&r_x)?;
        let vc = state.sum_cz_over_y.eval_at(&r_x)?;

        let next_state = ProverFifthState {
            z: state.z,
            pk: state.pk,
            r_x,
        };
        let msg = ProverFourthMessage {
            va,
            vb,
            vc,
        };
        Ok((next_state, msg))
    }
    /// receive ra, rb, rc, and prepare for second sumcheck
    pub fn prove_fifth_round(state: ProverFifthState<F>, v_msg: VerifierFourthMessage<F>)
                             -> Result<(ProverSecondSumcheckState<F>, ProverFifthMessage), crate::Error>
    {
        let r_a = v_msg.r_a;
        let r_b = v_msg.r_b;
        let r_c = v_msg.r_c;
        let r_x = state.r_x;
        let z = state.z;
        let az_rx_on_y = vec![state.pk.matrix_a.eval_on_x(&r_x)?.multiply(r_a)?, z.clone()];
        let bz_rx_on_y = vec![state.pk.matrix_b.eval_on_x(&r_x)?.multiply(r_b)?, z.clone()];
        let cz_rx_on_y = vec![state.pk.matrix_c.eval_on_x(&r_x)?.multiply(r_c)?, z.clone()];
        let mut round2_poly = ArithmeticCombination::new(state.pk.log_n);
        round2_poly.add_product(az_rx_on_y.into_iter())?;
        round2_poly.add_product(bz_rx_on_y.into_iter())?;
        round2_poly.add_product(cz_rx_on_y.into_iter())?;
        let index = AHPForMLSumcheck::convert_to_index(round2_poly)?;
        let ml_prover_state = AHPForMLSumcheck::prover_init(&index);

        let next_state = ProverSecondSumcheckState { z, ml_prover_state };
        let msg = ProverFifthMessage { index_info: index.info() };

        Ok((next_state, msg))
    }

    /// second round sumcheck
    pub fn prove_second_sumcheck_round(mut state: ProverSecondSumcheckState<F>, v_msg: Option<MLVerifierMsg<F>>)
                                       -> Result<(ProverSecondSumcheckState<F>, MLProverMsg<F>), crate::Error> {
        let (mlp_msg, new_prover_state) = AHPForMLSumcheck::prove_round(state.ml_prover_state,
                                                                        &v_msg)?;
        state.ml_prover_state = new_prover_state;
        Ok((state, mlp_msg))
    }
    /// final round: send z(r_y) and its corresponding proof
    pub fn prove_sixth_round(state: ProverSecondSumcheckState<F>, v_msg: VerifierFifthMessage<F>)
                             -> Result<ProverFinalMessage<F>, crate::Error> {
        let mut r_y = state.ml_prover_state.randomness;
        r_y.push(v_msg.last_random_point);
        let msg = ProverFinalMessage { z_ry: state.z.eval_at(&r_y)?, proof_for_z_ry: () };
        Ok(msg)
    }
}