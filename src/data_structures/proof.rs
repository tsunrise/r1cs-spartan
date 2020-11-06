use ark_ff::Field;

use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, SerializationError, Read, Write};
use crate::ahp::prover::{ProverFirstMessage, ProverSecondMessage, ProverThirdMessage, ProverFourthMessage, ProverFifthMessage, ProverSixthMessage};
use linear_sumcheck::ml_sumcheck::ahp::prover::ProverMsg as MLProverMsg;

/// message sent by the prover
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<F: Field> {
    pub prover_first_message: ProverFirstMessage,
    pub prover_second_message: ProverSecondMessage<F>,
    pub prover_third_message: ProverThirdMessage,
    pub first_sumcheck_messages: Vec<MLProverMsg<F>>,
    pub prover_fourth_message: ProverFourthMessage<F>,
    pub prover_fifth_message: ProverFifthMessage,
    pub second_sumcheck_messages: Vec<MLProverMsg<F>>,
    pub prover_sixth_message: ProverSixthMessage<F>
}