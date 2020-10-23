use ark_ff::Field;
use linear_sumcheck::ml_sumcheck::t13::{T13Proof, T13Claim};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, SerializationError, Read, Write};
pub type Proof<F> = Transcript<F>;
/// message sent by the prover
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Transcript<F: Field> {
    pub commit_w: (), // todo

    pub z_rv_0: F, 
    pub proof_for_z_rv_0: (), // todo
    
    pub first_sumcheck_claim: T13Claim<F>,
    pub first_sumcheck_proof: T13Proof<F>,

    pub va: F,
    pub vb: F,
    pub vc: F,

    pub second_sumcheck_claim: T13Claim<F>,
    pub second_sumcheck_proof: T13Proof<F>,

    pub eval_z_at_ry: F,
    pub proof_for_eval_z: (), // todo

}