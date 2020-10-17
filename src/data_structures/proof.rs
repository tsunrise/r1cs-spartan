use ark_ff::Field;
use linear_sumcheck::ml_sumcheck::t13::T13Proof;

pub type Proof<F> = Transcript<F>;
/// message sent by the prover
pub struct Transcript<F: Field> {
    pub commit_w: (), // todo

    pub first_sumcheck_proof: T13Proof<F>,

    pub va: F,
    pub vb: F,
    pub vc: F,

    pub second_sumcheck_proof: T13Proof<F>,

    pub eval_z_at_ry: F,
    pub proof_for_eval_z: (), // todo

}