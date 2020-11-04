use ark_ff::Field;
use crate::ahp::AHPForSpartan;
/// r_v: randomness
pub struct VerifierFirstMessage<F: Field>{
    pub r_v: Vec<F>
}

/// random tor
pub struct VerifierSecondMessage<F: Field> {
    pub tor: Vec<F>
}
/// the last randomness for MLSumcheck
pub struct VerifierThirdMessage<F: Field> {
    pub last_random_point: F
}

pub struct VerifierFourthMessage<F: Field> {
    pub r_a: F,
    pub r_b: F,
    pub r_c: F
}

/// the last randomness for second MLSumcheck
pub struct VerifierFifthMessage<F: Field> {
    pub last_random_point: F
}

impl<F: Field> AHPForSpartan<F> {

}