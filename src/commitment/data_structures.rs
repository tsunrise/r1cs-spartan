use ark_ec::PairingEngine;

pub type EvaluationHyperCubeOnG1<E: PairingEngine> = Vec<E::G1Projective>;
pub type EvaluationHyperCubeOnG2<E: PairingEngine> = Vec<E::G2Projective>;

pub struct PublicParameter<E: PairingEngine> {
    pub nv: usize,
    /// pp_k defined by libra
    pub powers_of_g: Vec<EvaluationHyperCubeOnG1<E>>,
    pub powers_of_h: Vec<EvaluationHyperCubeOnG2<E>>,
    pub g: E::G1Projective,
    pub h: E::G2Projective,
}

pub struct VerifierParameter<E: PairingEngine> {
    pub nv: usize,
    pub g: E::G1Projective,
    pub h: E::G2Projective,
    /// g^t1, g^t2, ...
    pub g_mask_random: Vec<E::G1Projective>,
    pub h_mask_random: Vec<E::G2Projective>
}