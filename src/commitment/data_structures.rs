use ark_ec::PairingEngine;

pub type EvaluationHyperCubeOnG1<E: PairingEngine> = Vec<E::G1Projective>;
pub type EvaluationHyperCubeOnG2<E: PairingEngine> = Vec<E::G2Projective>;

pub struct PublicParameter<E: PairingEngine> {
    pub powers_of_g: Vec<EvaluationHyperCubeOnG1<E>>,
    pub powers_of_h: Vec<EvaluationHyperCubeOnG2<E>>,
    pub g: E::G1Projective,
    pub h: E::G2Projective,
}