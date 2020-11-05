use rand::RngCore;
use crate::error::SResult;
use crate::test_utils::generate_circuit_with_random_input;
use crate::ahp::AHPForSpartan;
use ark_ff::test_rng;

type TestField = ark_test_curves::bls12_381::Fr;

fn test_circuit<R: RngCore>(log_n: usize, log_v: usize, rng: &mut R) -> SResult<()> {
    let num_public = 1 << log_v;
    let num_private = (1 << log_n) - num_public;
    let (r1cs,
        v, w) = generate_circuit_with_random_input::<TestField, _>(
        num_public, num_private, true, 1, rng);

    let matrices = r1cs.to_matrices().unwrap();
    let pk = AHPForSpartan::index(matrices.a,
                                  matrices.b,
                                  matrices.c, v, w)?;

    let vk = pk.vk();

    let ps = AHPForSpartan::prover_init(pk);
    let vs = AHPForSpartan::verifier_init(vk);

    let (ps, pm) = AHPForSpartan::prover_first_round(ps)?;
    let (vs, vm) = AHPForSpartan::verifier_first_round(vs, pm, rng)?;

    let (ps, pm) = AHPForSpartan::prover_second_round(ps, vm)?;
    let (vs, vm) = AHPForSpartan::verifier_second_round(vs, pm, rng)?;

    let (mut ps, pm) = AHPForSpartan::prover_third_round(ps, vm)?;
    let (mut vs, mut vm) = AHPForSpartan::verifier_third_round(vs, pm)?;

    for _ in 0..(log_n - 1) {
        let (ps_new, pm) = AHPForSpartan::prove_first_sumcheck_round(ps, vm)?;
        ps = ps_new;
        let (vs_new, vm_new) = AHPForSpartan::verifier_first_sumcheck_ongoing_round(vs, pm, rng)?;
        vs = vs_new;
        vm = vm_new;
    }

    let (ps, pm) = AHPForSpartan::prove_first_sumcheck_round(ps, vm)?;
    let (vs, vm) = AHPForSpartan::verifier_first_sumcheck_final_round(vs, pm, rng)?;

    let (ps, pm) = AHPForSpartan::prove_fourth_round(ps, vm)?;
    let (vs, vm) = AHPForSpartan::verifier_fourth_round(vs, pm, rng)?;

    let (mut ps, pm) = AHPForSpartan::prove_fifth_round(ps, vm)?;
    let (mut vs, mut vm) = AHPForSpartan::verifier_fifth_round(vs, pm)?;

    for _ in 0..(log_n - 1) {
        let (ps_new, pm) = AHPForSpartan::prove_second_sumcheck_round(ps, vm)?;
        ps = ps_new;
        let (vs_new, vm_new)
            = AHPForSpartan::verifier_second_sumcheck_ongoing_round(vs, pm, rng)?;
        vs = vs_new;
        vm = vm_new;
    }

    let (ps, pm) = AHPForSpartan::prove_second_sumcheck_round(ps, vm)?;
    let (vs, vm) = AHPForSpartan::verifier_second_sumcheck_final_round(vs, pm, rng)?;

    let pm = AHPForSpartan::prove_sixth_round(ps, vm)?;
    let result = AHPForSpartan::verifier_sixth_round(vs, pm)?;

    if result {Ok(())} else {Err(crate::Error::WrongWitness(Some("cannot verify".into())))}
}

#[test]
fn test_small(){
    test_circuit(8, 2, &mut test_rng()).expect("fail to test small");
}