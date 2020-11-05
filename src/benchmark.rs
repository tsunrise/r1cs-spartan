use rand::RngCore;
use ark_ff::{Field, test_rng};
use ark_relations::r1cs::{ConstraintMatrices};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use crate::Spartan;
use ark_std::rc::Rc;
use crate::test_utils::generate_circuit_with_random_input;
use crate::data_structures::proof::Proof;

fn test_circuit<R: RngCore, F: Field>(matrices: ConstraintMatrices<F>,v: Vec<F>,w: Vec<F> ,rng: &mut R) -> Result<(),crate::Error> {
        println!("|v| = {}, |w| = {}, #non-zero-entries = {}",
                 matrices.num_instance_variables,
                 matrices.num_witness_variables,
                 matrices.a_num_non_zero + matrices.b_num_non_zero + matrices.c_num_non_zero);
    let session_key = Spartan::<F>::setup(rng);
    let matrix_a = Rc::new(matrices.a);
    let matrix_b = Rc::new(matrices.b);
    let matrix_c = Rc::new(matrices.c);

    let timer = start_timer!(||"Prove Circuit");
    let proof = Spartan::prove(&session_key,
                               matrix_a.clone(),
                               matrix_b.clone(),
                               matrix_c.clone(),&v, &w, false)?;
    let proof_serialized = {
        let mut data: Vec<u8> = Vec::new();
        proof.serialize(&mut data)?;
        data
    };
    end_timer!(timer);
    // test communication cost
    println!("Communication Cost: {} bytes", proof_serialized.len());
    let timer = start_timer!(||"Verify Circuit");
    let proof = Proof::deserialize(&proof_serialized[..])?;
    Spartan::verify(&session_key, matrix_a.clone(),
                    matrix_b.clone(),
                    matrix_c.clone(),
                    matrices.num_instance_variables + matrices.num_witness_variables,
                    &v,
                    &proof)?;
    end_timer!(timer);
    println!();
    Ok(())
}

#[test]
#[ignore]
fn benchmark() {
    type F = ark_test_curves::bls12_381::Fr;
    let mut rng = test_rng();

    println!("Spartan Benchmark\nNote: As commitment scheme has not been used, \
    the runtime does not include commit time. \n");

    println!("Benchmark: Prover and Verifier Runtime with different matrix size with same sparsity\n");
    for i in 7..15{
        let (r1cs, v, w)
            = generate_circuit_with_random_input::<F, _>(32,
                                                         (2<<i) - 32,
                                                         true,0,
                                                         &mut rng);

        test_circuit(r1cs.to_matrices().unwrap(), v, w, &mut rng).expect("Failed to test circuit");
    }
    println!("Benchmark: Prover and Verifier Runtime with same matrix size with different sparsity\n");
    for i in 0..10{
        let density = (255 * i / 10) as u8;
        let (r1cs, v, w)
            = generate_circuit_with_random_input::<F, _>(32,
                                                         (2<<10) - 32,
                                                         true,density,
                                                         &mut rng);

        test_circuit(r1cs.to_matrices().unwrap(), v, w, &mut rng).expect("Failed to test circuit");
    }

}