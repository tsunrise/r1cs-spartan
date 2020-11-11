use ark_ff::{Field, test_rng};
use ark_relations::r1cs::{ConstraintMatrices};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use crate::Spartan;

use crate::test_utils::{generate_circuit_with_random_input, TestCurveFr};
use crate::data_structures::proof::Proof;

fn test_circuit<F: Field>(matrices: ConstraintMatrices<F>,v: Vec<F>,w: Vec<F>) -> Result<(),crate::Error> {
        println!("|v| = {}, |w| = {}, #non-zero-entries = {}",
                 matrices.num_instance_variables,
                 matrices.num_witness_variables,
                 matrices.a_num_non_zero + matrices.b_num_non_zero + matrices.c_num_non_zero);


    let timer = start_timer!(||"Index");
    let index_pk = Spartan::index(matrices.a, matrices.b, matrices.c)?;
    let index_vk = index_pk.vk();
    end_timer!(timer);

    let timer = start_timer!(||"Prove Circuit");
    let proof = Spartan::prove(index_pk, v.to_vec(), w)?;
    let proof_serialized = {
        let mut data: Vec<u8> = Vec::new();
        proof.serialize(&mut data)?;
        data
    };
    end_timer!(timer);
    // test communication cost
    println!("Communication Cost: {} bytes", proof_serialized.len());
    let timer = start_timer!(||"Verify");
    let proof = Proof::deserialize(&proof_serialized[..])?;
    let result = Spartan::verify(index_vk,v,proof)?;
    assert!(result);
    end_timer!(timer);
    println!();
    Ok(())
}

#[test]
#[ignore]
fn benchmark() {
    type F = TestCurveFr;
    let mut rng = test_rng();

    println!("Spartan Benchmark\nNote: As commitment scheme has not been used, \
    the runtime does not include commit time. \n");

    println!("Benchmark: Prover and Verifier Runtime with different matrix size with same sparsity\n");
    for i in 7..14{
        let (r1cs, v, w)
            = generate_circuit_with_random_input::<F, _>(32,
                                                         (2<<i) - 32,
                                                         true,0,
                                                         &mut rng);

        test_circuit(r1cs.to_matrices().unwrap(), v, w).expect("Failed to test circuit");
    }
    println!("Benchmark: Prover and Verifier Runtime with same matrix size with different sparsity\n");
    for i in 0..10{
        let density = (255 * i / 10) as u8;
        let (r1cs, v, w)
            = generate_circuit_with_random_input::<F, _>(32,
                                                         (2<<10) - 32,
                                                         true,density,
                                                         &mut rng);

        test_circuit(r1cs.to_matrices().unwrap(), v, w).expect("Failed to test circuit");
    }

}