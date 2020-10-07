//! testing utility

use rand::RngCore;
use r1cs_core::Matrix;
use algebra_core::{UniformRand, Field};
use hashbrown::HashSet;

/// curve instance used for test
pub type F = algebra::ed_on_bls12_381::Fr;
pub fn random_matrix<R: RngCore>(log_size: usize,num_non_zero: usize, rng:&mut R) -> Matrix<F> {
    let bound = 1 << log_size;
    let mut mat: Vec<_> = (0..bound)
        .map(|_|Vec::new())
        .collect();
    let mut added = HashSet::new();
    for _ in 0..num_non_zero{
        let mut x = (rng.next_u64() & (bound - 1)) as usize;
        let mut y = (rng.next_u64() & (bound - 1)) as usize;
        while added.contains(&(x,y)) {
            x = (rng.next_u64() & (bound - 1)) as usize;
            y = (rng.next_u64() & (bound - 1)) as usize;
        }
        added.insert((x,y));
        mat[x].push((F::rand(rng),y));
    }
    mat
}

pub fn bits_to_field_elements<F: Field>(mut bits: usize, mut num_bits: usize) -> Vec<F> {
    let mut result = Vec::new();
    while num_bits > 0 {
        let bi = bits & 1;
        result.push(if bi == 1 {F::one()} else {F::zero()});
        bits >>= 1;
        num_bits-=1;
    }

    result
}
