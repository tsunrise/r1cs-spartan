use ark_ff::Field;
use ark_relations::r1cs::Matrix;
use crate::data_structures::r1cs_reader::MatrixExtension;
use crate::ahp::AHPForSpartan;
use crate::error::invalid_arg;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
/// Prover's Key
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct IndexPK<F: Field> {
    pub matrix_a: MatrixExtension<F>,
    pub matrix_b: MatrixExtension<F>,
    pub matrix_c: MatrixExtension<F>,
    /// public witness
    pub v: Vec<F>,
    /// private witness
    pub w: Vec<F>,
    /// log(|v|+|w|)
    pub log_n: usize,
    /// log(|v|)
    pub log_v: usize
}

/// Verifier's Key
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct IndexVK<F: Field> {
    pub matrix_a: MatrixExtension<F>,
    pub matrix_b: MatrixExtension<F>,
    pub matrix_c: MatrixExtension<F>,
    /// public witness
    pub v: Vec<F>,
    /// log(|v|+|w|)
    pub log_n: usize,
    /// log(|v|)
    pub log_v: usize
}

impl<F: Field> IndexPK<F> {
    pub fn vk(&self) -> IndexVK<F> {
        IndexVK{
            matrix_a: self.matrix_a.clone(),
            matrix_b: self.matrix_b.clone(),
            matrix_c: self.matrix_c.clone(),
            v: self.v.clone(),
            log_n: self.log_n,
            log_v: self.log_v
        }
    }
}

impl<F: Field> AHPForSpartan<F> {
    pub fn index(matrix_a: Matrix<F>,
                 matrix_b: Matrix<F>,
                 matrix_c: Matrix<F>, v: Vec<F>, w: Vec<F>) -> Result<IndexPK<F>, crate::Error> {
        // sanity check
        let n = v.len() + w.len();
        // for simplicity, this protocol assume width of matrix (n) is a power of 2.
        if !n.is_power_of_two() {
            return Err(invalid_arg("Matrix width should be a power of 2."));
        }
        if !v.len().is_power_of_two() {
            return Err(invalid_arg("Size of public input should be power of two. "));
        }
        let log_n = ark_std::log2(n) as usize;
        let log_v = ark_std::log2(v.len()) as usize;

        let matrix_a = MatrixExtension::new(matrix_a, n)?;
        let matrix_b = MatrixExtension::new(matrix_b, n)?;
        let matrix_c = MatrixExtension::new(matrix_c, n)?;

        Ok(IndexPK{
            matrix_a,
            matrix_b,
            matrix_c,
            log_n,
            log_v,
            v,
            w
        })
    }
}

