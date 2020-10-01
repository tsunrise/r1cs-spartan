//! reader interpreting r1cs matrix as dense MLExtension

use algebra_core::PairingEngine;
use ark_std::rc::Rc;
use linear_sumcheck::data_structures::MLExtensionArray;
use r1cs_core::Matrix;

pub struct R1CSReader<E: PairingEngine> {
    constraint: Rc<Matrix<E::Fr>>,
    /// io: public instances
    pub num_instance_variables: usize,
    /// z: private witnesses
    pub num_witness_variables: usize,
    /// number of constraints
    pub num_constraints: usize
}

impl<E: PairingEngine> R1CSReader<E> {
    /// setup the MLExtension
    pub fn setup(matrix: Rc<Matrix<E::Fr>>,
                 num_instance_variables: usize,
                 num_witness_variables: usize,
                 num_constraints: usize) -> Result<Self, crate::Error>{
        // sanity check
        if num_instance_variables + num_witness_variables + 1 != num_constraints {
            return Err(crate::Error::InvalidArgument(None))
        }

        if matrix.len() != num_constraints {
            return Err(crate::Error::InvalidArgument(None))
        }

        let s = Self{
            constraint: matrix,
            num_constraints,
            num_instance_variables,
            num_witness_variables
        };
        Ok(s)
    }

    /// Convert the matrix A(x,y) to sum over y A(x,y)
    ///
    /// return: multilinear extension sum over y A(x,y) with `num_constraints` variables
    pub fn sum_over_y(&self) -> Result<MLExtensionArray<E::Fr>, crate::Error> {
        let temp: Vec<E::Fr> = self.constraint.iter()
            .map(|v| v.iter().
                map(|(a, _)| a)
                .sum()).
            collect();
        Ok(MLExtensionArray::from_slice(&temp)?)
    }

    /// Given A(x,y) and randomness r_x
    ///
    /// return: multilinear extension A(r_x,y) with `num_constraints` variables
    pub fn eval_on_x(&self, _r_x:Vec<E::Fr>) -> Result<MLExtensionArray<E::Fr>, crate::Error> {
        todo!()
    }
}



