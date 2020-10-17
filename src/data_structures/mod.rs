pub mod r1cs_reader;

/// extension of eq polynomial
pub mod eq;

/// a transcript of the interactive proof process
pub mod proof;

#[cfg(test)]
/// a constraint synthesizer
pub mod constraints;