use ark_std::fmt;
use ark_std::fmt::Formatter;

#[derive(Debug)]
pub enum Error {
    /// bad argument
    InvalidArgument(Option<String>),
    /// linear sumcheck error
    SumCheckError(linear_sumcheck::Error)
}

impl fmt::Display for Error {
    fn fmt(&self, _f: &mut Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl From<linear_sumcheck::Error> for Error {
    fn from(e: linear_sumcheck::Error) -> Self {
        Error::SumCheckError(e)
    }
}