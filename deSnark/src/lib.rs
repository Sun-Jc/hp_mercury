//! deSnark - Distributed SNARK protocol implementation

pub mod errors;
pub mod structs;

pub use errors::DeSnarkError;
pub use structs::{Config, Instance, Proof, ProvingKey, VerifyingKey, Witness};
