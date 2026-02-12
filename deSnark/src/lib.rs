//! deSnark - Distributed SNARK protocol implementation

pub mod errors;
pub mod snark;
pub mod structs;

pub use errors::DeSnarkError;
pub use snark::{dist_snark_prove, make_circuit, prove, prove_hyper_pianist, prove_sumfold, setup};
pub use structs::{
    Config, GateType, Instance, NetworkConfig, Proof, ProvingKey, VerifyingKey, Witness,
};
