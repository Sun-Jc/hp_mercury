//! deSnark - Distributed SNARK protocol implementation

pub mod errors;
pub mod snark;
pub mod structs;

pub use errors::DeSnarkError;
pub use snark::{circuits_to_sumcheck, dist_prove, make_circuit, prove_hyper_pianist, prove_sumfold, setup, HyperPlonkPCS};
pub use structs::{
    Config, GateType, NetworkConfig, Proof, SumCheckInstance,
};
