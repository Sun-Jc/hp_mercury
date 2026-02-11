//! Core data structures for deSnark distributed SNARK protocol.

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Configuration for the distributed SNARK protocol.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    /// M - number of instances
    pub num_instances: usize,
    /// ν (nu) - log of number of instances
    pub log_num_instances: usize,
    /// N - number of constraints
    pub num_constraints: usize,
    /// μ (mu) - log of number of constraints
    pub log_num_constraints: usize,
    /// t - number of MLEs
    pub num_mles: usize,
    /// K - number of parties
    pub num_parties: usize,
    /// κ (kappa) - log of number of parties
    pub log_num_parties: usize,
}

impl Config {
    /// Create a new Config with validation.
    pub fn new(
        log_num_instances: usize,
        log_num_constraints: usize,
        num_mles: usize,
        log_num_parties: usize,
    ) -> Self {
        Self {
            num_instances: 1 << log_num_instances,
            log_num_instances,
            num_constraints: 1 << log_num_constraints,
            log_num_constraints,
            num_mles,
            num_parties: 1 << log_num_parties,
            log_num_parties,
        }
    }
}

/// Proving key for the distributed SNARK.
#[derive(Clone, Debug)]
pub struct ProvingKey {
    // TODO: define fields
}

/// Verifying key for the distributed SNARK.
#[derive(Clone, Debug)]
pub struct VerifyingKey {
    // TODO: define fields
}

/// Public instance (public input).
#[derive(Clone, Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct Instance<F: PrimeField> {
    // TODO: define fields
    _marker: std::marker::PhantomData<F>,
}

/// Private witness.
#[derive(Clone, Debug, Default)]
pub struct Witness<F: PrimeField> {
    // TODO: define fields
    _marker: std::marker::PhantomData<F>,
}

/// Proof for the distributed SNARK.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof {
    // TODO: define fields
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_new() {
        // log_num_instances=4, log_num_constraints=10, num_mles=8, log_num_parties=2
        let config = Config::new(4, 10, 8, 2);
        assert_eq!(config.num_instances, 16);
        assert_eq!(config.log_num_instances, 4);
        assert_eq!(config.num_constraints, 1024);
        assert_eq!(config.log_num_constraints, 10);
        assert_eq!(config.num_mles, 8);
        assert_eq!(config.num_parties, 4);
        assert_eq!(config.log_num_parties, 2);
    }
}
