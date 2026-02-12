//! Core data structures for deSnark distributed SNARK protocol.

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Gate type for the circuit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GateType {
    /// Vanilla PLONK gate: q_L w_1 + q_R w_2 + q_O w_3 + q_M w_1 w_2 + q_C = 0
    /// 3 witness columns, 5 selector columns
    #[default]
    Vanilla,
}

impl GateType {
    /// t - number of witness columns for this gate type.
    pub fn num_witness_columns(&self) -> usize {
        match self {
            GateType::Vanilla => 3,
        }
    }
}

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
    /// Gate type
    pub gate_type: GateType,
    /// K - number of parties
    pub num_parties: usize,
    /// κ (kappa) - log of number of parties
    pub log_num_parties: usize,
}

impl Config {
    /// Create a new Config.
    pub fn new(
        log_num_instances: usize,
        log_num_constraints: usize,
        gate_type: GateType,
        log_num_parties: usize,
    ) -> Self {
        Self {
            num_instances: 1 << log_num_instances,
            log_num_instances,
            num_constraints: 1 << log_num_constraints,
            log_num_constraints,
            gate_type,
            num_parties: 1 << log_num_parties,
            log_num_parties,
        }
    }

    /// t - number of witness columns based on gate type.
    pub fn num_witness_columns(&self) -> usize {
        self.gate_type.num_witness_columns()
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

/// Network configuration for distributed proving.
#[derive(Clone, Debug)]
pub struct NetworkConfig {
    /// Path to hosts file (one HOST:PORT per line)
    pub hosts_file: String,
    /// This party's ID (0-indexed)
    pub party_id: usize,
}

impl NetworkConfig {
    /// Create a new NetworkConfig.
    pub fn new(hosts_file: impl Into<String>, party_id: usize) -> Self {
        Self {
            hosts_file: hosts_file.into(),
            party_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_new() {
        let config = Config::new(4, 10, GateType::Vanilla, 2);
        assert_eq!(config.num_instances, 16);
        assert_eq!(config.log_num_instances, 4);
        assert_eq!(config.num_constraints, 1024);
        assert_eq!(config.log_num_constraints, 10);
        assert_eq!(config.gate_type, GateType::Vanilla);
        assert_eq!(config.num_witness_columns(), 3);
        assert_eq!(config.num_parties, 4);
        assert_eq!(config.log_num_parties, 2);
    }

    #[test]
    fn test_gate_type_witness_columns() {
        assert_eq!(GateType::Vanilla.num_witness_columns(), 3);
    }
}
