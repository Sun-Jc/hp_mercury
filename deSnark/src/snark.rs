//! deSnark protocol functions.

use crate::errors::DeSnarkError;
use crate::structs::{Config, Instance, NetworkConfig, Proof, ProvingKey, VerifyingKey, Witness};
use deNetwork::{DeMultiNet as Net, DeNet};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use subroutines::pcs::PolynomialCommitmentScheme;

/// Result type for deSnark operations.
pub type Result<T> = std::result::Result<T, DeSnarkError>;

/// Phase 0: Generate SRS from config.
///
/// # Arguments
/// * `config` - Protocol configuration
///
/// # Returns
/// * `PCS::SRS` - Structured Reference String for the PCS
pub fn setup<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(
    _config: &Config,
) -> PCS::SRS {
    // TODO: implement SRS generation
    unimplemented!("setup")
}

/// Phase 1: Generate circuit, keys, instances, and witnesses.
///
/// Internally calls `preprocess()` to generate proving and verifying keys.
///
/// # Arguments
/// * `config` - Protocol configuration
/// * `srs` - Structured Reference String
///
/// # Returns
/// * `ProvingKey` - Key for proving
/// * `VerifyingKey` - Key for verification
/// * `Vec<Instance>` - M instances (public inputs)
/// * `Vec<Witness>` - M witnesses (private inputs)
pub fn make_circuit<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(
    config: Config,
    srs: &PCS::SRS,
) -> Result<(
    ProvingKey,
    VerifyingKey,
    Vec<Instance<E::ScalarField>>,
    Vec<Witness<E::ScalarField>>,
)> {
    // 1. Build Index from Config
    // let index = build_index(&config);

    // 2. Preprocess to generate PK/VK
    let (pk, vk) = preprocess::<E, PCS>(&config, srs)?;

    // 3. Generate M instances and witnesses
    let (instances, witnesses) = generate_mock_data::<E::ScalarField>(&config);

    Ok((pk, vk, instances, witnesses))
}

/// Preprocess: generate proving and verifying keys from circuit description.
fn preprocess<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(
    _config: &Config,
    _srs: &PCS::SRS,
) -> Result<(ProvingKey, VerifyingKey)> {
    // TODO: implement
    // 1. PCS::trim(srs) -> (prover_param, verifier_param)
    // 2. Build permutation_oracles, selector_oracles
    // 3. PCS::commit to generate commitments
    // 4. Return (ProvingKey, VerifyingKey)
    unimplemented!("preprocess")
}

/// Generate mock instances and witnesses for testing.
fn generate_mock_data<F: PrimeField>(
    config: &Config,
) -> (Vec<Instance<F>>, Vec<Witness<F>>) {
    let mut instances = Vec::with_capacity(config.num_instances);
    let mut witnesses = Vec::with_capacity(config.num_instances);

    for _ in 0..config.num_instances {
        instances.push(Instance::default());
        witnesses.push(Witness::default());
    }

    (instances, witnesses)
}

/// Phase 2: SumFold protocol - aggregate instances and witnesses.
///
/// # Arguments
/// * `pk` - Proving key
/// * `instances` - M instances to aggregate
/// * `witnesses` - M witnesses to aggregate
///
/// # Returns
/// * `Instance` - Aggregated instance
/// * `Witness` - Aggregated witness
/// * `Proof` - SumFold proof
pub fn prove_sumfold<F: PrimeField>(
    _pk: &ProvingKey,
    _instances: &[Instance<F>],
    _witnesses: &[Witness<F>],
) -> Result<(Instance<F>, Witness<F>, Proof)> {
    // TODO: implement SumFold aggregation
    unimplemented!("prove_sumfold")
}

/// Phase 3: HyperPianist proof - generate final SNARK proof.
///
/// # Arguments
/// * `instance` - Aggregated instance
/// * `witness` - Aggregated witness
///
/// # Returns
/// * `Proof` - Final SNARK proof
pub fn prove_hyper_pianist<F: PrimeField>(
    _instance: &Instance<F>,
    _witness: &Witness<F>,
) -> Result<Proof> {
    // TODO: implement HyperPianist proving
    unimplemented!("prove_hyper_pianist")
}

/// Full prove pipeline: setup -> make_circuit -> prove_sumfold -> prove_hyper_pianist
pub fn prove<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(
    config: Config,
) -> Result<Proof> {
    let srs = setup::<E, PCS>(&config);
    let (pk, _vk, instances, witnesses) = make_circuit::<E, PCS>(config, &srs)?;
    let (instance, witness, _sumfold_proof) = prove_sumfold(&pk, &instances, &witnesses)?;
    prove_hyper_pianist(&instance, &witness)
}

/// Distributed SNARK prove - complete end-to-end pipeline.
///
/// # Flow
/// 1. Initialize network (if net_config provided)
/// 2. setup(config) -> SRS
/// 3. make_circuit(config, srs) -> (PK, VK, Vec<Instance>, Vec<Witness>)
/// 4. prove_sumfold(pk, instances, witnesses) -> (aggregated Instance, Witness, SumFold Proof)
/// 5. prove_hyper_pianist(instance, witness) -> Final Proof
/// 6. Deinitialize network
///
/// # Arguments
/// * `config` - Protocol configuration
/// * `net_config` - Optional network configuration for distributed mode
///
/// # Returns
/// * `VerifyingKey` - For verification
/// * `Proof` - Final SNARK proof
pub fn dist_snark_prove<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(
    config: Config,
    net_config: Option<NetworkConfig>,
) -> Result<(VerifyingKey, Proof)> {
    // Initialize network if distributed mode
    if let Some(ref net_cfg) = net_config {
        Net::init_from_file(&net_cfg.hosts_file, net_cfg.party_id);
    }

    // Use defer pattern to ensure network cleanup
    let result = (|| {
        // Phase 0: Setup
        let srs = setup::<E, PCS>(&config);

        // Phase 1: Make circuit
        let (pk, vk, instances, witnesses) = make_circuit::<E, PCS>(config, &srs)?;

        // Phase 2: SumFold aggregation
        let (instance, witness, _sumfold_proof) = prove_sumfold(&pk, &instances, &witnesses)?;

        // Phase 3: HyperPianist final proof
        let proof = prove_hyper_pianist(&instance, &witness)?;

        Ok((vk, proof))
    })();

    // Deinitialize network
    if net_config.is_some() {
        Net::deinit();
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structs::GateType;

    #[test]
    fn test_generate_mock_data() {
        use ark_bn254::Fr;
        let config = Config::new(2, 10, GateType::Vanilla, 2);
        let (instances, witnesses) = generate_mock_data::<Fr>(&config);
        assert_eq!(instances.len(), 4); // 2^2 = 4
        assert_eq!(witnesses.len(), 4);
    }
}
