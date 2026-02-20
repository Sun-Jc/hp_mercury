//! deSnark protocol functions.

use crate::errors::DeSnarkError;
use crate::structs::{
    Config, HyperPlonkProvingKey, HyperPlonkVerifyingKey, MockCircuit, Proof, SumCheckInstance,
    SumFoldProof,
};
use arithmetic::eq_poly::EqPolynomial;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_poly::DenseMultilinearExtension;
use ark_std::rand::Rng;
use ark_std::test_rng;
use deNetwork::{DeMultiNet as Net, DeNet, DeSerNet};
use hyperplonk::prelude::build_f;
use hyperplonk::HyperPlonkSNARK;
use tracing::{debug, info, instrument};
use std::sync::Arc;
use ark_std::time::Instant;
use subroutines::poly_iop::prelude::SumCheck;
use subroutines::poly_iop::sum_check::verify_sum_fold;
use subroutines::pcs::PolynomialCommitmentScheme;
use subroutines::poly_iop::prelude::PolyIOP;
use subroutines::{BatchProof, Commitment, IOPProof};
use transcript::IOPTranscript;

/// Result type for deSnark operations.
pub type Result<T> = std::result::Result<T, DeSnarkError>;

/// Type aliases for clarity
pub type ProvingKey<E, PCS> = HyperPlonkProvingKey<E, PCS>;
pub type VerifyingKey<E, PCS> = HyperPlonkVerifyingKey<E, PCS>;

/// PCS trait bounds required for HyperPlonk compatibility.
pub trait HyperPlonkPCS<E: Pairing>:
    PolynomialCommitmentScheme<
        E,
        Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>,
        Point = Vec<E::ScalarField>,
        Evaluation = E::ScalarField,
        Commitment = Commitment<E>,
        BatchProof = BatchProof<E, Self>,
    > + Sized
{
}

impl<E, PCS> HyperPlonkPCS<E> for PCS
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<
        E,
        Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>,
        Point = Vec<E::ScalarField>,
        Evaluation = E::ScalarField,
        Commitment = Commitment<E>,
        BatchProof = BatchProof<E, PCS>,
    >,
{
}

/// Phase 0: Generate SRS from config.
///
/// The SRS log-size is `log_num_constraints - log_num_parties`,
/// matching the per-partition constraint count.
///
/// WARNING: Uses `test_rng()` — for testing only, not production.
///
/// # Arguments
/// * `config` - Protocol configuration
///
/// # Returns
/// * `PCS::SRS` - Structured Reference String for the PCS
#[instrument(level = "debug", skip_all, name = "setup")]
pub fn setup<E: Pairing, PCS: HyperPlonkPCS<E>>(
    config: &Config,
) -> Result<PCS::SRS> {
    let supported_log_size = config.log_num_constraints - config.log_num_parties;
    info!(
        "SRS generation: log_size = {} (log_constraints = {}, log_parties = {})",
        supported_log_size, config.log_num_constraints, config.log_num_parties
    );
    let mut rng = test_rng();
    let srs = PCS::gen_srs_for_testing(&mut rng, supported_log_size)
        .map_err(|e| DeSnarkError::InvalidParameters(format!("SRS generation failed: {e}")))?;
    info!("SRS generated successfully");
    Ok(srs)
}

/// Phase 1: Generate circuit, keys, and mock circuits.
///
/// Internally calls HyperPlonk preprocess to generate proving and verifying keys.
///
/// # Arguments
/// * `config` - Protocol configuration
/// * `srs` - Structured Reference String
///
/// # Returns
/// * `ProvingKey` - Key for proving
/// * `VerifyingKey` - Key for verification
/// * `Vec<MockCircuit>` - M circuits (each with index + public_inputs + witnesses)
#[instrument(level = "debug", skip_all, name = "make_circuit")]
pub fn make_circuit<E: Pairing, PCS: HyperPlonkPCS<E>>(
    config: &Config,
    srs: &PCS::SRS,
) -> Result<(ProvingKey<E, PCS>, VerifyingKey<E, PCS>, Vec<MockCircuit<E::ScalarField>>)> {
    // 1. Generate M partitioned mock circuits
    let num_instances = config.num_instances();
    let constraints_per_party = config.num_constraints() / config.num_parties();
    info!(
        "Building {} mock circuits (constraints_per_party = {}, gate = {:?})",
        num_instances, constraints_per_party, config.gate_type
    );
    let circuits = config.build_partitioned_circuits::<E::ScalarField>();
    info!(
        "Circuits built: {} instances, {} witness columns, {} selector columns, {} public inputs each",
        circuits.len(),
        circuits[0].index.params.num_witness_columns(),
        circuits[0].index.params.num_selector_columns(),
        circuits[0].public_inputs.len()
    );

    // 2. Preprocess using the first circuit's index
    info!(
        "Preprocessing: num_variables = {}, num_constraints = {}",
        circuits[0].index.num_variables(),
        circuits[0].index.params.num_constraints
    );
    let (pk, vk, _duration) =
        <PolyIOP<E::ScalarField> as HyperPlonkSNARK<E, PCS>>::preprocess(&circuits[0].index, srs)
            .map_err(|e| DeSnarkError::HyperPlonkError(e.to_string()))?;
    info!(
        "PK: {} selector commitments, {} permutation commitments, {} permutation oracles",
        pk.selector_commitments.len(),
        pk.permutation_commitments.len(),
        pk.permutation_oracles.len()
    );
    info!(
        "VK: {} selector commitments, {} permutation commitments",
        vk.selector_commitments.len(),
        vk.perm_commitments.len()
    );

    Ok((pk, vk, circuits))
}

/// Convert MockCircuits into SumCheck instances (one per circuit).
///
/// Each circuit's constraint polynomial `f(w_0(x), ..., w_d(x))` is built
/// from its gate function, selector oracles (from pk), and witness MLEs.
/// The claimed sum for each is 0 (a valid circuit satisfies all constraints
/// on the boolean hypercube).
///
/// This is the bridge from any circuit representation to the
/// circuit-agnostic `SumCheckInstance`.
///
/// # Arguments
/// * `pk` - Proving key (contains selector oracles and gate function)
/// * `circuits` - M mock circuits, each with witnesses and public inputs
///
/// # Returns
/// * `Vec<SumCheckInstance>` - One instance per circuit (VP + zero sum)
#[instrument(level = "debug", skip_all, name = "circuits_to_sumcheck")]
pub fn circuits_to_sumcheck<E: Pairing, PCS: HyperPlonkPCS<E>>(
    pk: &ProvingKey<E, PCS>,
    circuits: &[MockCircuit<E::ScalarField>],
) -> Result<Vec<SumCheckInstance<E::ScalarField>>> {
    let num_vars = pk.params.num_variables();
    let gate_func = &pk.params.gate_func;

    let instances: Vec<SumCheckInstance<E::ScalarField>> = circuits
        .iter()
        .map(|circuit| {
            let witness_mles: Vec<Arc<DenseMultilinearExtension<E::ScalarField>>> = circuit
                .witnesses
                .iter()
                .map(|w| Arc::new(DenseMultilinearExtension::from(w)))
                .collect();

            // Use each circuit's own selectors so each VP independently
            // satisfies its constraint (sum = 0). This is necessary because
            // each MockCircuit may have different selectors.
            let selector_mles: Vec<Arc<DenseMultilinearExtension<E::ScalarField>>> = circuit
                .index
                .selectors
                .iter()
                .map(|s| Arc::new(DenseMultilinearExtension::from(s)))
                .collect();

            let poly = build_f(gate_func, num_vars, &selector_mles, &witness_mles)
                .map_err(|e| DeSnarkError::HyperPlonkError(e.to_string()))?;

            Ok(SumCheckInstance::new(poly, E::ScalarField::from(0u64)))
        })
        .collect::<Result<Vec<_>>>()?;

    info!(
        "Converted {} circuits to SumCheck instances (num_vars = {}, max_degree = {})",
        instances.len(),
        instances[0].aux_info().num_variables,
        instances[0].aux_info().max_degree,
    );

    Ok(instances)
}

/// Phase 2: SumFold protocol - aggregate SumCheck instances.
///
/// Takes M SumCheck instances (each claiming sum = 0 over the boolean
/// hypercube) and folds them into a single instance via
/// the SumFold interactive argument.
///
/// Runs all three sum_fold versions (v1, v2, v3) and cross-validates
/// that they produce identical results.
///
/// # Arguments
/// * `instances` - M SumCheck instances to fold
/// * `transcript` - Fiat-Shamir transcript (threaded from caller)
///
/// # Returns
/// * `SumCheckInstance` - Folded single-instance (1 VP + 1 sum)
/// * `SumFoldProof` - SumFold proof with all verification data
pub fn prove_sumfold<F: PrimeField>(
    instances: Vec<SumCheckInstance<F>>,
    transcript: &mut IOPTranscript<F>,
) -> Result<(SumCheckInstance<F>, SumFoldProof<F>)> {
    if instances.is_empty() {
        return Err(DeSnarkError::InvalidParameters("no instances to fold".into()));
    }
    if !instances.len().is_power_of_two() {
        return Err(DeSnarkError::InvalidParameters(format!(
            "number of instances must be power of 2, got {}",
            instances.len()
        )));
    }

    let m = instances.len();
    info!("prove_sumfold: folding {} instances", m);

    // Extract polys and sums from instances
    let (polys, sums): (Vec<_>, Vec<_>) = instances
        .into_iter()
        .map(|inst| (inst.poly, inst.sum))
        .unzip();

    // In debug mode, save copies for v1/v3 before v2 consumes the originals
    #[cfg(debug_assertions)]
    let (polys_v1, sums_v1, polys_v3, sums_v3) = {
        let p1 = polys.iter().map(|p| p.deep_copy()).collect::<Vec<_>>();
        let s1 = sums.clone();
        let p3 = polys.iter().map(|p| p.deep_copy()).collect::<Vec<_>>();
        let s3 = sums.clone();
        (p1, s1, p3, s3)
    };

    // ═══════════════════════════════════════════════════════════════
    // Run v2 (always) — uses originals directly, no copy in release
    // ═══════════════════════════════════════════════════════════════
    let start = Instant::now();
    let (_proof_v2, _sum_t_v2, _aux_info_v2, folded_poly_v2, v_v2) =
        <PolyIOP<F> as SumCheck<F>>::sum_fold_v2(polys, sums, transcript)
            .map_err(|e| DeSnarkError::HyperPlonkError(format!("sum_fold v2 failed: {e}")))?;
    let dur_v2 = start.elapsed();
    info!("sum_fold v2: {:?}", dur_v2);
    info!("v v2: {:?}", v_v2);

    // ═══════════════════════════════════════════════════════════════
    // Run v1 & v3 and cross-validate (debug only)
    // ═══════════════════════════════════════════════════════════════
    #[cfg(debug_assertions)]
    {
        // Run v1
        let start = Instant::now();
        let mut transcript_v1 = <PolyIOP<F> as SumCheck<F>>::init_transcript();
        let (proof_v1, sum_t_v1, aux_info_v1, folded_poly_v1, v_v1) =
            <PolyIOP<F> as SumCheck<F>>::sum_fold(polys_v1, sums_v1, &mut transcript_v1)
                .map_err(|e| DeSnarkError::HyperPlonkError(format!("sum_fold v1 failed: {e}")))?;
        let dur_v1 = start.elapsed();
        info!("sum_fold v1: {:?}", dur_v1);
        info!("v v1: {:?}", v_v1);

        // Run v3
        let start = Instant::now();
        let mut transcript_v3 = <PolyIOP<F> as SumCheck<F>>::init_transcript();
        let (proof_v3, sum_t_v3, aux_info_v3, folded_poly_v3, v_v3) =
            <PolyIOP<F> as SumCheck<F>>::sum_fold_v3(polys_v3, sums_v3, &mut transcript_v3)
                .map_err(|e| DeSnarkError::HyperPlonkError(format!("sum_fold v3 failed: {e}")))?;
        let dur_v3 = start.elapsed();
        info!("sum_fold v3: {:?}", dur_v3);
        info!("v v3: {:?}", v_v3);

        // v1 vs v2
        assert_eq!(sum_t_v1, _sum_t_v2, "sum_t mismatch: v1 vs v2");
        assert_eq!(v_v1, v_v2, "v mismatch: v1 vs v2");
        assert_eq!(proof_v1, _proof_v2, "proof mismatch: v1 vs v2");
        assert_eq!(
            aux_info_v1.max_degree, _aux_info_v2.max_degree,
            "aux_info max_degree mismatch: v1 vs v2"
        );
        assert_eq!(
            aux_info_v1.num_variables, _aux_info_v2.num_variables,
            "aux_info num_variables mismatch: v1 vs v2"
        );
        for j in 0..folded_poly_v1.flattened_ml_extensions.len() {
            assert_eq!(
                folded_poly_v1.flattened_ml_extensions[j].evaluations,
                folded_poly_v2.flattened_ml_extensions[j].evaluations,
                "folded MLE[{}] mismatch: v1 vs v2",
                j
            );
        }

        // v2 vs v3
        assert_eq!(_sum_t_v2, sum_t_v3, "sum_t mismatch: v2 vs v3");
        assert_eq!(v_v2, v_v3, "v mismatch: v2 vs v3");
        assert_eq!(_proof_v2, proof_v3, "proof mismatch: v2 vs v3");
        assert_eq!(
            _aux_info_v2.max_degree, aux_info_v3.max_degree,
            "aux_info max_degree mismatch: v2 vs v3"
        );
        assert_eq!(
            _aux_info_v2.num_variables, aux_info_v3.num_variables,
            "aux_info num_variables mismatch: v2 vs v3"
        );
        for j in 0..folded_poly_v2.flattened_ml_extensions.len() {
            assert_eq!(
                folded_poly_v2.flattened_ml_extensions[j].evaluations,
                folded_poly_v3.flattened_ml_extensions[j].evaluations,
                "folded MLE[{}] mismatch: v2 vs v3",
                j
            );
        }

        info!(
            "All 3 versions match! sum_t={:?}, v={:?}",
            sum_t_v1, v_v1
        );
        info!(
            "Timing: v1={:?}, v2={:?}, v3={:?} | speedup v1/v2={:.2}x, v2/v3={:.2}x",
            dur_v1,
            dur_v2,
            dur_v3,
            dur_v1.as_secs_f64() / dur_v2.as_secs_f64(),
            dur_v2.as_secs_f64() / dur_v3.as_secs_f64(),
        );
    }

    // Return v2 result (best single-machine version)
    let folded_instance = SumCheckInstance::new(folded_poly_v2, v_v2);
    let sumfold_proof = SumFoldProof::new(_proof_v2, _sum_t_v2, _aux_info_v2, v_v2);
    Ok((folded_instance, sumfold_proof))
}

/// Combine and verify K parties' SumFold proofs (pure verifier — no witness data).
///
/// In the distributed SumFold protocol, all K parties share the same
/// Fiat-Shamir transcript: challenges are derived from **aggregated**
/// prover messages (element-wise sum across parties). Each party
/// contributes its partial prover messages, partial sum_t, and partial v.
///
/// This function:
/// 1. **Combines** K partial proofs into a single SumCheck proof
///    by summing prover messages element-wise per round
/// 2. **Verifies** the combined proof via `verify_sum_fold` (log₂(M) rounds)
/// 3. **Checks** consistency: `c == v_total · eq(ρ, r_b)`
///
/// # Arguments
/// * `party_proofs` - K SumFold proofs (partial contributions from each party)
///   All must share the same challenges (from the distributed protocol).
///
/// # Returns
/// * `F` - Verified total claimed sum `v_total = Σᵢ vᵢ`
#[instrument(level = "debug", skip_all, name = "merge_and_verify")]
pub fn merge_and_verify_sumfold<F: PrimeField>(
    party_proofs: Vec<SumFoldProof<F>>,
) -> Result<F> {
    let k = party_proofs.len();
    if k == 0 {
        return Err(DeSnarkError::InvalidParameters(
            "no proofs to verify".into(),
        ));
    }

    let num_rounds = party_proofs[0].q_aux_info.num_variables;
    info!(
        "merge_and_verify_sumfold: combining {} parties' proofs ({} rounds)",
        k, num_rounds
    );

    // Validate: all proofs have compatible structure
    for (i, sfp) in party_proofs.iter().enumerate().skip(1) {
        if sfp.q_aux_info.num_variables != num_rounds
            || sfp.q_aux_info.max_degree != party_proofs[0].q_aux_info.max_degree
        {
            return Err(DeSnarkError::InvalidParameters(format!(
                "Party {i}'s aux_info incompatible with party 0"
            )));
        }
        if sfp.proof.proofs.len() != num_rounds {
            return Err(DeSnarkError::InvalidParameters(format!(
                "Party {i} has {} round messages, expected {}",
                sfp.proof.proofs.len(),
                num_rounds
            )));
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Step 1: Combine K partial proofs into a single SumCheck proof
    // Sum prover messages element-wise per round
    // ═══════════════════════════════════════════════════════════════
    let mut combined_msgs = party_proofs[0].proof.proofs.clone();
    for sfp in &party_proofs[1..] {
        for (round, msg) in sfp.proof.proofs.iter().enumerate() {
            for (j, eval) in msg.evaluations.iter().enumerate() {
                combined_msgs[round].evaluations[j] += eval;
            }
        }
    }

    // Shared challenges (all parties derived the same challenges
    // from the aggregated prover messages in the distributed protocol)
    let combined_proof = IOPProof {
        point: party_proofs[0].proof.point.clone(),
        proofs: combined_msgs,
    };

    let combined_sum_t: F = party_proofs.iter().map(|p| p.sum_t).sum();
    let v_total: F = party_proofs.iter().map(|p| p.v).sum();

    debug!(
        "Combined {} proofs: sum_t={:?}, v_total={:?}",
        k, combined_sum_t, v_total
    );

    // ═══════════════════════════════════════════════════════════════
    // Step 2: Verify combined proof as a single SumCheck (log₂(M) rounds)
    // ═══════════════════════════════════════════════════════════════
    let (subclaim, rho) =
        verify_sum_fold(combined_sum_t, &combined_proof, &party_proofs[0].q_aux_info)
            .map_err(|e| {
                DeSnarkError::HyperPlonkError(format!(
                    "Combined sumfold SumCheck verification failed: {e}"
                ))
            })?;

    // ═══════════════════════════════════════════════════════════════
    // Step 3: Consistency check: c = v_total · eq(ρ, r_b)
    // ═══════════════════════════════════════════════════════════════
    let eq_poly = EqPolynomial::new(rho);
    let eq_val = eq_poly.evaluate(&subclaim.point);
    let expected_c = v_total * eq_val;
    if subclaim.expected_evaluation != expected_c {
        return Err(DeSnarkError::HyperPlonkError(format!(
            "Combined sumfold consistency check failed: \
             c={:?} != v_total·eq(ρ,rb)={:?}",
            subclaim.expected_evaluation, expected_c
        )));
    }

    info!(
        "Combined proof verified: v_total={:?}, {} rounds",
        v_total, num_rounds
    );

    Ok(v_total)
}

/// Phase 3: HyperPianist proof - distributed SumCheck on the folded instance.
///
/// Runs `d_prove` (two-phase distributed SumCheck) on the folded VP.
/// Master returns `Some(Proof)` with the SumCheck proof;
/// workers return `None` (they participated in network aggregation only).
///
/// # Arguments
/// * `_pk` - Proving key (will be used for PCS openings in future)
/// * `instance` - Folded SumCheck instance (single VP + sum)
/// * `transcript` - Fiat-Shamir transcript (carries SumFold state)
///
/// # Returns
/// * `Option<Proof>` - `Some` on master, `None` on workers
pub fn prove_hyper_pianist<E: Pairing, PCS: HyperPlonkPCS<E>>(
    _pk: &ProvingKey<E, PCS>,
    instance: &SumCheckInstance<E::ScalarField>,
    transcript: &mut IOPTranscript<E::ScalarField>,
) -> Result<Option<Proof<E::ScalarField>>> {
    // Run distributed SumCheck on the folded instance
    let sumcheck_proof =
        <PolyIOP<E::ScalarField> as SumCheck<E::ScalarField>>::d_prove::<Net>(
            &instance.poly,
            transcript,
        )
        .map_err(|e| DeSnarkError::HyperPlonkError(format!("d_prove failed: {e}")))?;

    // Master has the proof; workers return None
    match sumcheck_proof {
        Some(sumcheck_proof) => {
            info!(
                "d_prove complete: {} rounds, point dimension = {}",
                sumcheck_proof.proofs.len(),
                sumcheck_proof.point.len()
            );
            // TODO: PCS opening phase (accumulate polys, evaluate, d_multi_open)
            Ok(Some(Proof { sumcheck_proof }))
        }
        None => Ok(None),
    }
}

/// Verify network connectivity with a synchronized round-trip challenge.
///
/// Protocol:
/// 1. Master generates a random challenge `r`
/// 2. Master broadcasts `r` to all workers
/// 3. Each worker sends `r + party_id` back to master
/// 4. Master verifies all responses
/// 5. Master broadcasts pass/fail to all workers
/// 6. All workers check the result
///
/// Must be called after `Net::init_from_file`.
pub fn verify_network() -> Result<()> {
    let party_id = Net::party_id();
    let n_parties = Net::n_parties();
    info!(
        "[Party {}] Starting network verification ({} parties)...",
        party_id, n_parties
    );

    // Step 1-2: Master generates and broadcasts random challenge
    let r: u64 = Net::recv_from_master_uniform(Net::am_master().then(|| {
        let r: u64 = test_rng().gen();
        info!("[Party 0] Broadcasting challenge: {}", r);
        r
    }));
    info!("[Party {}] Received challenge: {}", party_id, r);

    // Step 3: Each party sends (r + party_id) back to master
    // collected[i] is guaranteed to be party i's response (indexed by party ID in DeMultiNet)
    let response = r.wrapping_add(party_id as u64);
    let collected: Option<Vec<u64>> = Net::send_to_master(&response);

    // Step 4: Master forwards all collected responses to every party
    let all_responses: Vec<u64> = Net::recv_from_master_uniform(collected);

    // Step 5: Each party verifies all responses locally
    for (i, resp) in all_responses.iter().enumerate() {
        let expected = r.wrapping_add(i as u64);
        if *resp != expected {
            return Err(DeSnarkError::NetworkError(format!(
                "Party {} verification failed: got {}, expected {}",
                i, resp, expected
            )));
        } else {
            debug!(
                "[Party {}] Verified response from party {}: got {}, expected {}",
                party_id, i, resp, expected
            );
        }
    }

    info!("[Party {}] Network verification passed", party_id);
    Ok(())
}

/// Distributed SNARK prove - complete end-to-end pipeline.
///
/// The network must be initialized (via `Net::init_from_file`) before calling.
/// The caller is responsible for `Net::deinit()` after this returns.
///
/// # Flow
/// 1. verify_network() - round-trip connectivity check
/// 2. setup(config) -> SRS
/// 3. make_circuit(config, srs) -> (PK, VK, Vec<MockCircuit>)
/// 4. circuits_to_sumcheck(pk, circuits) -> Vec<SumCheckInstance>
/// 5. prove_sumfold(instances) -> (folded SumCheckInstance, SumFold Proof)
/// 6. prove_hyper_pianist(pk, folded_instance) -> Final Proof
///
/// # Arguments
/// * `config` - Protocol configuration
///
/// # Returns
/// * `VerifyingKey` - For verification
/// * `Option<Proof>` - Final SNARK proof (`Some` on master, `None` on workers)
pub fn dist_prove<E: Pairing, PCS: HyperPlonkPCS<E>>(
    config: &Config,
) -> Result<(VerifyingKey<E, PCS>, Option<Proof<E::ScalarField>>)> {
    // Step 0: Verify network connectivity
    verify_network()?;

    // Phase 0: Setup
    let srs = setup::<E, PCS>(config)?;

    // Phase 1: Make circuit
    let (pk, vk, circuits) = make_circuit::<E, PCS>(config, &srs)?;

    // Phase 1.5: Convert circuits to SumCheck instances
    let instances = circuits_to_sumcheck::<E, PCS>(&pk, &circuits)?;

    // Create a single transcript threaded through all proving phases
    let mut transcript =
        <PolyIOP<E::ScalarField> as SumCheck<E::ScalarField>>::init_transcript();

    // Phase 2: SumFold aggregation (circuit-agnostic)
    let (folded_instance, sumfold_proof) = prove_sumfold(instances, &mut transcript)?;

    #[cfg(debug_assertions)]
    {
        let v_total = merge_and_verify_sumfold(vec![sumfold_proof.clone()])?;
        debug!("SumFold verify passed: v_total={:?}", v_total);
    }
    let _ = sumfold_proof;

    // Phase 3: HyperPianist distributed SumCheck (operates on folded instance)
    let proof = prove_hyper_pianist::<E, PCS>(&pk, &folded_instance, &mut transcript)?;

    Ok((vk, proof))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structs::GateType;

    #[test]
    fn test_build_partitioned_circuits() {
        use ark_bn254::Fr;
        let config = Config::new(2, 10, GateType::Vanilla, 2);
        let circuits = config.build_partitioned_circuits::<Fr>();

        // M = 4 instances
        assert_eq!(circuits.len(), 4);

        // Each partition: 1024 / 4 = 256 constraints
        for circuit in &circuits {
            assert_eq!(circuit.index.params.num_constraints, 256);
            assert!(circuit.is_satisfied());
        }
    }

    /// End-to-end test: build circuits → convert to SumCheck instances → prove_sumfold.
    /// Validates that v1, v2, v3 produce identical results on real circuit polynomials.
    #[test]
    fn test_prove_sumfold_e2e() {
        use ark_bn254::{Bn254, Fr};
        use subroutines::MultilinearKzgPCS;

        // ν=2 → M=4 instances, μ=10 → N=1024, κ=2 → K=4 parties
        let config = Config::new(2, 10, GateType::Vanilla, 2);

        // Setup
        let srs = setup::<Bn254, MultilinearKzgPCS<Bn254>>(&config)
            .expect("SRS generation failed");

        // Make circuit
        let (pk, _vk, circuits) =
            make_circuit::<Bn254, MultilinearKzgPCS<Bn254>>(&config, &srs)
                .expect("make_circuit failed");

        // Convert to SumCheck instances
        let instances = circuits_to_sumcheck::<Bn254, MultilinearKzgPCS<Bn254>>(&pk, &circuits)
            .expect("circuits_to_sumcheck failed");

        assert_eq!(instances.len(), 4);
        for inst in &instances {
            assert_eq!(inst.sum, Fr::from(0u64));
        }

        // Prove sumfold (runs v1, v2, v3 and cross-validates)
        let mut transcript = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
        let (folded, _proof) = prove_sumfold(instances, &mut transcript).expect("prove_sumfold failed");

        // The folded polynomial should have the same num_variables as the original instances
        assert_eq!(
            folded.poly.aux_info.num_variables,
            config.log_num_constraints - config.log_num_parties
        );
        println!(
            "Folded instance: num_vars={}, max_degree={}, v={:?}",
            folded.poly.aux_info.num_variables,
            folded.poly.aux_info.max_degree,
            folded.sum
        );
    }

    /// Test merge_and_verify_sumfold with K=1 (trivial combine).
    ///
    /// With K=1 the combined proof equals the original — verification
    /// replays the same transcript and succeeds.
    /// K>1 requires the distributed SumFold prover (shared challenges).
    #[test]
    fn test_merge_and_verify_sumfold() {
        use ark_bn254::{Bn254, Fr};
        use subroutines::MultilinearKzgPCS;

        // ν=2 → M=4 instances, μ=10 → N=1024, κ=2 → K=4 parties
        let config = Config::new(2, 10, GateType::Vanilla, 2);

        let srs = setup::<Bn254, MultilinearKzgPCS<Bn254>>(&config)
            .expect("SRS generation failed");
        let (pk, _vk, _) =
            make_circuit::<Bn254, MultilinearKzgPCS<Bn254>>(&config, &srs)
                .expect("make_circuit failed");

        // K=1: single party folds M=4 instances
        let circuits = config.build_partitioned_circuits::<Fr>();
        let instances =
            circuits_to_sumcheck::<Bn254, MultilinearKzgPCS<Bn254>>(&pk, &circuits)
                .expect("circuits_to_sumcheck failed");
        assert_eq!(instances.len(), 4);

        for inst in &instances {
            assert_eq!(inst.sum, Fr::from(0u64));
        }

        let mut transcript = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
        let (_folded, proof) = prove_sumfold(instances, &mut transcript).expect("prove_sumfold failed");

        // Combine + verify with K=1 (trivial: combined proof == original)
        let v_total = merge_and_verify_sumfold(vec![proof])
            .expect("merge_and_verify_sumfold failed");

        println!("Verified: v_total={:?}", v_total);
    }
}
