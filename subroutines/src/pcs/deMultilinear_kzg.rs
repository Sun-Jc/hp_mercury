//! Distributed Multilinear KZG Polynomial Commitment Scheme.
//!
//! This module provides distributed commit and open operations for multilinear
//! polynomials, using the standard MultilinearKzgPCS types underneath.
//!
//! Requires the `distributed` feature to be enabled.

#[cfg(feature = "distributed")]
use deNetwork::{DeMultiNet as Net, DeNet, DeSerNet};

use crate::pcs::{
    multilinear_kzg::{
        srs::{MultilinearProverParam, MultilinearUniversalParams, MultilinearVerifierParam},
        MultilinearKzgPCS, MultilinearKzgProof,
    },
    prelude::{Commitment, PCSError},
    PolynomialCommitmentScheme,
};
use arithmetic::DenseMultilinearExtension;
use ark_ec::{pairing::Pairing, scalar_mul::variable_base::VariableBaseMSM, CurveGroup};
use ark_poly::MultilinearExtension;
use ark_std::{sync::Arc, vec::Vec};

/// Distributed Multilinear KZG - wrapper providing distributed operations.
///
/// This struct provides `d_commit` and `d_open` methods that coordinate
/// across multiple parties using deNetwork.
pub struct DeMkzg<E: Pairing> {
    _phantom: std::marker::PhantomData<E>,
}

impl<E: Pairing> DeMkzg<E> {
    /// Distributed commit: each party commits to its local polynomial slice,
    /// then aggregates to master.
    ///
    /// # Arguments
    /// * `prover_param` - Prover parameters (SRS slice for this party)
    /// * `poly` - Local polynomial (2^μ evaluations for this party)
    ///
    /// # Returns
    /// * `Ok(Some(commitment))` on master node
    /// * `Ok(None)` on non-master nodes
    #[cfg(feature = "distributed")]
    pub fn d_commit(
        prover_param: &MultilinearProverParam<E>,
        poly: &Arc<DenseMultilinearExtension<E::ScalarField>>,
    ) -> Result<Option<Commitment<E>>, PCSError> {
        use ark_std::{end_timer, start_timer, Zero};

        let commit_timer = start_timer!(|| "DeMkzg::d_commit");

        let scalars: Vec<_> = poly.to_evaluations();

        // Get the correct SRS slice for this party's polynomial
        // powers_of_g[0] has 2^nv elements
        let bases = &prover_param.powers_of_g[0].evals[..scalars.len()];

        // Local MSM - convert to G1Affine for network transfer
        let local_commit: E::G1Affine = E::G1MSM::msm_unchecked(bases, &scalars).into();

        // Aggregate to master
        let sub_comms: Option<Vec<E::G1Affine>> = Net::send_to_master(&local_commit);

        end_timer!(commit_timer);

        if Net::am_master() {
            // Sum all sub-commitments (convert to projective for addition)
            let final_commit: E::G1 = sub_comms
                .unwrap()
                .into_iter()
                .fold(E::G1::zero(), |acc, x| acc + x);
            Ok(Some(Commitment(final_commit.into_affine())))
        } else {
            Ok(None)
        }
    }

    /// Batch distributed commit for multiple polynomials.
    #[cfg(feature = "distributed")]
    pub fn batch_d_commit(
        prover_param: &MultilinearProverParam<E>,
        polys: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
    ) -> Result<Vec<Option<Commitment<E>>>, PCSError> {
        polys
            .iter()
            .map(|poly| Self::d_commit(prover_param, poly))
            .collect()
    }

    /// Standard (non-distributed) commit using MultilinearKzgPCS.
    pub fn commit(
        prover_param: &MultilinearProverParam<E>,
        poly: &Arc<DenseMultilinearExtension<E::ScalarField>>,
    ) -> Result<Commitment<E>, PCSError> {
        MultilinearKzgPCS::<E>::commit(prover_param, poly)
    }

    /// Standard (non-distributed) open using MultilinearKzgPCS.
    pub fn open(
        prover_param: &MultilinearProverParam<E>,
        poly: &Arc<DenseMultilinearExtension<E::ScalarField>>,
        point: &[E::ScalarField],
    ) -> Result<(MultilinearKzgProof<E>, E::ScalarField), PCSError> {
        MultilinearKzgPCS::<E>::open(prover_param, poly, &point.to_vec())
    }

    /// Standard verify using MultilinearKzgPCS.
    pub fn verify(
        verifier_param: &MultilinearVerifierParam<E>,
        commitment: &Commitment<E>,
        point: &[E::ScalarField],
        value: &E::ScalarField,
        proof: &MultilinearKzgProof<E>,
    ) -> Result<bool, PCSError> {
        MultilinearKzgPCS::<E>::verify(verifier_param, commitment, &point.to_vec(), value, proof)
    }

    /// Generate SRS for testing (delegates to MultilinearKzgPCS).
    pub fn gen_srs_for_testing<R: ark_std::rand::Rng>(
        rng: &mut R,
        num_vars: usize,
    ) -> Result<MultilinearUniversalParams<E>, PCSError> {
        MultilinearKzgPCS::<E>::gen_srs_for_testing(rng, num_vars)
    }

    /// Trim SRS to specific size (delegates to MultilinearKzgPCS).
    pub fn trim(
        srs: &MultilinearUniversalParams<E>,
        num_vars: usize,
    ) -> Result<(MultilinearProverParam<E>, MultilinearVerifierParam<E>), PCSError> {
        MultilinearKzgPCS::<E>::trim(srs, None, Some(num_vars))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_std::{test_rng, UniformRand};

    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;

    #[test]
    fn test_demkzg_commit_open_verify() {
        let mut rng = test_rng();
        let num_vars = 4;

        // Generate SRS
        let srs = DeMkzg::<E>::gen_srs_for_testing(&mut rng, num_vars).unwrap();
        let (pk, vk) = DeMkzg::<E>::trim(&srs, num_vars).unwrap();

        // Create random polynomial
        let evals: Vec<Fr> = (0..(1 << num_vars)).map(|_| Fr::rand(&mut rng)).collect();
        let poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars, evals,
        ));

        // Commit
        let commitment = DeMkzg::<E>::commit(&pk, &poly).unwrap();

        // Random evaluation point
        let point: Vec<Fr> = (0..num_vars).map(|_| Fr::rand(&mut rng)).collect();

        // Open
        let (proof, eval) = DeMkzg::<E>::open(&pk, &poly, &point).unwrap();

        // Verify
        let result = DeMkzg::<E>::verify(&vk, &commitment, &point, &eval, &proof).unwrap();
        assert!(result, "Verification should pass");
    }

    #[test]
    fn test_demkzg_wrong_eval_fails() {
        let mut rng = test_rng();
        let num_vars = 3;

        let srs = DeMkzg::<E>::gen_srs_for_testing(&mut rng, num_vars).unwrap();
        let (pk, vk) = DeMkzg::<E>::trim(&srs, num_vars).unwrap();

        let evals: Vec<Fr> = (0..(1 << num_vars)).map(|_| Fr::rand(&mut rng)).collect();
        let poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars, evals,
        ));

        let commitment = DeMkzg::<E>::commit(&pk, &poly).unwrap();
        let point: Vec<Fr> = (0..num_vars).map(|_| Fr::rand(&mut rng)).collect();
        let (proof, _eval) = DeMkzg::<E>::open(&pk, &poly, &point).unwrap();

        // Use wrong evaluation
        let wrong_eval = Fr::rand(&mut rng);
        let result = DeMkzg::<E>::verify(&vk, &commitment, &point, &wrong_eval, &proof).unwrap();
        assert!(!result, "Verification should fail with wrong evaluation");
    }

    #[test]
    fn test_demkzg_multiple_polys() {
        let mut rng = test_rng();
        let num_vars = 3;
        let num_polys = 5;

        let srs = DeMkzg::<E>::gen_srs_for_testing(&mut rng, num_vars).unwrap();
        let (pk, vk) = DeMkzg::<E>::trim(&srs, num_vars).unwrap();

        for _ in 0..num_polys {
            let evals: Vec<Fr> = (0..(1 << num_vars)).map(|_| Fr::rand(&mut rng)).collect();
            let poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(
                num_vars, evals,
            ));

            let commitment = DeMkzg::<E>::commit(&pk, &poly).unwrap();
            let point: Vec<Fr> = (0..num_vars).map(|_| Fr::rand(&mut rng)).collect();
            let (proof, eval) = DeMkzg::<E>::open(&pk, &poly, &point).unwrap();

            assert!(DeMkzg::<E>::verify(&vk, &commitment, &point, &eval, &proof).unwrap());
        }
    }
}
