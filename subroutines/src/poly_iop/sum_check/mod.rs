// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the HyperPlonk library.

// You should have received a copy of the MIT License
// along with the HyperPlonk library. If not, see <https://mit-license.org/>.

//! This module implements the sum check protocol.

use crate::{barycentric_weights, extrapolate,poly_iop::{
    errors::PolyIOPErrors,
    structs::{IOPProof, IOPProverMessage, IOPProverState, IOPVerifierState},
    PolyIOP,
}};

use ark_ff::PrimeField;
use ark_poly::{DenseMultilinearExtension,MultilinearExtension};
use ark_std::cfg_into_iter;
use ark_std::log2;
use transcript::IOPTranscript;
use arithmetic::eq_poly::EqPolynomial;
use arithmetic::{build_eq_x_r, build_eq_x_r_vec, fix_variables, unipoly::interpolate_uni_poly, VPAuxInfo, VirtualPolynomial};
use std::{collections::HashMap, fmt::Debug, marker::PhantomData, sync::Arc};
use rayon::iter::{IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator, IntoParallelIterator};
use ark_std::time::Instant;

mod prover;
mod verifier;

#[cfg(feature = "distributed")]
pub mod dist_sum_fold;

/// Trait for doing sum check protocols.
pub trait SumCheck<F: PrimeField> {
    type VirtualPolynomial;
    type VPAuxInfo;
    type MultilinearExtension;

    type SumCheckProof: Clone + Debug + Default + PartialEq;
    type Transcript;
    type SumCheckSubClaim: Clone + Debug + Default + PartialEq;

    /// Extract sum from the proof
    fn extract_sum(proof: &Self::SumCheckProof) -> F;

    /// Initialize the system with a transcript
    ///
    /// This function is optional -- in the case where a SumCheck is
    /// an building block for a more complex protocol, the transcript
    /// may be initialized by this complex protocol, and passed to the
    /// SumCheck prover/verifier.
    fn init_transcript() -> Self::Transcript;

    /// Generate proof of the sum of polynomial over {0,1}^`num_vars`
    ///
    /// The polynomial is represented in the form of a VirtualPolynomial.
    fn prove(
        poly: &Self::VirtualPolynomial,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::SumCheckProof, PolyIOPErrors>;

    /// Verify the claimed sum using the proof
    fn verify(
        sum: F,
        proof: &Self::SumCheckProof,
        aux_info: &Self::VPAuxInfo,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::SumCheckSubClaim, PolyIOPErrors>;

    fn sum_fold(
        polys: Vec<VirtualPolynomial<F>>,
        sums: Vec<F>,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<(Self::SumCheckProof, F, VPAuxInfo<F>, VirtualPolynomial<F>, F), PolyIOPErrors>;

    /// Optimized version of sum_fold with MLE transform and reduced allocations.
    /// Produces identical results to sum_fold but with better performance.
    fn sum_fold_v2(
        polys: Vec<VirtualPolynomial<F>>,
        sums: Vec<F>,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<(Self::SumCheckProof, F, VPAuxInfo<F>, VirtualPolynomial<F>, F), PolyIOPErrors>;

    /// Split-and-merge version of sum_fold using VirtualPolynomial::split_by_last_variables.
    /// 
    /// Strategy: m VPs → split each by last `length` vars → m² sub-VPs → merge by split index → m merged VPs
    /// Uses sequential execution and eq-weighted sums.
    fn sum_fold_v3(
        polys: Vec<VirtualPolynomial<F>>,
        sums: Vec<F>,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<(Self::SumCheckProof, F, VPAuxInfo<F>, VirtualPolynomial<F>, F), PolyIOPErrors>;
}

/// Trait for sum check protocol prover side APIs.
pub trait SumCheckProver<F: PrimeField>
where
    Self: Sized,
{
    type VirtualPolynomial;
    type ProverMessage;

    /// Initialize the prover state to argue for the sum of the input polynomial
    /// over {0,1}^`num_vars`.
    fn prover_init(polynomial: &Self::VirtualPolynomial) -> Result<Self, PolyIOPErrors>;

    /// Receive message from verifier, generate prover message, and proceed to
    /// next round.
    ///
    /// Main algorithm used is from section 3.2 of [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.2).
    fn prove_round_and_update_state(
        &mut self,
        challenge: &Option<F>,
    ) -> Result<Self::ProverMessage, PolyIOPErrors>;
}

/// Trait for sum check protocol verifier side APIs.
pub trait SumCheckVerifier<F: PrimeField> {
    type VPAuxInfo;
    type ProverMessage;
    type Challenge;
    type Transcript;
    type SumCheckSubClaim;

    /// Initialize the verifier's state.
    fn verifier_init(index_info: &Self::VPAuxInfo) -> Self;

    /// Run verifier for the current round, given a prover message.
    ///
    /// Note that `verify_round_and_update_state` only samples and stores
    /// challenges; and update the verifier's state accordingly. The actual
    /// verifications are deferred (in batch) to `check_and_generate_subclaim`
    /// at the last step.
    fn verify_round_and_update_state(
        &mut self,
        prover_msg: &Self::ProverMessage,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::Challenge, PolyIOPErrors>;

    /// This function verifies the deferred checks in the interactive version of
    /// the protocol; and generate the subclaim. Returns an error if the
    /// proof failed to verify.
    ///
    /// If the asserted sum is correct, then the multilinear polynomial
    /// evaluated at `subclaim.point` will be `subclaim.expected_evaluation`.
    /// Otherwise, it is highly unlikely that those two will be equal.
    /// Larger field size guarantees smaller soundness error.
    fn check_and_generate_subclaim(
        &self,
        asserted_sum: &F,
    ) -> Result<Self::SumCheckSubClaim, PolyIOPErrors>;
}

/// A SumCheckSubClaim is a claim generated by the verifier at the end of
/// verification when it is convinced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SumCheckSubClaim<F: PrimeField> {
    /// the multi-dimensional point that this multilinear extension is evaluated
    /// to
    pub point: Vec<F>,
    /// the expected evaluation
    pub expected_evaluation: F,
}

impl<F: PrimeField> SumCheck<F> for PolyIOP<F> {
    type SumCheckProof = IOPProof<F>;
    type VirtualPolynomial = VirtualPolynomial<F>;
    type VPAuxInfo = VPAuxInfo<F>;
    type MultilinearExtension = Arc<DenseMultilinearExtension<F>>;
    type SumCheckSubClaim = SumCheckSubClaim<F>;
    type Transcript = IOPTranscript<F>;

    fn extract_sum(proof: &Self::SumCheckProof) -> F {
        let res = proof.proofs[0].evaluations[0] + proof.proofs[0].evaluations[1];
        res
    }

    fn init_transcript() -> Self::Transcript {
        let res = IOPTranscript::<F>::new(b"Initializing SumCheck transcript");
        res
    }

    fn prove(
        poly: &Self::VirtualPolynomial,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::SumCheckProof, PolyIOPErrors> {
        transcript.append_serializable_element(b"aux info", &poly.aux_info)?;

        let mut prover_state = IOPProverState::prover_init(poly)?;
        let mut challenge = None;
        let mut prover_msgs = Vec::with_capacity(poly.aux_info.num_variables);
        for _ in 0..poly.aux_info.num_variables {
            let prover_msg =
                IOPProverState::prove_round_and_update_state(&mut prover_state, &challenge)?;
            transcript.append_serializable_element(b"prover msg", &prover_msg)?;
            prover_msgs.push(prover_msg);
            challenge = Some(transcript.get_and_append_challenge(b"Internal round")?);
        }
        // pushing the last challenge point to the state
        if let Some(p) = challenge {
            prover_state.challenges.push(p)
        };

        Ok(IOPProof {
            point: prover_state.challenges,
            proofs: prover_msgs,
        })
    }

    fn verify(
        claimed_sum: F,
        proof: &Self::SumCheckProof,
        aux_info: &Self::VPAuxInfo,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::SumCheckSubClaim, PolyIOPErrors> {
        transcript.append_serializable_element(b"aux info", aux_info)?;
        let mut verifier_state = IOPVerifierState::verifier_init(aux_info);
        for i in 0..aux_info.num_variables {
            let prover_msg = proof.proofs.get(i).expect("proof is incomplete");
            transcript.append_serializable_element(b"prover msg", prover_msg)?;
            IOPVerifierState::verify_round_and_update_state(
                &mut verifier_state,
                prover_msg,
                transcript,
            )?;
        }

        let res = IOPVerifierState::check_and_generate_subclaim(&verifier_state, &claimed_sum);
        res
    }

    fn sum_fold(
        polys: Vec<VirtualPolynomial<F>>,
        sums: Vec<F>,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<(Self::SumCheckProof, F, VPAuxInfo<F>, VirtualPolynomial<F>, F), PolyIOPErrors> {
        let m = polys.len();
        let t = polys[0].flattened_ml_extensions.len();
        let num_vars = polys[0].aux_info.num_variables;
        let length = log2(m) as usize;
    
        let q_aux_info = VPAuxInfo::<F> {
            max_degree: polys[0].aux_info.max_degree + 1,
            num_variables: length,
            phantom: PhantomData::default(),
        };
    
        transcript.append_serializable_element(b"aux info", &q_aux_info)?;
        let rho: Vec<F> = transcript.get_and_append_challenge_vectors(b"sumfold rho", length)?;
        let eq_poly = EqPolynomial::new(rho.clone());
        let eq_xr_poly = build_eq_x_r(&rho)?;
    
        // compute the sum T
        let mut sum_t = F::zero();
        let eq_xr_vec = eq_xr_poly.to_evaluations();
        for i in 0..m {
            sum_t += eq_xr_vec[i] * sums[i];
        }
    
        // compute evaluations of f_j(b,x)
        let new_num_vars = length + num_vars;
        let mut new_mle = Vec::new();
        let mut hm = HashMap::new();
    
        let eval_len = 1 << num_vars;
        for j in 0..t {
            let mut f = Vec::with_capacity(m * eval_len);
            for k in 0..eval_len {
                for i in 0..m {
                    f.push(polys[i].flattened_ml_extensions[j].evaluations[k].clone());
                }
            }
            let mle = Arc::new(DenseMultilinearExtension::from_evaluations_vec(new_num_vars, f));
            let mle_ptr = Arc::as_ptr(&mle);
            new_mle.push(mle);
            hm.insert(mle_ptr, j);
        }
    
        // compose_poly h
        let mut compose_poly = VirtualPolynomial {
            aux_info: VPAuxInfo {
                max_degree: polys[0].aux_info.max_degree + 1,
                num_variables: new_num_vars,
                phantom: PhantomData::default(),
            },
            products: polys[0].products.clone(),
            flattened_ml_extensions: new_mle,
            raw_pointers_lookup_table: hm,
        };
    
        // sumcheck round prove
        let mut challenge = None;
        let mut prover_msgs = Vec::with_capacity(length);
        let mut challenges = Vec::with_capacity(length);
        let mut eq_fix = eq_xr_poly.as_ref().clone();

        let mut flattened_ml_extensions: Vec<DenseMultilinearExtension<F>> = compose_poly
            .flattened_ml_extensions
            .par_iter()
            .map(|x| x.as_ref().clone())
            .collect();
    
        for round in 0..length {
            // Start timer for this round
            let start= Instant::now();
    
            if let Some(chal) = challenge {
                if round == 0 {
                    return Err(PolyIOPErrors::InvalidProver(
                        "first round should be prover first.".to_string(),
                    ));
                }
                challenges.push(chal);
    
                let r = challenges[round - 1];
                #[cfg(feature = "parallel")]
                flattened_ml_extensions
                    .par_iter_mut()
                    .for_each(|mle| *mle = fix_variables(mle, &[r]));
                #[cfg(not(feature = "parallel"))]
                flattened_ml_extensions
                    .iter_mut()
                    .for_each(|mle| *mle = fix_variables(mle, &[r]));
                eq_fix = fix_variables(&eq_fix, &[r]);
            } else if round > 0 {
                return Err(PolyIOPErrors::InvalidProver(
                    "verifier message is empty".to_string(),
                ));
            }
    
            let products_list = compose_poly.products.clone();
            let mut products_sum = vec![F::zero(); compose_poly.aux_info.max_degree + 1];
            let extrapolation_aux: Vec<(Vec<F>, Vec<F>)> = (1..compose_poly.aux_info.max_degree)
                .map(|degree| {
                    let points = (0..1 + degree as u64).map(F::from).collect::<Vec<_>>();
                    let weights = barycentric_weights(&points);
                    (points, weights)
                })
                .collect();
    
            // Step 2: generate sum for the partial evaluated polynomial:
            // f(r_1, ... r_m,, x_{m+1}... x_n)
            let mut eq_sum = vec![vec![F::zero(); 1 << (length - round - 1)]; compose_poly.aux_info.max_degree + 1];
            for b in 0..1 << (length - round - 1) {
                let table = &eq_fix;
                let mut eval = table[b << 1];
                let step = table[(b << 1) + 1] - table[b << 1];
    
                eq_sum[0][b] = eval;
    
                eq_sum[1..].iter_mut().for_each(|acc| {
                    eval += step;
                    acc[b] = eval;
                });
            }
    
            products_list.iter().for_each(|(coefficient, products)| {
                let mut sum = cfg_into_iter!(0..1 << (compose_poly.aux_info.num_variables - round - 1))
                    .fold(
                        || {
                            (
                                vec![(F::zero(), F::zero()); products.len()],
                                vec![vec![F::zero(); 1 << (length - round - 1)]; products.len() + 2],
                            )
                        },
                        |(mut buf, mut acc), b| {
                            buf.iter_mut()
                                .zip(products.iter())
                                .for_each(|((eval, step), f)| {
                                    let table = &flattened_ml_extensions[*f];
                                    *eval = table[b << 1];
                                    *step = table[(b << 1) + 1] - table[b << 1];
                                });
                            acc[0][b % (1 << (length - round - 1))] += buf.iter().map(|(eval, _)| eval).product::<F>();
                            acc[1..].iter_mut().for_each(|acc| {
                                buf.iter_mut().for_each(|(eval, step)| *eval += step as &_);
                                acc[b % (1 << (length - round - 1))] += buf.iter().map(|(eval, _)| eval).product::<F>();
                            });
                            (buf, acc)
                        },
                    )
                    .map(|(_, partial)| {
                        let partial_sum: Vec<F> = eq_sum[..partial.len()]
                            .iter()
                            .zip(partial.iter())
                            .map(|(eq_row, partial_row)| {
                                assert_eq!(eq_row.len(), partial_row.len());
                                eq_row
                                    .iter()
                                    .zip(partial_row)
                                    .map(|(a, b)| *a * *b)
                                    .sum::<F>()
                            })
                            .collect();
                        partial_sum
                    })
                    .reduce(
                        || vec![F::zero(); products.len() + 2],
                        |mut sum, partial_sum| {
                            sum.iter_mut()
                                .zip(partial_sum.iter())
                                .for_each(|(sum, partial_sum)| *sum += partial_sum);
                            sum
                        },
                    );
                sum.iter_mut().for_each(|sum| *sum *= coefficient);
    
                let extrapolation = cfg_into_iter!(0..compose_poly.aux_info.max_degree - products.len() - 1)
                    .map(|i| {
                        let (points, weights) = &extrapolation_aux[products.len()];
                        let at = F::from((products.len() + 2 + i) as u64);
                        extrapolate(points, weights, &sum, &at)
                    })
                    .collect::<Vec<_>>();
                products_sum
                    .iter_mut()
                    .zip(sum.iter().chain(extrapolation.iter()))
                    .for_each(|(products_sum, sum)| *products_sum += sum);
            });
    
            let message = IOPProverMessage {
                evaluations: products_sum,
            };
            transcript.append_serializable_element(b"prover msg", &message)?;
            prover_msgs.push(message);
            challenge = Some(transcript.get_and_append_challenge(b"Internal round")?);
    
            // End timer for this round
            let duration = start.elapsed();
            println!("---------------SumFold Round {:?} Duration {:?}---------",round,duration);
        }
    
        // pushing the last challenge point to the state
        if let Some(p) = challenge {
            challenges.push(p);
        }
    
        let proof = IOPProof {
            point: challenges,
            proofs: prover_msgs,
        };
    
        let final_round_proof = proof.proofs[length - 1].evaluations.clone();
        let final_challenge = proof.point[length - 1].clone();
        let c = interpolate_uni_poly::<F>(&final_round_proof, final_challenge);
        let rb = proof.point.clone();
    
        // compute the folded instance-witness pair
        let v = c * eq_poly.evaluate(&rb).inverse().unwrap();
        let eq_rb_vec = build_eq_x_r_vec(&rb)?;
        let mut new_mle = vec![];
        let mut hm = HashMap::new();
        for j in 0..t {
            let mut vec = vec![F::zero(); 1 << num_vars];
            for i in 0..m {
                for (eval, sum) in polys[i].flattened_ml_extensions[j].to_evaluations().clone().iter().zip(&mut vec) {
                    *sum += eq_rb_vec[i] * (*eval);
                }
            }
            let mle = Arc::new(DenseMultilinearExtension::from_evaluations_vec(num_vars, vec));
            let mle_ptr = Arc::as_ptr(&mle);
            new_mle.push(mle);
            hm.insert(mle_ptr, j);
        }
        let folded_poly = VirtualPolynomial {
            aux_info: polys[0].aux_info.clone(),
            products: polys[0].products.clone(),
            flattened_ml_extensions: new_mle,
            raw_pointers_lookup_table: hm,
        };
    
        Ok((proof, sum_t, q_aux_info, folded_poly, v))
    }

    /// Optimized sum_fold with MLE transform and reduced allocations.
    /// Key optimizations:
    /// 1. Hoist barycentric weight precomputation outside round loop
    /// 2. Use MLE transform in final stage instead of explicit eq_rb_vec accumulation
    /// 3. Use in-place fix_variables where possible
    fn sum_fold_v2(
        polys: Vec<VirtualPolynomial<F>>,
        sums: Vec<F>,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<(Self::SumCheckProof, F, VPAuxInfo<F>, VirtualPolynomial<F>, F), PolyIOPErrors> {
        let m = polys.len();
        let t = polys[0].flattened_ml_extensions.len();
        let num_vars = polys[0].aux_info.num_variables;
        let length = log2(m) as usize;

        let q_aux_info = VPAuxInfo::<F> {
            max_degree: polys[0].aux_info.max_degree + 1,
            num_variables: length,
            phantom: PhantomData::default(),
        };

        transcript.append_serializable_element(b"aux info", &q_aux_info)?;
        let rho: Vec<F> = transcript.get_and_append_challenge_vectors(b"sumfold rho", length)?;
        let eq_poly = EqPolynomial::new(rho.clone());
        let eq_xr_poly = build_eq_x_r(&rho)?;

        // Stage 2: compute the sum T
        let mut sum_t = F::zero();
        let eq_xr_vec = eq_xr_poly.to_evaluations();
        for i in 0..m {
            sum_t += eq_xr_vec[i] * sums[i];
        }

        // Stage 3: compute evaluations of f_j(b,x) - interleaved MLE structure
        let new_num_vars = length + num_vars;
        let mut new_mle = Vec::with_capacity(t);
        let mut hm = HashMap::new();

        let eval_len = 1 << num_vars;
        for j in 0..t {
            let mut f = Vec::with_capacity(m * eval_len);
            for k in 0..eval_len {
                for i in 0..m {
                    f.push(polys[i].flattened_ml_extensions[j].evaluations[k]);
                }
            }
            let mle = Arc::new(DenseMultilinearExtension::from_evaluations_vec(new_num_vars, f));
            let mle_ptr = Arc::as_ptr(&mle);
            new_mle.push(mle);
            hm.insert(mle_ptr, j);
        }

        // Stage 4: compose_poly h
        let compose_poly = VirtualPolynomial {
            aux_info: VPAuxInfo {
                max_degree: polys[0].aux_info.max_degree + 1,
                num_variables: new_num_vars,
                phantom: PhantomData::default(),
            },
            products: polys[0].products.clone(),
            flattened_ml_extensions: new_mle,
            raw_pointers_lookup_table: hm,
        };

        // OPTIMIZATION: Hoist barycentric weight precomputation outside round loop
        let extrapolation_aux: Vec<(Vec<F>, Vec<F>)> = (1..compose_poly.aux_info.max_degree)
            .map(|degree| {
                let points = (0..1 + degree as u64).map(F::from).collect::<Vec<_>>();
                let weights = barycentric_weights(&points);
                (points, weights)
            })
            .collect();

        // Stage 5: sumcheck round prove
        let mut challenge = None;
        let mut prover_msgs = Vec::with_capacity(length);
        let mut challenges = Vec::with_capacity(length);
        let mut eq_fix = eq_xr_poly.as_ref().clone();

        let mut flattened_ml_extensions: Vec<DenseMultilinearExtension<F>> = compose_poly
            .flattened_ml_extensions
            .par_iter()
            .map(|x| x.as_ref().clone())
            .collect();

        let products_list = compose_poly.products.clone();

        for round in 0..length {
            if let Some(chal) = challenge {
                if round == 0 {
                    return Err(PolyIOPErrors::InvalidProver(
                        "first round should be prover first.".to_string(),
                    ));
                }
                challenges.push(chal);

                let r = challenges[round - 1];
                #[cfg(feature = "parallel")]
                flattened_ml_extensions
                    .par_iter_mut()
                    .for_each(|mle| *mle = fix_variables(mle, &[r]));
                #[cfg(not(feature = "parallel"))]
                flattened_ml_extensions
                    .iter_mut()
                    .for_each(|mle| *mle = fix_variables(mle, &[r]));
                eq_fix = fix_variables(&eq_fix, &[r]);
            } else if round > 0 {
                return Err(PolyIOPErrors::InvalidProver(
                    "verifier message is empty".to_string(),
                ));
            }

            let mut products_sum = vec![F::zero(); compose_poly.aux_info.max_degree + 1];

            // Compute eq_sum for this round
            let mut eq_sum = vec![vec![F::zero(); 1 << (length - round - 1)]; compose_poly.aux_info.max_degree + 1];
            for b in 0..1 << (length - round - 1) {
                let table = &eq_fix;
                let mut eval = table[b << 1];
                let step = table[(b << 1) + 1] - table[b << 1];

                eq_sum[0][b] = eval;

                eq_sum[1..].iter_mut().for_each(|acc| {
                    eval += step;
                    acc[b] = eval;
                });
            }

            products_list.iter().for_each(|(coefficient, products)| {
                let mut sum = cfg_into_iter!(0..1 << (compose_poly.aux_info.num_variables - round - 1))
                    .fold(
                        || {
                            (
                                vec![(F::zero(), F::zero()); products.len()],
                                vec![vec![F::zero(); 1 << (length - round - 1)]; products.len() + 2],
                            )
                        },
                        |(mut buf, mut acc), b| {
                            buf.iter_mut()
                                .zip(products.iter())
                                .for_each(|((eval, step), f)| {
                                    let table = &flattened_ml_extensions[*f];
                                    *eval = table[b << 1];
                                    *step = table[(b << 1) + 1] - table[b << 1];
                                });
                            acc[0][b % (1 << (length - round - 1))] += buf.iter().map(|(eval, _)| eval).product::<F>();
                            acc[1..].iter_mut().for_each(|acc| {
                                buf.iter_mut().for_each(|(eval, step)| *eval += step as &_);
                                acc[b % (1 << (length - round - 1))] += buf.iter().map(|(eval, _)| eval).product::<F>();
                            });
                            (buf, acc)
                        },
                    )
                    .map(|(_, partial)| {
                        let partial_sum: Vec<F> = eq_sum[..partial.len()]
                            .iter()
                            .zip(partial.iter())
                            .map(|(eq_row, partial_row)| {
                                assert_eq!(eq_row.len(), partial_row.len());
                                eq_row
                                    .iter()
                                    .zip(partial_row)
                                    .map(|(a, b)| *a * *b)
                                    .sum::<F>()
                            })
                            .collect();
                        partial_sum
                    })
                    .reduce(
                        || vec![F::zero(); products.len() + 2],
                        |mut sum, partial_sum| {
                            sum.iter_mut()
                                .zip(partial_sum.iter())
                                .for_each(|(sum, partial_sum)| *sum += partial_sum);
                            sum
                        },
                    );
                sum.iter_mut().for_each(|sum| *sum *= coefficient);

                let extrapolation = cfg_into_iter!(0..compose_poly.aux_info.max_degree - products.len() - 1)
                    .map(|i| {
                        let (points, weights) = &extrapolation_aux[products.len()];
                        let at = F::from((products.len() + 2 + i) as u64);
                        extrapolate(points, weights, &sum, &at)
                    })
                    .collect::<Vec<_>>();
                products_sum
                    .iter_mut()
                    .zip(sum.iter().chain(extrapolation.iter()))
                    .for_each(|(products_sum, sum)| *products_sum += sum);
            });

            let message = IOPProverMessage {
                evaluations: products_sum,
            };
            transcript.append_serializable_element(b"prover msg", &message)?;
            prover_msgs.push(message);
            challenge = Some(transcript.get_and_append_challenge(b"Internal round")?);
        }

        // Push the last challenge
        if let Some(p) = challenge {
            challenges.push(p);
        }

        let proof = IOPProof {
            point: challenges,
            proofs: prover_msgs,
        };

        let final_round_proof = proof.proofs[length - 1].evaluations.clone();
        let final_challenge = proof.point[length - 1];
        let c = interpolate_uni_poly::<F>(&final_round_proof, final_challenge);
        let rb = proof.point.clone();

        // Stage 6: compute the folded instance-witness pair using MLE transform
        // OPTIMIZATION: Instead of explicit O(t * m * 2^num_vars) accumulation with eq_rb_vec,
        // leverage the prover loop's intermediate state.
        // After all rounds, flattened_ml_extensions is fixed at rb[0..length-1].
        // Apply one more fix_variables for the final challenge to get the folded MLEs.
        let v = c * eq_poly.evaluate(&rb).inverse().unwrap();

        // Apply final challenge to get folded MLEs via transform
        // Fix the last challenge on each MLE (they're already fixed at rb[0..length-1])
        let final_challenge_val = rb[length - 1];
        
        // Fix the final challenge on all MLEs in parallel
        #[cfg(feature = "parallel")]
        let new_mle: Vec<Arc<DenseMultilinearExtension<F>>> = flattened_ml_extensions
            .par_iter()
            .map(|mle| Arc::new(fix_variables(mle, &[final_challenge_val])))
            .collect();
        #[cfg(not(feature = "parallel"))]
        let new_mle: Vec<Arc<DenseMultilinearExtension<F>>> = flattened_ml_extensions
            .iter()
            .map(|mle| Arc::new(fix_variables(mle, &[final_challenge_val])))
            .collect();

        let mut hm = HashMap::new();
        for (j, mle) in new_mle.iter().enumerate() {
            let mle_ptr = Arc::as_ptr(mle);
            hm.insert(mle_ptr, j);
        }

        let folded_poly = VirtualPolynomial {
            aux_info: polys[0].aux_info.clone(),
            products: polys[0].products.clone(),
            flattened_ml_extensions: new_mle,
            raw_pointers_lookup_table: hm,
        };

        Ok((proof, sum_t, q_aux_info, folded_poly, v))
    }

    /// Split-and-merge version of sum_fold using VirtualPolynomial::split_by_last_variables.
    ///
    /// Strategy: m VPs → split each by last `length` vars → m² sub-VPs → merge by split index → m merged VPs
    ///
    /// # Split-and-Merge Example (m=4, t=2 MLEs each)
    ///
    /// ## Before Splitting: 4 VPs
    /// ```text
    /// VP₀, VP₁, VP₂, VP₃
    /// ```
    ///
    /// ## After Splitting: 16 sub-VPs (split by last 2 variables)
    /// ```text
    /// VP₀ → [VP₀[0], VP₀[1], VP₀[2], VP₀[3]]
    /// VP₁ → [VP₁[0], VP₁[1], VP₁[2], VP₁[3]]
    /// VP₂ → [VP₂[0], VP₂[1], VP₂[2], VP₂[3]]
    /// VP₃ → [VP₃[0], VP₃[1], VP₃[2], VP₃[3]]
    /// ```
    ///
    /// ## After Merging: 4 Merged VPs (group by split index, interleave MLEs)
    /// ```text
    /// Merged[0] = interleave(VP₀[0], VP₁[0], VP₂[0], VP₃[0])
    /// Merged[1] = interleave(VP₀[1], VP₁[1], VP₂[1], VP₃[1])
    /// Merged[2] = interleave(VP₀[2], VP₁[2], VP₂[2], VP₃[2])
    /// Merged[3] = interleave(VP₀[3], VP₁[3], VP₂[3], VP₃[3])
    /// ```
    ///
    /// Uses sequential execution and eq-weighted sums for sum_t computation.
    fn sum_fold_v3(
        polys: Vec<VirtualPolynomial<F>>,
        sums: Vec<F>,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<(Self::SumCheckProof, F, VPAuxInfo<F>, VirtualPolynomial<F>, F), PolyIOPErrors> {
        let m = polys.len();
        let t = polys[0].flattened_ml_extensions.len();
        let num_vars = polys[0].aux_info.num_variables;
        let length = log2(m) as usize;

        // ═══════════════════════════════════════════════════════════════
        // Stage 1: Setup and Challenge Generation
        // ═══════════════════════════════════════════════════════════════
        let q_aux_info = VPAuxInfo::<F> {
            max_degree: polys[0].aux_info.max_degree + 1,
            num_variables: length,
            phantom: PhantomData::default(),
        };

        transcript.append_serializable_element(b"aux info", &q_aux_info)?;
        let rho: Vec<F> = transcript.get_and_append_challenge_vectors(b"sumfold rho", length)?;
        let eq_poly = EqPolynomial::new(rho.clone());
        let eq_xr_poly = build_eq_x_r(&rho)?;
        let eq_xr_vec = eq_xr_poly.to_evaluations();

        // ═══════════════════════════════════════════════════════════════
        // Stage 2: Split VPs and compute sum_t with eq-weighted sums
        // ═══════════════════════════════════════════════════════════════
        // Split each VP by last `length` variables
        // VP_i splits into m sub-VPs: VP_i[0], VP_i[1], ..., VP_i[m-1]
        let all_splits: Vec<Vec<VirtualPolynomial<F>>> = polys
            .iter()
            .map(|vp| vp.split_by_last_variables(length))
            .collect();

        // Compute sum_t = Σᵢ eq(rho, i) * sums[i]
        let sum_t = stage2_compute_sum_t(&sums, &eq_xr_vec);

        // ═══════════════════════════════════════════════════════════════
        // Stage 3: Merge split MLEs across VPs for each split index
        // ═══════════════════════════════════════════════════════════════
        // For each split index s, interleave MLEs from all m VPs
        let new_num_vars = length + num_vars;
        let merged_mles = stage3_merge_split_mles(&all_splits, m, t, new_num_vars);

        // ═══════════════════════════════════════════════════════════════
        // Stage 4: Build composed VirtualPolynomial
        // ═══════════════════════════════════════════════════════════════
        let compose_poly = stage4_compose_poly(
            merged_mles,
            polys[0].products.clone(),
            polys[0].aux_info.max_degree + 1,
            new_num_vars,
        );

        // Precompute barycentric weights for extrapolation
        let extrapolation_aux: Vec<(Vec<F>, Vec<F>)> = (1..compose_poly.aux_info.max_degree)
            .map(|degree| {
                let points = (0..1 + degree as u64).map(F::from).collect::<Vec<_>>();
                let weights = barycentric_weights(&points);
                (points, weights)
            })
            .collect();

        // ═══════════════════════════════════════════════════════════════
        // Stage 5: Sumcheck rounds (sequential)
        // ═══════════════════════════════════════════════════════════════
        let mut challenge = None;
        let mut prover_msgs = Vec::with_capacity(length);
        let mut challenges = Vec::with_capacity(length);
        let mut eq_fix = eq_xr_poly.as_ref().clone();

        // Clone MLEs for mutation (sequential)
        let mut flattened_ml_extensions: Vec<DenseMultilinearExtension<F>> = compose_poly
            .flattened_ml_extensions
            .iter()
            .map(|x| x.as_ref().clone())
            .collect();

        let products_list = compose_poly.products.clone();

        for round in 0..length {
            if let Some(chal) = challenge {
                if round == 0 {
                    return Err(PolyIOPErrors::InvalidProver(
                        "first round should be prover first.".to_string(),
                    ));
                }
                challenges.push(chal);

                let r = challenges[round - 1];
                // Sequential fix_variables
                flattened_ml_extensions
                    .iter_mut()
                    .for_each(|mle| *mle = fix_variables(mle, &[r]));
                eq_fix = fix_variables(&eq_fix, &[r]);
            } else if round > 0 {
                return Err(PolyIOPErrors::InvalidProver(
                    "verifier message is empty".to_string(),
                ));
            }

            let mut products_sum = vec![F::zero(); compose_poly.aux_info.max_degree + 1];

            // Compute eq_sum for this round (sequential)
            let mut eq_sum = vec![vec![F::zero(); 1 << (length - round - 1)]; compose_poly.aux_info.max_degree + 1];
            for b in 0..1 << (length - round - 1) {
                let table = &eq_fix;
                let mut eval = table[b << 1];
                let step = table[(b << 1) + 1] - table[b << 1];

                eq_sum[0][b] = eval;

                eq_sum[1..].iter_mut().for_each(|acc| {
                    eval += step;
                    acc[b] = eval;
                });
            }

            // Sequential product accumulation
            for (coefficient, products) in products_list.iter() {
                let mut sum = vec![F::zero(); products.len() + 2];
                let mut partial_acc = vec![vec![F::zero(); 1 << (length - round - 1)]; products.len() + 2];

                for b in 0..1 << (compose_poly.aux_info.num_variables - round - 1) {
                    let mut buf: Vec<(F, F)> = vec![(F::zero(), F::zero()); products.len()];

                    buf.iter_mut()
                        .zip(products.iter())
                        .for_each(|((eval, step), f)| {
                            let table = &flattened_ml_extensions[*f];
                            *eval = table[b << 1];
                            *step = table[(b << 1) + 1] - table[b << 1];
                        });

                    let bucket = b % (1 << (length - round - 1));
                    partial_acc[0][bucket] += buf.iter().map(|(eval, _)| eval).product::<F>();

                    for acc_idx in 1..partial_acc.len() {
                        buf.iter_mut().for_each(|(eval, step)| *eval += *step);
                        partial_acc[acc_idx][bucket] += buf.iter().map(|(eval, _)| eval).product::<F>();
                    }
                }

                // Apply eq_sum weights
                for (i, partial_row) in partial_acc.iter().enumerate() {
                    if i < eq_sum.len() {
                        sum[i] = eq_sum[i]
                            .iter()
                            .zip(partial_row.iter())
                            .map(|(a, b)| *a * *b)
                            .sum::<F>();
                    }
                }

                sum.iter_mut().for_each(|s| *s *= coefficient);

                // Extrapolate remaining degrees
                for i in 0..compose_poly.aux_info.max_degree - products.len() - 1 {
                    let (points, weights) = &extrapolation_aux[products.len()];
                    let at = F::from((products.len() + 2 + i) as u64);
                    let extra = extrapolate(points, weights, &sum, &at);
                    if products.len() + 2 + i < products_sum.len() {
                        products_sum[products.len() + 2 + i] += extra;
                    }
                }

                for (i, s) in sum.iter().enumerate() {
                    if i < products_sum.len() {
                        products_sum[i] += *s;
                    }
                }
            }

            let message = IOPProverMessage {
                evaluations: products_sum,
            };
            transcript.append_serializable_element(b"prover msg", &message)?;
            prover_msgs.push(message);
            challenge = Some(transcript.get_and_append_challenge(b"Internal round")?);
        }

        // Push the last challenge
        if let Some(p) = challenge {
            challenges.push(p);
        }

        let proof = IOPProof {
            point: challenges,
            proofs: prover_msgs,
        };

        let final_round_proof = proof.proofs[length - 1].evaluations.clone();
        let final_challenge = proof.point[length - 1];
        let c = interpolate_uni_poly::<F>(&final_round_proof, final_challenge);
        let rb = proof.point.clone();

        // ═══════════════════════════════════════════════════════════════
        // Stage 6: Compute folded polynomial via fix_variables
        // ═══════════════════════════════════════════════════════════════
        let v = c * eq_poly.evaluate(&rb).inverse().unwrap();

        // Apply final challenge to get folded MLEs (sequential)
        let final_challenge_val = rb[length - 1];
        let new_mle: Vec<Arc<DenseMultilinearExtension<F>>> = flattened_ml_extensions
            .iter()
            .map(|mle| Arc::new(fix_variables(mle, &[final_challenge_val])))
            .collect();

        let mut hm = HashMap::new();
        for (j, mle) in new_mle.iter().enumerate() {
            let mle_ptr = Arc::as_ptr(mle);
            hm.insert(mle_ptr, j);
        }

        let folded_poly = VirtualPolynomial {
            aux_info: polys[0].aux_info.clone(),
            products: polys[0].products.clone(),
            flattened_ml_extensions: new_mle,
            raw_pointers_lookup_table: hm,
        };

        Ok((proof, sum_t, q_aux_info, folded_poly, v))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Stage helper functions for sum_fold_v3
// ═══════════════════════════════════════════════════════════════════════════

/// Stage 2: Compute sum_t = Σᵢ eq(rho, i) * sums[i]
fn stage2_compute_sum_t<F: PrimeField>(sums: &[F], eq_xr_vec: &[F]) -> F {
    sums.iter()
        .zip(eq_xr_vec.iter())
        .map(|(s, eq)| *s * *eq)
        .sum()
}

/// Stage 3: Merge split MLEs across VPs for interleaved structure
///
/// For each MLE index j, produce a merged MLE with (length + num_vars) variables.
/// The interleaving follows sum_fold_v2's layout:
///   merged_evals[k * m + i] = original_polys[i].mle[j].evals[k]
///
/// After splitting by last `length` vars:
///   all_splits[i][s].mle[j].evals[x'] = original_polys[i].mle[j].evals[s * chunk_size + x']
///   where chunk_size = 2^(num_vars - length)
///
/// So we iterate: for s in 0..num_splits, for x' in 0..chunk_size, for i in 0..m
/// This produces k = s * chunk_size + x' in correct order.
fn stage3_merge_split_mles<F: PrimeField>(
    all_splits: &[Vec<VirtualPolynomial<F>>],
    m: usize,
    t: usize,
    new_num_vars: usize,
) -> Vec<Arc<DenseMultilinearExtension<F>>> {
    let num_splits = all_splits[0].len();
    let split_num_vars = all_splits[0][0].aux_info.num_variables;
    let chunk_size = 1 << split_num_vars;

    let mut merged_mles = Vec::with_capacity(t);

    for j in 0..t {
        // Total evaluations = m * num_splits * chunk_size = m * 2^num_vars
        let total_len = m * num_splits * chunk_size;
        let mut f = Vec::with_capacity(total_len);

        // Iterate to produce k = s * chunk_size + x' in order
        // This matches sum_fold_v2's: for k in 0..eval_len, for i in 0..m
        for s in 0..num_splits {
            for x_prime in 0..chunk_size {
                for i in 0..m {
                    f.push(all_splits[i][s].flattened_ml_extensions[j].evaluations[x_prime]);
                }
            }
        }

        let mle = Arc::new(DenseMultilinearExtension::from_evaluations_vec(new_num_vars, f));
        merged_mles.push(mle);
    }

    merged_mles
}

/// Stage 4: Build composed VirtualPolynomial from merged MLEs
fn stage4_compose_poly<F: PrimeField>(
    merged_mles: Vec<Arc<DenseMultilinearExtension<F>>>,
    products: Vec<(F, Vec<usize>)>,
    max_degree: usize,
    num_variables: usize,
) -> VirtualPolynomial<F> {
    let mut hm = HashMap::new();
    for (j, mle) in merged_mles.iter().enumerate() {
        let mle_ptr = Arc::as_ptr(mle);
        hm.insert(mle_ptr, j);
    }

    VirtualPolynomial {
        aux_info: VPAuxInfo {
            max_degree,
            num_variables,
            phantom: PhantomData::default(),
        },
        products,
        flattened_ml_extensions: merged_mles,
        raw_pointers_lookup_table: hm,
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::{One, UniformRand, Zero};
    use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
    use ark_std::test_rng;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Instant;

    fn test_sumcheck(
        nv: usize,
        num_multiplicands_range: (usize, usize),
        num_products: usize,
    ) -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let mut transcript = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();

        let (poly, asserted_sum) =
            VirtualPolynomial::rand(nv, num_multiplicands_range, num_products, &mut rng)?;
        let proof = <PolyIOP<Fr> as SumCheck<Fr>>::prove(&poly, &mut transcript)?;
        let poly_info = poly.aux_info.clone();
        let mut transcript = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
        let subclaim = <PolyIOP<Fr> as SumCheck<Fr>>::verify(
            asserted_sum,
            &proof,
            &poly_info,
            &mut transcript,
        )?;
        assert!(
            poly.evaluate(&subclaim.point).unwrap() == subclaim.expected_evaluation,
            "wrong subclaim"
        );
        Ok(())
    }

    fn test_sumcheck_internal(
        nv: usize,
        num_multiplicands_range: (usize, usize),
        num_products: usize,
    ) -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let (poly, asserted_sum) =
            VirtualPolynomial::<Fr>::rand(nv, num_multiplicands_range, num_products, &mut rng)?;
        let poly_info = poly.aux_info.clone();
        let mut prover_state = IOPProverState::prover_init(&poly)?;
        let mut verifier_state = IOPVerifierState::verifier_init(&poly_info);
        let mut challenge = None;
        let mut transcript = IOPTranscript::new(b"a test transcript");
        transcript
            .append_message(b"testing", b"initializing transcript for testing")
            .unwrap();
        for _ in 0..poly.aux_info.num_variables {
            let prover_message =
                IOPProverState::prove_round_and_update_state(&mut prover_state, &challenge)
                    .unwrap();

            challenge = Some(
                IOPVerifierState::verify_round_and_update_state(
                    &mut verifier_state,
                    &prover_message,
                    &mut transcript,
                )
                .unwrap(),
            );
        }
        let subclaim =
            IOPVerifierState::check_and_generate_subclaim(&verifier_state, &asserted_sum)
                .expect("fail to generate subclaim");
        assert!(
            poly.evaluate(&subclaim.point).unwrap() == subclaim.expected_evaluation,
            "wrong subclaim"
        );
        Ok(())
    }

    #[test]
    fn test_trivial_polynomial() -> Result<(), PolyIOPErrors> {
        let nv = 1;
        let num_multiplicands_range = (4, 13);
        let num_products = 5;

        test_sumcheck(nv, num_multiplicands_range, num_products)?;
        test_sumcheck_internal(nv, num_multiplicands_range, num_products)
    }
    #[test]
    fn test_normal_polynomial() -> Result<(), PolyIOPErrors> {
        let nv = 12;
        let num_multiplicands_range = (4, 9);
        let num_products = 5;

        test_sumcheck(nv, num_multiplicands_range, num_products)?;
        test_sumcheck_internal(nv, num_multiplicands_range, num_products)
    }
    #[test]
    fn zero_polynomial_should_error() {
        let nv = 0;
        let num_multiplicands_range = (4, 13);
        let num_products = 5;

        assert!(test_sumcheck(nv, num_multiplicands_range, num_products).is_err());
        assert!(test_sumcheck_internal(nv, num_multiplicands_range, num_products).is_err());
    }

    #[test]
    fn test_extract_sum() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let mut transcript = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
        let (poly, asserted_sum) = VirtualPolynomial::<Fr>::rand(8, (3, 4), 3, &mut rng)?;

        let proof = <PolyIOP<Fr> as SumCheck<Fr>>::prove(&poly, &mut transcript)?;
        assert_eq!(
            <PolyIOP<Fr> as SumCheck<Fr>>::extract_sum(&proof),
            asserted_sum
        );
        Ok(())
    }

    #[test]
    /// Test that the memory usage of shared-reference is linear to number of
    /// unique MLExtensions instead of total number of multiplicands.
    fn test_shared_reference() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let ml_extensions: Vec<_> = (0..5)
            .map(|_| Arc::new(DenseMultilinearExtension::<Fr>::rand(8, &mut rng)))
            .collect();
        let mut poly = VirtualPolynomial::new(8);
        poly.add_mle_list(
            vec![
                ml_extensions[2].clone(),
                ml_extensions[3].clone(),
                ml_extensions[0].clone(),
            ],
            Fr::rand(&mut rng),
        )?;
        poly.add_mle_list(
            vec![
                ml_extensions[1].clone(),
                ml_extensions[4].clone(),
                ml_extensions[4].clone(),
            ],
            Fr::rand(&mut rng),
        )?;
        poly.add_mle_list(
            vec![
                ml_extensions[3].clone(),
                ml_extensions[2].clone(),
                ml_extensions[1].clone(),
            ],
            Fr::rand(&mut rng),
        )?;
        poly.add_mle_list(
            vec![ml_extensions[0].clone(), ml_extensions[0].clone()],
            Fr::rand(&mut rng),
        )?;
        poly.add_mle_list(vec![ml_extensions[4].clone()], Fr::rand(&mut rng))?;

        assert_eq!(poly.flattened_ml_extensions.len(), 5);

        // test memory usage for prover
        let prover = IOPProverState::<Fr>::prover_init(&poly).unwrap();
        assert_eq!(prover.poly.flattened_ml_extensions.len(), 5);
        drop(prover);

        let mut transcript = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
        let poly_info = poly.aux_info.clone();
        let proof = <PolyIOP<Fr> as SumCheck<Fr>>::prove(&poly, &mut transcript)?;
        let asserted_sum = <PolyIOP<Fr> as SumCheck<Fr>>::extract_sum(&proof);

        let mut transcript = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
        let subclaim = <PolyIOP<Fr> as SumCheck<Fr>>::verify(
            asserted_sum,
            &proof,
            &poly_info,
            &mut transcript,
        )?;
        assert!(
            poly.evaluate(&subclaim.point)? == subclaim.expected_evaluation,
            "wrong subclaim"
        );
        Ok(())
    }

    /// Test that sum_fold_v2 produces identical proofs to sum_fold.
    /// Compares proofs by serializing to bytes and asserting equality.
    #[test]
    fn test_sum_fold_v2_equivalence() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let nv = 10;
        let m = 4; // number of polynomials (must be power of 2)
        let num_multiplicands = 3;
        let num_products = 2;

        // Generate m virtual polynomials with the SAME structure
        // First, create a template polynomial to get the products structure
        let (template, _) = VirtualPolynomial::<Fr>::rand(nv, (num_multiplicands, num_multiplicands + 1), num_products, &mut rng)?;
        
        let mut polys = Vec::with_capacity(m);
        let mut sums = Vec::with_capacity(m);

        for _ in 0..m {
            // Create new MLEs with random evaluations but same structure
            let t = template.flattened_ml_extensions.len();
            let mut new_mles: Vec<Arc<DenseMultilinearExtension<Fr>>> = Vec::with_capacity(t);
            let mut raw_pointers_lookup_table = HashMap::new();
            
            for _ in 0..t {
                let mle = Arc::new(DenseMultilinearExtension::<Fr>::rand(nv, &mut rng));
                let mle_ptr = Arc::as_ptr(&mle);
                raw_pointers_lookup_table.insert(mle_ptr, new_mles.len());
                new_mles.push(mle);
            }

            let poly = VirtualPolynomial {
                aux_info: template.aux_info.clone(),
                products: template.products.clone(),
                flattened_ml_extensions: new_mles,
                raw_pointers_lookup_table,
            };

            // Compute sum for this polynomial
            let mut sum = Fr::zero();
            for (coefficient, product_indices) in poly.products.iter() {
                let mut product = Fr::one();
                for &idx in product_indices.iter() {
                    let mle_sum: Fr = poly.flattened_ml_extensions[idx].evaluations.iter().sum();
                    product *= mle_sum;
                }
                sum += *coefficient * product;
            }
            sums.push(sum);
            polys.push(poly);
        }

        // Clone for second call (since sum_fold consumes the polys)
        let polys_clone: Vec<VirtualPolynomial<Fr>> = polys
            .iter()
            .map(|p| p.deep_copy())
            .collect();
        let sums_clone = sums.clone();

        // Run sum_fold (original) with timing
        println!("\n=== sum_fold (original) ===");
        let start1 = Instant::now();
        let mut transcript1 = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
        let (proof1, sum_t1, aux_info1, folded_poly1, v1) =
            <PolyIOP<Fr> as SumCheck<Fr>>::sum_fold(polys, sums, &mut transcript1)?;
        let duration1 = start1.elapsed();
        println!("sum_fold total: {:?}", duration1);

        // Run sum_fold_v2 (optimized) with timing
        println!("\n=== sum_fold_v2 (optimized) ===");
        let start2 = Instant::now();
        let mut transcript2 = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
        let (proof2, sum_t2, aux_info2, folded_poly2, v2) =
            <PolyIOP<Fr> as SumCheck<Fr>>::sum_fold_v2(polys_clone, sums_clone, &mut transcript2)?;
        let duration2 = start2.elapsed();
        println!("sum_fold_v2 total: {:?}", duration2);

        // Print comparison
        let speedup = duration1.as_secs_f64() / duration2.as_secs_f64();
        println!("\n=== COMPARISON (nv={}, m={}) ===", nv, m);
        println!("  sum_fold:    {:?}", duration1);
        println!("  sum_fold_v2: {:?}", duration2);
        println!("  Speedup:     {:.2}x", speedup);

        // Compare proofs directly using PartialEq
        assert_eq!(
            proof1, proof2,
            "sum_fold and sum_fold_v2 proofs must be identical"
        );

        // Compare sum_t
        assert_eq!(sum_t1, sum_t2, "sum_t values must match");

        // Compare v
        assert_eq!(v1, v2, "v values must match");

        // Compare aux_info
        assert_eq!(
            aux_info1.max_degree, aux_info2.max_degree,
            "aux_info max_degree must match"
        );
        assert_eq!(
            aux_info1.num_variables, aux_info2.num_variables,
            "aux_info num_variables must match"
        );

        // Compare folded polynomial evaluations
        assert_eq!(
            folded_poly1.flattened_ml_extensions.len(),
            folded_poly2.flattened_ml_extensions.len(),
            "folded_poly MLE count must match"
        );

        for j in 0..folded_poly1.flattened_ml_extensions.len() {
            assert_eq!(
                folded_poly1.flattened_ml_extensions[j].evaluations,
                folded_poly2.flattened_ml_extensions[j].evaluations,
                "folded_poly MLE[{}] evaluations must match",
                j
            );
        }

        Ok(())
    }

    /// Extended test with multiple configurations
    #[test]
    fn test_sum_fold_v2_multiple_configs() -> Result<(), PolyIOPErrors> {
        let configs = [
            (8, 4, 3, 2),   // nv=8, m=4, num_multiplicands=3, num_products=2
            (10, 8, 2, 2),  // nv=10, m=8
            (12, 4, 3, 3),  // nv=12, m=4, higher products
        ];

        for (nv, m, num_multiplicands, num_products) in configs {
            let mut rng = test_rng();

            // Create template with same structure for all polynomials
            let (template, _) = VirtualPolynomial::<Fr>::rand(
                nv,
                (num_multiplicands, num_multiplicands + 1),
                num_products,
                &mut rng,
            )?;

            let mut polys = Vec::with_capacity(m);
            let mut sums = Vec::with_capacity(m);

            for _ in 0..m {
                // Create new MLEs with random evaluations but same structure
                let t = template.flattened_ml_extensions.len();
                let mut new_mles: Vec<Arc<DenseMultilinearExtension<Fr>>> = Vec::with_capacity(t);
                let mut raw_pointers_lookup_table = HashMap::new();

                for _ in 0..t {
                    let mle = Arc::new(DenseMultilinearExtension::<Fr>::rand(nv, &mut rng));
                    let mle_ptr = Arc::as_ptr(&mle);
                    raw_pointers_lookup_table.insert(mle_ptr, new_mles.len());
                    new_mles.push(mle);
                }

                let poly = VirtualPolynomial {
                    aux_info: template.aux_info.clone(),
                    products: template.products.clone(),
                    flattened_ml_extensions: new_mles,
                    raw_pointers_lookup_table,
                };

                // Compute sum for this polynomial
                let mut sum = Fr::zero();
                for (coefficient, product_indices) in poly.products.iter() {
                    let mut product = Fr::one();
                    for &idx in product_indices.iter() {
                        let mle_sum: Fr = poly.flattened_ml_extensions[idx].evaluations.iter().sum();
                        product *= mle_sum;
                    }
                    sum += *coefficient * product;
                }
                sums.push(sum);
                polys.push(poly);
            }

            let polys_clone: Vec<VirtualPolynomial<Fr>> = polys
                .iter()
                .map(|p| p.deep_copy())
                .collect();
            let sums_clone = sums.clone();

            // Run sum_fold (original) with timing
            let start1 = Instant::now();
            let mut transcript1 = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
            let (proof1, sum_t1, _, folded_poly1, v1) =
                <PolyIOP<Fr> as SumCheck<Fr>>::sum_fold(polys, sums, &mut transcript1)?;
            let duration1 = start1.elapsed();

            // Run sum_fold_v2 (optimized) with timing
            let start2 = Instant::now();
            let mut transcript2 = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
            let (proof2, sum_t2, _, folded_poly2, v2) =
                <PolyIOP<Fr> as SumCheck<Fr>>::sum_fold_v2(polys_clone, sums_clone, &mut transcript2)?;
            let duration2 = start2.elapsed();

            // Print timing comparison
            let speedup = duration1.as_secs_f64() / duration2.as_secs_f64();
            println!("\n=== Config (nv={}, m={}) ===", nv, m);
            println!("  sum_fold:    {:?}", duration1);
            println!("  sum_fold_v2: {:?}", duration2);
            println!("  Speedup:     {:.2}x", speedup);

            // Direct proof comparison using PartialEq
            assert_eq!(
                proof1, proof2,
                "Config (nv={}, m={}): proofs must be identical",
                nv, m
            );
            assert_eq!(sum_t1, sum_t2, "Config (nv={}, m={}): sum_t must match", nv, m);
            assert_eq!(v1, v2, "Config (nv={}, m={}): v must match", nv, m);

            for j in 0..folded_poly1.flattened_ml_extensions.len() {
                assert_eq!(
                    folded_poly1.flattened_ml_extensions[j].evaluations,
                    folded_poly2.flattened_ml_extensions[j].evaluations,
                    "Config (nv={}, m={}): folded MLE[{}] must match",
                    nv,
                    m,
                    j
                );
            }
        }

        Ok(())
    }

    /// Benchmark sum_fold vs sum_fold_v2 with multiple iterations for accurate timing.
    /// Run with: cargo test -p subroutines --lib sum_check::test::bench_sum_fold --release -- --nocapture --ignored
    #[test]
    #[ignore] // Run manually with --ignored flag
    fn bench_sum_fold_comparison() -> Result<(), PolyIOPErrors> {
        let configs = [
            (10, 4, 3, 2),   // nv=10, m=4
            (12, 4, 3, 2),   // nv=12, m=4
            (12, 8, 3, 2),   // nv=12, m=8
            (14, 4, 3, 2),   // nv=14, m=4
            (14, 8, 3, 2),   // nv=14, m=8
        ];
        let iterations = 10;

        println!("\n╔════════════════════════════════════════════════════════════════════╗");
        println!("║          sum_fold vs sum_fold_v2 Benchmark ({} iterations)         ║", iterations);
        println!("╠════════════════════════════════════════════════════════════════════╣");
        println!("║  Config      │ sum_fold (avg) │ sum_fold_v2 (avg) │ Speedup       ║");
        println!("╠════════════════════════════════════════════════════════════════════╣");

        for (nv, m, num_multiplicands, num_products) in configs {
            let mut total_v1 = std::time::Duration::ZERO;
            let mut total_v2 = std::time::Duration::ZERO;

            for _ in 0..iterations {
                let mut rng = test_rng();

                // Create template
                let (template, _) = VirtualPolynomial::<Fr>::rand(
                    nv,
                    (num_multiplicands, num_multiplicands + 1),
                    num_products,
                    &mut rng,
                )?;

                let mut polys = Vec::with_capacity(m);
                let mut sums = Vec::with_capacity(m);

                for _ in 0..m {
                    let t = template.flattened_ml_extensions.len();
                    let mut new_mles: Vec<Arc<DenseMultilinearExtension<Fr>>> = Vec::with_capacity(t);
                    let mut raw_pointers_lookup_table = HashMap::new();

                    for _ in 0..t {
                        let mle = Arc::new(DenseMultilinearExtension::<Fr>::rand(nv, &mut rng));
                        let mle_ptr = Arc::as_ptr(&mle);
                        raw_pointers_lookup_table.insert(mle_ptr, new_mles.len());
                        new_mles.push(mle);
                    }

                    let poly = VirtualPolynomial {
                        aux_info: template.aux_info.clone(),
                        products: template.products.clone(),
                        flattened_ml_extensions: new_mles,
                        raw_pointers_lookup_table,
                    };

                    let mut sum = Fr::zero();
                    for (coefficient, product_indices) in poly.products.iter() {
                        let mut product = Fr::one();
                        for &idx in product_indices.iter() {
                            let mle_sum: Fr = poly.flattened_ml_extensions[idx].evaluations.iter().sum();
                            product *= mle_sum;
                        }
                        sum += *coefficient * product;
                    }
                    sums.push(sum);
                    polys.push(poly);
                }

                let polys_clone: Vec<VirtualPolynomial<Fr>> = polys.iter().map(|p| p.deep_copy()).collect();
                let sums_clone = sums.clone();

                // Time sum_fold
                let start1 = Instant::now();
                let mut transcript1 = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
                let _ = <PolyIOP<Fr> as SumCheck<Fr>>::sum_fold(polys, sums, &mut transcript1)?;
                total_v1 += start1.elapsed();

                // Time sum_fold_v2
                let start2 = Instant::now();
                let mut transcript2 = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
                let _ = <PolyIOP<Fr> as SumCheck<Fr>>::sum_fold_v2(polys_clone, sums_clone, &mut transcript2)?;
                total_v2 += start2.elapsed();
            }

            let avg_v1 = total_v1 / iterations as u32;
            let avg_v2 = total_v2 / iterations as u32;
            let speedup = avg_v1.as_secs_f64() / avg_v2.as_secs_f64();

            println!(
                "║  nv={:2}, m={} │ {:>13.3?} │ {:>17.3?} │ {:>6.2}x       ║",
                nv, m, avg_v1, avg_v2, speedup
            );
        }

        println!("╚════════════════════════════════════════════════════════════════════╝");

        Ok(())
    }

    /// Test that sum_fold_v3 produces identical results to sum_fold_v2.
    /// Validates the split-and-merge strategy produces equivalent output.
    #[test]
    fn test_sum_fold_v3_equivalence() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let nv = 10;
        let m = 4; // number of polynomials (must be power of 2)
        let num_multiplicands = 3;
        let num_products = 2;

        // Generate m virtual polynomials with the SAME structure
        let (template, _) = VirtualPolynomial::<Fr>::rand(
            nv,
            (num_multiplicands, num_multiplicands + 1),
            num_products,
            &mut rng,
        )?;

        let mut polys = Vec::with_capacity(m);
        let mut sums = Vec::with_capacity(m);

        for _ in 0..m {
            let t = template.flattened_ml_extensions.len();
            let mut new_mles: Vec<Arc<DenseMultilinearExtension<Fr>>> = Vec::with_capacity(t);
            let mut raw_pointers_lookup_table = HashMap::new();

            for _ in 0..t {
                let mle = Arc::new(DenseMultilinearExtension::<Fr>::rand(nv, &mut rng));
                let mle_ptr = Arc::as_ptr(&mle);
                raw_pointers_lookup_table.insert(mle_ptr, new_mles.len());
                new_mles.push(mle);
            }

            let poly = VirtualPolynomial {
                aux_info: template.aux_info.clone(),
                products: template.products.clone(),
                flattened_ml_extensions: new_mles,
                raw_pointers_lookup_table,
            };

            // Compute sum for this polynomial
            let mut sum = Fr::zero();
            for (coefficient, product_indices) in poly.products.iter() {
                let mut product = Fr::one();
                for &idx in product_indices.iter() {
                    let mle_sum: Fr = poly.flattened_ml_extensions[idx].evaluations.iter().sum();
                    product *= mle_sum;
                }
                sum += *coefficient * product;
            }
            sums.push(sum);
            polys.push(poly);
        }

        // Clone for v3 call
        let polys_clone: Vec<VirtualPolynomial<Fr>> =
            polys.iter().map(|p| p.deep_copy()).collect();
        let sums_clone = sums.clone();

        // Run sum_fold_v2
        println!("\n=== sum_fold_v2 ===");
        let start2 = Instant::now();
        let mut transcript2 = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
        let (proof2, sum_t2, aux_info2, folded_poly2, v2) =
            <PolyIOP<Fr> as SumCheck<Fr>>::sum_fold_v2(polys, sums, &mut transcript2)?;
        let duration2 = start2.elapsed();
        println!("sum_fold_v2 total: {:?}", duration2);

        // Run sum_fold_v3
        println!("\n=== sum_fold_v3 (split-merge) ===");
        let start3 = Instant::now();
        let mut transcript3 = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
        let (proof3, sum_t3, aux_info3, folded_poly3, v3) =
            <PolyIOP<Fr> as SumCheck<Fr>>::sum_fold_v3(polys_clone, sums_clone, &mut transcript3)?;
        let duration3 = start3.elapsed();
        println!("sum_fold_v3 total: {:?}", duration3);

        // Print comparison
        println!("\n=== COMPARISON (nv={}, m={}) ===", nv, m);
        println!("  sum_fold_v2: {:?}", duration2);
        println!("  sum_fold_v3: {:?}", duration3);

        // Compare sum_t
        assert_eq!(sum_t2, sum_t3, "sum_t values must match");

        // Compare v
        assert_eq!(v2, v3, "v values must match");

        // Compare aux_info
        assert_eq!(
            aux_info2.max_degree, aux_info3.max_degree,
            "aux_info max_degree must match"
        );
        assert_eq!(
            aux_info2.num_variables, aux_info3.num_variables,
            "aux_info num_variables must match"
        );

        // Compare proofs
        assert_eq!(
            proof2, proof3,
            "sum_fold_v2 and sum_fold_v3 proofs must be identical"
        );

        // Compare folded polynomial evaluations
        assert_eq!(
            folded_poly2.flattened_ml_extensions.len(),
            folded_poly3.flattened_ml_extensions.len(),
            "folded_poly MLE count must match"
        );

        for j in 0..folded_poly2.flattened_ml_extensions.len() {
            assert_eq!(
                folded_poly2.flattened_ml_extensions[j].evaluations,
                folded_poly3.flattened_ml_extensions[j].evaluations,
                "folded_poly MLE[{}] evaluations must match",
                j
            );
        }

        Ok(())
    }
}
