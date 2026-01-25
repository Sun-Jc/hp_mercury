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

        // Run sum_fold (original)
        let mut transcript1 = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
        let (proof1, sum_t1, aux_info1, folded_poly1, v1) =
            <PolyIOP<Fr> as SumCheck<Fr>>::sum_fold(polys, sums, &mut transcript1)?;

        // Run sum_fold_v2 (optimized)
        let mut transcript2 = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
        let (proof2, sum_t2, aux_info2, folded_poly2, v2) =
            <PolyIOP<Fr> as SumCheck<Fr>>::sum_fold_v2(polys_clone, sums_clone, &mut transcript2)?;

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

            let mut transcript1 = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
            let (proof1, sum_t1, _, folded_poly1, v1) =
                <PolyIOP<Fr> as SumCheck<Fr>>::sum_fold(polys, sums, &mut transcript1)?;

            let mut transcript2 = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
            let (proof2, sum_t2, _, folded_poly2, v2) =
                <PolyIOP<Fr> as SumCheck<Fr>>::sum_fold_v2(polys_clone, sums_clone, &mut transcript2)?;

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
}
