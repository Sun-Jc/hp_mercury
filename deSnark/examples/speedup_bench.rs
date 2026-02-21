//! Speedup Benchmark: single-node vs distributed prove
//!
//! Measures "pure prove" time (no verify, no debug assertions) for:
//!   - Single-node:  prove_sumfold + SumCheck::prove  (RAYON_NUM_THREADS=2)
//!   - Distributed:  d_sumfold + d_prove (4 nodes, RAYON_NUM_THREADS=2 each)
//!
//! Reports per-phase timings (sumfold, sumcheck) plus total, enabling
//! phase-level speedup analysis.
//!
//! Usage:
//! ```bash
//! # Single-node
//! RAYON_NUM_THREADS=2 speedup_bench --mode single --iters 5 demo_config.toml
//!
//! # Distributed (launched by bench_speedup.sh)
//! RAYON_NUM_THREADS=2 speedup_bench --mode dist --party <ID> --iters 5 demo_config.toml
//! ```

use ark_bls12_381::{Bls12_381, Fr};
use deNetwork::{DeMultiNet as Net, DeNet};
use deSnark::{
    circuits_to_sumcheck, make_circuit, prove_sumfold, setup, Config, MockCircuit, NetworkConfig,
    SumCheckInstance,
};
use deSnark::snark::ProvingKey;
use std::env;
use std::time::Instant;
use subroutines::poly_iop::prelude::{PolyIOP, SumCheck};
use subroutines::MercuryPCS;
use tracing_subscriber::{fmt, EnvFilter};

type E = Bls12_381;
type PCS = MercuryPCS<E>;

fn main() {
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .init();

    let args: Vec<String> = env::args().collect();
    let opts = parse_args(&args);

    let (mut config, net_config) = Config::from_toml_file(&opts.config_path).unwrap_or_else(|e| {
        eprintln!("Error loading {}: {e}", opts.config_path);
        std::process::exit(1);
    });

    if opts.mode == "single" {
        config.log_num_parties = 0;
    }

    eprintln!(
        "[{}] Config: M={} instances, N={} constraints, K={} parties, constraints/party={}",
        opts.mode,
        config.num_instances(),
        config.num_constraints(),
        config.num_parties(),
        config.num_constraints() / config.num_parties()
    );
    eprintln!("Rayon threads: {}", rayon::current_num_threads());

    let srs = setup::<E, PCS>(&config).expect("setup failed");
    let (pk, _vk, circuits) = make_circuit::<E, PCS>(&config, &srs).expect("make_circuit failed");

    match opts.mode.as_str() {
        "single" => run_single(&pk, &circuits, opts.iters),
        "dist" => {
            let party_id = opts.party_id.expect("--party required for dist mode");
            run_dist(&pk, &circuits, party_id, &net_config, opts.iters);
        }
        other => {
            eprintln!("Unknown mode: {other}");
            std::process::exit(1);
        }
    }
}

fn run_single(pk: &ProvingKey<E, PCS>, circuits: &[MockCircuit<Fr>], iters: usize) {
    let mut t_sumfold = Vec::with_capacity(iters);
    let mut t_sumcheck = Vec::with_capacity(iters);
    let mut t_total = Vec::with_capacity(iters);

    for i in 0..iters {
        let instances: Vec<SumCheckInstance<Fr>> =
            circuits_to_sumcheck::<E, PCS>(pk, circuits).expect("circuits_to_sumcheck failed");

        let t0 = Instant::now();
        let mut transcript = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
        let (folded, _) =
            prove_sumfold(instances, &mut transcript).expect("prove_sumfold failed");
        let d_sf = t0.elapsed();

        let t1 = Instant::now();
        let _proof = <PolyIOP<Fr> as SumCheck<Fr>>::prove(&folded.poly, &mut transcript)
            .expect("SumCheck::prove failed");
        let d_sc = t1.elapsed();

        let total = d_sf + d_sc;
        t_sumfold.push(d_sf.as_micros());
        t_sumcheck.push(d_sc.as_micros());
        t_total.push(total.as_micros());
        eprintln!(
            "[single] iter {}: sumfold={} us, sumcheck={} us, total={} us",
            i,
            d_sf.as_micros(),
            d_sc.as_micros(),
            total.as_micros()
        );
    }

    print_result("single/sumfold", &t_sumfold);
    print_result("single/sumcheck", &t_sumcheck);
    print_result("single/total", &t_total);
}

fn run_dist(
    pk: &ProvingKey<E, PCS>,
    circuits: &[MockCircuit<Fr>],
    party_id: usize,
    net_config: &NetworkConfig,
    iters: usize,
) {
    let mut nc = net_config.clone();
    nc.party_id = party_id;
    Net::init_from_file(&nc.hosts_file, nc.party_id);
    eprintln!(
        "[Party {}] Network initialized ({} parties)",
        party_id,
        Net::n_parties()
    );

    let mut t_sumfold = Vec::with_capacity(iters);
    let mut t_sumcheck = Vec::with_capacity(iters);
    let mut t_total = Vec::with_capacity(iters);

    for i in 0..iters {
        let instances: Vec<SumCheckInstance<Fr>> =
            circuits_to_sumcheck::<E, PCS>(pk, circuits).expect("circuits_to_sumcheck failed");
        let (polys, sums): (Vec<_>, Vec<_>) =
            instances.into_iter().map(|inst| (inst.poly, inst.sum)).unzip();

        let mut transcript = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();

        // Phase 1: d_sumfold
        let t0 = Instant::now();
        let transcript_opt = if Net::am_master() {
            Some(&mut transcript)
        } else {
            None
        };
        let (folded_instance, _sumfold_proof) =
            deSnark::d_sumfold::d_sumfold::<Fr, Net>(polys, sums, transcript_opt)
                .expect("d_sumfold failed");
        let d_sf = t0.elapsed();

        // Phase 2: d_prove (HyperPianist distributed SumCheck)
        let t1 = Instant::now();
        let transcript_opt = if Net::am_master() {
            Some(&mut transcript)
        } else {
            None
        };
        let _hp_proof = <PolyIOP<Fr> as SumCheck<Fr>>::d_prove::<Net>(
            &folded_instance.poly,
            transcript_opt,
        )
        .expect("d_prove failed");
        let d_sc = t1.elapsed();

        let total = d_sf + d_sc;
        t_sumfold.push(d_sf.as_micros());
        t_sumcheck.push(d_sc.as_micros());
        t_total.push(total.as_micros());

        let role = if Net::am_master() { "master" } else { "worker" };
        eprintln!(
            "[dist/{}] iter {}: sumfold={} us, sumcheck={} us, total={} us",
            role, i,
            d_sf.as_micros(),
            d_sc.as_micros(),
            total.as_micros()
        );
    }

    if Net::am_master() {
        print_result("dist/sumfold", &t_sumfold);
        print_result("dist/sumcheck", &t_sumcheck);
        print_result("dist/total", &t_total);
    }

    Net::deinit();
}

fn print_result(mode: &str, times_us: &[u128]) {
    let avg = times_us.iter().sum::<u128>() / times_us.len() as u128;
    let times_str: Vec<String> = times_us.iter().map(|t| t.to_string()).collect();
    println!(
        "BENCH_RESULT mode={} iters={} times_us={} avg_us={}",
        mode,
        times_us.len(),
        times_str.join(","),
        avg,
    );
}

struct Opts {
    mode: String,
    party_id: Option<usize>,
    iters: usize,
    config_path: String,
}

fn parse_args(args: &[String]) -> Opts {
    let mut mode = None;
    let mut party_id = None;
    let mut iters = 5usize;
    let mut config_path = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--mode" => {
                i += 1;
                mode = Some(args.get(i).expect("--mode requires a value").to_string());
            }
            "--party" => {
                i += 1;
                party_id = Some(
                    args.get(i)
                        .expect("--party requires a value")
                        .parse::<usize>()
                        .expect("Invalid party ID"),
                );
            }
            "--iters" => {
                i += 1;
                iters = args
                    .get(i)
                    .expect("--iters requires a value")
                    .parse::<usize>()
                    .expect("Invalid iters");
            }
            arg if !arg.starts_with('-') => {
                config_path = Some(arg.to_string());
            }
            other => {
                eprintln!("Unknown option: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }
    let mode = mode.unwrap_or_else(|| {
        if party_id.is_some() { "dist".to_string() } else {
            eprintln!("Usage: {} --mode <single|dist> [--party <ID>] [--iters <N>] <config.toml>", args[0]);
            std::process::exit(1);
        }
    });
    if mode == "dist" && party_id.is_none() {
        eprintln!("--party <ID> required for dist mode");
        std::process::exit(1);
    }
    let config_path = config_path.unwrap_or_else(|| {
        eprintln!("Missing <config.toml>");
        std::process::exit(1);
    });
    Opts { mode, party_id, iters, config_path }
}
