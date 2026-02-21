# deSnark — Distributed SNARK Protocol

Distributed proving protocol that splits a HyperPlonk SNARK across multiple parties using SumFold.

## Architecture

```
Master (party 0)          Workers (parties 1..K-1)
      │                         │
      ├── Network sync ─────────┤
      ├── SRS setup ─────────── ┤
      ├── Circuit gen + preprocess ┤
      ├── SumFold ───────────── ┤
      ├── HyperPianist ──────── ┤
      └── Proof assembly        │
```

**Star topology**: Master connects to all workers; workers bind and listen first.

## Quick Start

```bash
# Build
./scripts/run_desnark_demo.sh build

# Run in tmux 2×2 grid with synced scrolling
./scripts/run_desnark_demo.sh tmux
```

## Demo Script

`./scripts/run_desnark_demo.sh [command]`

| Command     | Description                                               |
| ----------- | --------------------------------------------------------- |
| `build`     | Build the example binary (`--release`)                    |
| `run`       | Run 4 nodes, wait for completion, print summary (default) |
| `tmux`      | Run 4 nodes in a tmux 2×2 grid with synced scrolling      |
| `multitail` | Run 4 nodes with multitail live view                      |
| `logs`      | Show logs from previous run                               |
| `clean`     | Kill processes and remove logs                            |

### Environment Variables

| Variable                                 | Default                             | Description                                                              |
| ---------------------------------------- | ----------------------------------- | ------------------------------------------------------------------------ |
| `RUST_LOG`                               | `info`                              | Log level filter (e.g. `debug`, `info,deNetwork=debug`)                  |
| `DESNARK_CONFIG`                         | `deSnark/examples/demo_config.toml` | Path to TOML config file                                                 |
| `CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS` | unset                               | Set to `true` before `build` to keep `debug_assert!()` in release binary |

**Example — release build with debug assertions:**

```bash
CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true ./scripts/run_desnark_demo.sh build
./scripts/run_desnark_demo.sh run
```

**Example — use production config:**

```bash
DESNARK_CONFIG=deSnark/examples/demo_config.prod.toml ./scripts/run_desnark_demo.sh tmux
```

### tmux Keybindings

All 4 panes are synchronized — keystrokes go to every pane simultaneously.

| Key         | Action                           |
| ----------- | -------------------------------- |
| `Ctrl-C`    | Pause live follow → scroll       |
| `↑/↓`       | Scroll up/down                   |
| `PgUp/PgDn` | Scroll page                      |
| `g` / `G`   | Jump to top / bottom             |
| `F`         | Resume live follow               |
| `q`         | Quit less (closes pane)          |
| `Ctrl-b d`  | Detach tmux (nodes keep running) |

## Configuration

The demo reads `deSnark/examples/demo_config.toml`:

```toml
[config]
log_num_instances = 2      # ν: M = 2^ν = 4 instances
log_num_constraints = 10   # μ: N = 2^μ = 1024 constraints per instance
gate_type = "vanilla"      # Vanilla PLONK gate
log_num_parties = 2        # κ: K = 2^κ = 4 parties
srs_path = "srs.params"    # Optional SRS cache file

[network]
hosts_file = "deSnark/examples/hosts_4.txt"
```

### Parameters

| Parameter             | Symbol | Description                          |
| --------------------- | ------ | ------------------------------------ |
| `log_num_instances`   | ν      | log₂(M), number of circuit instances |
| `log_num_constraints` | μ      | log₂(N), constraints per instance    |
| `gate_type`           |        | Gate type (`"vanilla"`)              |
| `log_num_parties`     | κ      | log₂(K), number of sub-provers       |
| `srs_path`            |        | SRS file cache path (optional)       |

Each sub-prover handles all M instances, each with N/K constraints.

### Hosts File

One `HOST:PORT` per line, ordered by party ID:

```
127.0.0.1:12350   # party 0 (master)
127.0.0.1:12351   # party 1
127.0.0.1:12352   # party 2
127.0.0.1:12353   # party 3
```

## Manual Execution

```bash
# Build
cargo build --example dist_prove_demo -p deSnark --release

# Start workers first (they bind and listen)
./target/release/examples/dist_prove_demo --party 1 deSnark/examples/demo_config.toml &
./target/release/examples/dist_prove_demo --party 2 deSnark/examples/demo_config.toml &
./target/release/examples/dist_prove_demo --party 3 deSnark/examples/demo_config.toml &
sleep 2

# Start master last (it connects to workers)
./target/release/examples/dist_prove_demo --party 0 deSnark/examples/demo_config.toml
```

## Verification: `verify_proof_eval`

After the distributed proving pipeline completes, the master runs `verify_proof_eval` to check that the combined proof (SumFold + HyperPianist) is valid and consistent with the original circuit data.

### Step 1: Verify SumFold + HyperPianist on a shared transcript

The prover threads a single Fiat-Shamir transcript through SumFold and then HyperPianist. The verifier uses the same single transcript to verify both phases sequentially:

**Step 1a — SumFold SumCheck**

1. **Initialize** a fresh `IOPTranscript`.
2. **Extract the SumFold proof** from the combined proof (first `num_sumfold_rounds` rounds).
3. **Call `verify_sum_fold_with_transcript`** on the shared transcript. This appends `q_aux_info`, squeezes \(\rho\), and verifies each SumCheck round. Returns the subclaim \((r_b, c)\) and \(\rho\).
4. **Check the consistency relation**:

$$c = v \cdot \text{eq}(\rho, r_b)$$

where \(v\) is the claimed folded sum. This ensures the SumFold aggregation is sound.

**Step 1b — HyperPianist SumCheck** (continues on the same transcript)

5. **Extract the HyperPianist proof** (remaining rounds after `num_sumfold_rounds`).
6. **Call `SumCheck::verify(v, hp_proof, hp_aux_info, transcript)`** on the same transcript whose state was advanced by Step 1a.

This produces a **subclaim** \((r, c)\): "the folded polynomial at point \(r\) should equal \(c\)".

### Step 2: Evaluate the Folded Polynomial at the Challenge Point

The folded polynomial has the structure:

$$P(\mathbf{x}) = \sum_p \text{coeff}_p \cdot \prod_{j \in \text{prod}_p} \left[ \sum_{i=0}^{M-1} \text{eq}(\mathbf{r}_b, i) \cdot \text{mle}_j^{(i)}(\mathbf{x}) \right]$$

This is a **"product of sums"** structure — each MLE is first folded across all M circuits with eq weights, then the gate function computes products of the folded values.

The verifier computes \(P(r_{\text{phase1}})\) directly from circuit data:

1. **Extract challenge coordinates**:
   - \(r_b\) = first `num_sumfold_rounds` components of the proof point (SumFold random coordinates).
   - \(r_{\text{phase1}}\) = first `num_vars` components of the subclaim point (original polynomial variables).

2. **Compute eq weights**: \(\text{eq\_rb\_vec}[i] = \text{eq}(r_b, i)\) for \(i \in [0, M)\), using `build_eq_x_r_vec`.

3. **Fold selector and witness evaluations** across all M circuits:
   - For each circuit \(i\) and each selector \(j\): \(\text{folded\_sel\_evals}[j] \mathrel{+}= \text{eq}(r_b, i) \cdot \text{sel}_j^{(i)}(r_{\text{phase1}})\)
   - For each circuit \(i\) and each witness \(j\): \(\text{folded\_wit\_evals}[j] \mathrel{+}= \text{eq}(r_b, i) \cdot \text{wit}_j^{(i)}(r_{\text{phase1}})\)

4. **Apply the gate function**: \(\text{folded\_eval} = \text{eval\_f}(\text{gate\_func}, \text{folded\_sel\_evals}, \text{folded\_wit\_evals})\).

### Step 3: Compare Subclaim Against Folded Evaluation

The final check is a simple equality test:

```
subclaim.expected_evaluation == folded_eval
```

If they match, the proof is consistent with the circuit data. If not, verification fails.

### Summary

| Step    | Action                                                         | Purpose                                            |
| ------- | -------------------------------------------------------------- | -------------------------------------------------- |
| Step 1a | Verify SumFold SumCheck + consistency check \(c = v \cdot \text{eq}(\rho, r_b)\) on shared transcript | Ensure SumFold aggregation is sound                |
| Step 1b | Verify HyperPianist SumCheck on same transcript                | Reduce "sum equation" to "single-point evaluation" |
| Step 2  | Compute folded polynomial value from raw circuit data          | Obtain ground truth                                |
| Step 3  | Assert subclaim == ground truth                                | Soundness check                                    |

## Feature Flags

| Feature       | Description                    |
| ------------- | ------------------------------ |
| `parallel`    | Rayon parallelism (default on) |
| `print-trace` | Timing traces via `ark-std`    |

## Speedup Benchmark

Compares single-node proving (2 Rayon threads) against distributed proving (4 nodes × 2 threads each), reporting per-phase (SumFold, SumCheck) and total timings with speedup ratios.

### Quick Start

```bash
# Build & run with default 5 iterations
./scripts/bench_speedup.sh

# Run with 10 iterations
./scripts/bench_speedup.sh 10

# Use a different config
DESNARK_CONFIG=deSnark/examples/demo_config.prod.toml ./scripts/bench_speedup.sh
```

The script automatically:
1. Builds `speedup_bench` in release mode (no debug assertions)
2. Runs single-node benchmark (`RAYON_NUM_THREADS=2`)
3. Launches 4 distributed nodes (workers first, then master)
4. Prints a summary table with per-phase speedup

Example output:

```
               Single (us)  Dist (us)      Speedup
  ─────────  ──────────── ──────────── ────────────
  SumFold         123456       45678       2.70x
  SumCheck        234567       67890       3.45x
  ─────────  ──────────── ──────────── ────────────
  Total           358023      113568       3.15x
```

### Manual Execution

```bash
# Build
cargo build --example speedup_bench -p deSnark --release

# Single-node
RAYON_NUM_THREADS=2 ./target/release/examples/speedup_bench \
    --mode single --iters 5 deSnark/examples/demo_config.toml

# Distributed (start workers first, then master)
for i in 1 2 3; do
    RAYON_NUM_THREADS=2 ./target/release/examples/speedup_bench \
        --mode dist --party $i --iters 5 deSnark/examples/demo_config.toml &
done
sleep 2
RAYON_NUM_THREADS=2 ./target/release/examples/speedup_bench \
    --mode dist --party 0 --iters 5 deSnark/examples/demo_config.toml
```

### CLI Options

| Option          | Default | Description                                 |
| --------------- | ------- | ------------------------------------------- |
| `--mode <MODE>` | —       | `single` (one node) or `dist` (distributed) |
| `--party <ID>`  | —       | Party ID (required for `dist` mode)         |
| `--iters <N>`   | `5`     | Number of benchmark iterations              |
| `<config.toml>` | —       | Path to TOML config file (positional)       |

### Environment Variables

| Variable           | Default | Description                                    |
| ------------------ | ------- | ---------------------------------------------- |
| `RAYON_NUM_THREADS` | all CPUs | Number of Rayon threads per process           |
| `RUST_LOG`         | `warn`  | Log level (set to `info` or `debug` for detail) |
| `DESNARK_CONFIG`   | `deSnark/examples/demo_config.toml` | Config override (script only) |

Logs are saved to `target/bench_speedup_logs/`.

## Tests

```bash
cargo test -p deSnark
```
