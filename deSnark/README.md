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

After the distributed proving pipeline completes, the master runs `verify_proof_eval` to check that the SumCheck proof is consistent with the original circuit data. This is the SumCheck protocol's final "oracle query" step: SumCheck reduces "sum over the boolean hypercube" to "evaluation at a random point", and `verify_proof_eval` fulfills that evaluation using the raw circuit polynomials.

### Step 1: Replay Transcript and Verify HyperPianist SumCheck

The prover threads a single Fiat-Shamir transcript through SumFold → d_prove (HyperPianist). The verifier must replay the same transcript operations to derive identical challenges.

1. **Initialize** a fresh `IOPTranscript`.
2. **Replay SumFold operations**:
   - Append `q_aux_info` to the transcript.
   - Generate the challenge vector ρ = (ρ₁, …, ρ_{log₂M}) via `get_and_append_challenge_vectors("sumfold rho")`.
   - For each of the `num_sumfold_rounds` rounds, append the prover message and generate the round challenge.
3. **Split the combined proof** into the SumFold portion (first `num_sumfold_rounds` rounds) and the HyperPianist portion (remaining rounds).
4. **Verify HyperPianist SumCheck** by calling `SumCheck::verify(v, hp_proof, hp_aux_info, transcript)`, where `v` is the folded sum from SumFold.

This produces a **subclaim** (r, c): "the folded polynomial at point r should equal c".

### Step 2: Evaluate the Folded Polynomial at the Challenge Point

The folded polynomial has the structure:

$$P(\mathbf{x}) = \sum_p \text{coeff}_p \cdot \prod_{j \in \text{prod}_p} \left[ \sum_{i=0}^{M-1} \text{eq}(\mathbf{r}_b, i) \cdot \text{mle}_j^{(i)}(\mathbf{x}) \right]$$

This is a **"product of sums"** structure — each MLE is first folded across all M circuits with eq weights, then the gate function computes products of the folded values.

The verifier computes P(r_phase1) directly from circuit data:

1. **Extract challenge coordinates**:
   - r_b = first `num_sumfold_rounds` components of the proof point (SumFold random coordinates).
   - r_phase1 = first `num_vars` components of the subclaim point (original polynomial variables).

2. **Compute eq weights**: eq_rb_vec\[i\] = eq(r_b, i) for i ∈ \[0, M), using `build_eq_x_r_vec`.

3. **Fold selector and witness evaluations** across all M circuits:
   - For each circuit i and each selector j: `folded_sel_evals[j] += eq(r_b, i) · sel_j^(i)(r_phase1)`
   - For each circuit i and each witness j: `folded_wit_evals[j] += eq(r_b, i) · wit_j^(i)(r_phase1)`

4. **Apply the gate function**: `folded_eval = eval_f(gate_func, folded_sel_evals, folded_wit_evals)`.

### Step 3: Compare Subclaim Against Folded Evaluation

The final check is a simple equality test:

```
subclaim.expected_evaluation == folded_eval
```

If they match, the proof is consistent with the circuit data. If not, verification fails.

### Summary

| Step   | Action                                                   | Purpose                                            |
| ------ | -------------------------------------------------------- | -------------------------------------------------- |
| Step 1 | Replay SumFold transcript → verify HyperPianist SumCheck | Reduce "sum equation" to "single-point evaluation" |
| Step 2 | Compute folded polynomial value from raw circuit data    | Obtain ground truth                                |
| Step 3 | Assert subclaim == ground truth                          | Soundness check                                    |

## Feature Flags

| Feature       | Description                    |
| ------------- | ------------------------------ |
| `parallel`    | Rayon parallelism (default on) |
| `print-trace` | Timing traces via `ark-std`    |

## Tests

```bash
cargo test -p deSnark
```
