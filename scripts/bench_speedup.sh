#!/bin/bash
# Speedup Benchmark: single-node (2 threads) vs distributed (4 nodes × 2 threads)
#
# Measures "pure prove" time per phase (sumfold, sumcheck) and computes
# per-phase + overall speedup ratios.
#
# Usage:
#   ./scripts/bench_speedup.sh [iters]       # default: 5 iterations
#   ./scripts/bench_speedup.sh 10            # 10 iterations
#
# Environment:
#   DESNARK_CONFIG=<path>   Override config file (default: deSnark/examples/demo_config.toml)

set -e

ITERS="${1:-5}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="${DESNARK_CONFIG:-$PROJECT_ROOT/deSnark/examples/demo_config.toml}"
BINARY="$PROJECT_ROOT/target/release/examples/speedup_bench"
LOG_DIR="$PROJECT_ROOT/target/bench_speedup_logs"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Helper: extract avg_us for a given mode from BENCH_RESULT lines
extract_avg() {
    local output="$1"
    local mode="$2"
    echo "$output" | grep "^BENCH_RESULT mode=${mode} " | sed 's/.*avg_us=\([0-9]*\).*/\1/'
}

# Helper: compute speedup string (2 decimal places, integer arithmetic)
compute_speedup() {
    local single="$1"
    local dist="$2"
    if [[ "$dist" -gt 0 ]]; then
        local x100=$(( single * 100 / dist ))
        local int_part=$(( x100 / 100 ))
        local frac_part=$(( x100 % 100 ))
        printf "%d.%02d" "$int_part" "$frac_part"
    else
        echo "N/A"
    fi
}

# ─── Build ────────────────────────────────────────────────────────
echo -e "${YELLOW}Building speedup_bench (release, no debug assertions)...${NC}"
cd "$PROJECT_ROOT"
cargo build --example speedup_bench -p deSnark --release 2>&1 | tail -3
echo -e "${GREEN}Build complete.${NC}"
echo ""

if [[ ! -f "$BINARY" ]]; then
    echo -e "${RED}Binary not found at $BINARY${NC}"
    exit 1
fi

mkdir -p "$LOG_DIR"

# ─── Single-node ──────────────────────────────────────────────────
echo -e "${CYAN}════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Phase 1: Single-node (2 threads, $ITERS iters)${NC}"
echo -e "${CYAN}════════════════════════════════════════════════${NC}"

SINGLE_OUTPUT=$( \
    RAYON_NUM_THREADS=2 RUST_LOG=warn \
    "$BINARY" --mode single --iters "$ITERS" "$CONFIG_FILE" \
    2>"$LOG_DIR/single.log" \
)
echo "$SINGLE_OUTPUT"

S_SUMFOLD=$(extract_avg "$SINGLE_OUTPUT" "single/sumfold")
S_SUMCHECK=$(extract_avg "$SINGLE_OUTPUT" "single/sumcheck")
S_TOTAL=$(extract_avg "$SINGLE_OUTPUT" "single/total")

if [[ -z "$S_TOTAL" ]]; then
    echo -e "${RED}Failed to parse single-node result.${NC}"
    echo "Output: $SINGLE_OUTPUT"
    cat "$LOG_DIR/single.log"
    exit 1
fi

echo ""
echo -e "${GREEN}Single-node avg:  sumfold=${S_SUMFOLD} us  sumcheck=${S_SUMCHECK} us  total=${S_TOTAL} us${NC}"
echo ""

# ─── Distributed (4 nodes) ───────────────────────────────────────
echo -e "${CYAN}════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Phase 2: Distributed (4 nodes × 2 threads, $ITERS iters)${NC}"
echo -e "${CYAN}════════════════════════════════════════════════${NC}"

# Kill any leftover processes on the benchmark ports
for port in 12350 12351 12352 12353; do
    lsof -ti:$port 2>/dev/null | xargs kill -9 2>/dev/null || true
done
pkill -f "speedup_bench.*--mode dist" 2>/dev/null || true
sleep 1

# Start workers (parties 1-3)
WORKER_PIDS=()
for i in 1 2 3; do
    echo -e "  ${GREEN}→${NC} Party $i (worker)"
    RAYON_NUM_THREADS=2 RUST_LOG=warn \
        "$BINARY" --mode dist --party $i --iters "$ITERS" "$CONFIG_FILE" \
        > "$LOG_DIR/party$i.log" 2>&1 &
    WORKER_PIDS+=($!)
done
sleep 2

# Start master (party 0) — capture stdout for BENCH_RESULT
echo -e "  ${GREEN}→${NC} Party 0 (master)"
DIST_OUTPUT=$( \
    RAYON_NUM_THREADS=2 RUST_LOG=warn \
    "$BINARY" --mode dist --party 0 --iters "$ITERS" "$CONFIG_FILE" \
    2>"$LOG_DIR/party0.log" \
)
echo "$DIST_OUTPUT"

# Wait a moment then clean up workers
sleep 2
for pid in "${WORKER_PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
done
wait 2>/dev/null || true

D_SUMFOLD=$(extract_avg "$DIST_OUTPUT" "dist/sumfold")
D_SUMCHECK=$(extract_avg "$DIST_OUTPUT" "dist/sumcheck")
D_TOTAL=$(extract_avg "$DIST_OUTPUT" "dist/total")

if [[ -z "$D_TOTAL" ]]; then
    echo -e "${RED}Failed to parse distributed result.${NC}"
    echo "Output: $DIST_OUTPUT"
    echo ""
    echo "Master log:"
    cat "$LOG_DIR/party0.log"
    exit 1
fi

echo ""
echo -e "${GREEN}Distributed avg:  sumfold=${D_SUMFOLD} us  sumcheck=${D_SUMCHECK} us  total=${D_TOTAL} us${NC}"
echo ""

# ─── Summary ─────────────────────────────────────────────────────
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Summary ($ITERS iterations)${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo ""

SP_SUMFOLD=$(compute_speedup "$S_SUMFOLD" "$D_SUMFOLD")
SP_SUMCHECK=$(compute_speedup "$S_SUMCHECK" "$D_SUMCHECK")
SP_TOTAL=$(compute_speedup "$S_TOTAL" "$D_TOTAL")

printf "  ${BOLD}%-12s %12s %12s %12s${NC}\n" "" "Single (us)" "Dist (us)" "Speedup"
printf "  %-12s %12s %12s %12s\n"             "─────────" "──────────" "──────────" "──────────"
printf "  ${YELLOW}%-12s${NC} %12s %12s     ${GREEN}%sx${NC}\n" "SumFold"  "$S_SUMFOLD" "$D_SUMFOLD" "$SP_SUMFOLD"
printf "  ${YELLOW}%-12s${NC} %12s %12s     ${GREEN}%sx${NC}\n" "SumCheck" "$S_SUMCHECK" "$D_SUMCHECK" "$SP_SUMCHECK"
printf "  %-12s %12s %12s %12s\n"             "─────────" "──────────" "──────────" "──────────"
printf "  ${BOLD}%-12s${NC} %12s %12s     ${GREEN}${BOLD}%sx${NC}\n" "Total" "$S_TOTAL" "$D_TOTAL" "$SP_TOTAL"
echo ""
echo -e "Logs: ${YELLOW}$LOG_DIR/${NC}"
