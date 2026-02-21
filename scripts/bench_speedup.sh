#!/bin/bash
# Speedup Benchmark: single-node (2 threads) vs distributed (4 nodes × 2 threads)
#
# Measures "pure prove" time and computes the speedup ratio.
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
NC='\033[0m'

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

SINGLE_AVG=$(echo "$SINGLE_OUTPUT" | grep '^BENCH_RESULT' | sed 's/.*avg_us=\([0-9]*\).*/\1/')
if [[ -z "$SINGLE_AVG" ]]; then
    echo -e "${RED}Failed to parse single-node result.${NC}"
    echo "Output: $SINGLE_OUTPUT"
    cat "$LOG_DIR/single.log"
    exit 1
fi

echo -e "${GREEN}Single-node avg: ${SINGLE_AVG} us${NC}"
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

DIST_AVG=$(echo "$DIST_OUTPUT" | grep '^BENCH_RESULT' | sed 's/.*avg_us=\([0-9]*\).*/\1/')
if [[ -z "$DIST_AVG" ]]; then
    echo -e "${RED}Failed to parse distributed result.${NC}"
    echo "Output: $DIST_OUTPUT"
    echo ""
    echo "Master log:"
    cat "$LOG_DIR/party0.log"
    exit 1
fi

echo -e "${GREEN}Distributed avg: ${DIST_AVG} us${NC}"
echo ""

# ─── Summary ─────────────────────────────────────────────────────
echo -e "${CYAN}════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Summary ($ITERS iterations)${NC}"
echo -e "${CYAN}════════════════════════════════════════════════${NC}"
echo ""

# Compute speedup (integer arithmetic with 2 decimal places)
if [[ "$DIST_AVG" -gt 0 ]]; then
    SPEEDUP_X100=$(( SINGLE_AVG * 100 / DIST_AVG ))
    SPEEDUP_INT=$(( SPEEDUP_X100 / 100 ))
    SPEEDUP_FRAC=$(( SPEEDUP_X100 % 100 ))
    printf -v SPEEDUP "%d.%02d" "$SPEEDUP_INT" "$SPEEDUP_FRAC"
else
    SPEEDUP="N/A"
fi

echo -e "  Single-node (2 threads):          ${YELLOW}${SINGLE_AVG} us${NC}"
echo -e "  Distributed  (4×2 = 8 threads):   ${YELLOW}${DIST_AVG} us${NC}"
echo -e "  Speedup:                           ${GREEN}${SPEEDUP}x${NC}"
echo ""
echo -e "Logs: ${YELLOW}$LOG_DIR/${NC}"
