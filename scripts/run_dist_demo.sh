#!/bin/bash
# Distributed Sum-Fold Demo Script for 4 Nodes
# 
# Usage: ./run_dist_demo.sh [command]
#   build     - build the binary
#   run       - run all 4 nodes (default)
#   multitail - run with multitail for parallel log viewing
#   watch     - run and tail logs in separate panes (requires tmux)
#   logs      - just show logs from previous run
#   clean     - kill processes and clean logs

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HOSTS_FILE="$PROJECT_ROOT/subroutines/examples/hosts_4.txt"
BINARY="$PROJECT_ROOT/target/release/examples/dist_sum_fold_demo"
LOG_DIR="$PROJECT_ROOT/target/dist_demo_logs"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}   Distributed Sum-Fold Demo (4 nodes)${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
}

print_usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  build     - Build the binary with distributed feature"
    echo "  run       - Run all 4 nodes (default)"
    echo "  multitail - Run with multitail for parallel log viewing"
    echo "  watch     - Tail logs in real-time after starting"
    echo "  logs      - Show logs from previous run"
    echo "  clean     - Kill processes and clean logs"
    echo ""
    echo "Examples:"
    echo "  $0 build      # Build first"
    echo "  $0 run        # Run demo"
    echo "  $0 multitail  # Run with multitail (best visualization)"
}

do_build() {
    echo -e "${YELLOW}Building with --features distributed --release...${NC}"
    cd "$PROJECT_ROOT"
    cargo build --example dist_sum_fold_demo -p subroutines --features distributed --release
    echo -e "${GREEN}Build complete!${NC}"
}

check_binary() {
    if [[ ! -f "$BINARY" ]]; then
        echo -e "${RED}Error: Binary not found at $BINARY${NC}"
        echo "Run '$0 build' first"
        exit 1
    fi
}

kill_existing() {
    echo -e "${YELLOW}Cleaning up existing processes...${NC}"
    for port in 12340 12341 12342 12343; do
        lsof -ti:$port 2>/dev/null | xargs kill -9 2>/dev/null || true
    done
    pkill -f "dist_sum_fold_demo" 2>/dev/null || true
    sleep 1
}

setup_logs() {
    mkdir -p "$LOG_DIR"
    # Clear old logs
    for i in 0 1 2 3; do
        > "$LOG_DIR/party$i.log"
    done
}

start_workers() {
    echo -e "${BLUE}Starting workers (parties 1, 2, 3)...${NC}"
    
    for i in 1 2 3; do
        echo -e "  ${GREEN}→${NC} Starting worker $i on port 1234$i"
        RUST_LOG=info,deNetwork=debug "$BINARY" $i "$HOSTS_FILE" >> "$LOG_DIR/party$i.log" 2>&1 &
        eval "PID$i=$!"
    done
    
    # Wait for workers to start listening
    echo -e "${YELLOW}Waiting for workers to initialize...${NC}"
    sleep 2
}

start_master() {
    echo -e "${BLUE}Starting master (party 0)...${NC}"
    RUST_LOG=info,deNetwork=debug "$BINARY" 0 "$HOSTS_FILE" >> "$LOG_DIR/party0.log" 2>&1 &
    PID0=$!
    echo -e "  ${GREEN}→${NC} Master started with PID $PID0"
}

wait_completion() {
    echo ""
    echo -e "${YELLOW}Waiting for protocol to complete...${NC}"
    
    # Wait for master
    wait $PID0 2>/dev/null || true
    
    # Give workers time to finish
    sleep 2
    
    # Kill remaining
    kill $PID1 $PID2 $PID3 2>/dev/null || true
}

show_summary() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}   Results Summary${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    
    for i in 0 1 2 3; do
        if [[ $i -eq 0 ]]; then
            label="Master"
            color="${GREEN}"
        else
            label="Worker $i"
            color="${BLUE}"
        fi
        
        echo ""
        echo -e "${color}─── Party $i ($label) ───${NC}"
        if [[ -f "$LOG_DIR/party$i.log" ]]; then
            # Show key lines
            grep -E "(Initialized|Starting|completed|sum_t|Done|Error)" "$LOG_DIR/party$i.log" 2>/dev/null | tail -8 || echo "(no key output)"
        else
            echo "(no log file)"
        fi
    done
    
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "Full logs available in: ${YELLOW}$LOG_DIR/${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
}

do_run() {
    check_binary
    kill_existing
    setup_logs
    
    echo ""
    echo -e "Project root: ${YELLOW}$PROJECT_ROOT${NC}"
    echo -e "Hosts file:   ${YELLOW}$HOSTS_FILE${NC}"
    echo -e "Log dir:      ${YELLOW}$LOG_DIR${NC}"
    echo ""
    
    start_workers
    start_master
    
    echo ""
    echo -e "${CYAN}Process IDs:${NC}"
    echo "  Party 0 (master): $PID0"
    echo "  Party 1 (worker): $PID1"
    echo "  Party 2 (worker): $PID2"
    echo "  Party 3 (worker): $PID3"
    
    wait_completion
    show_summary
}

do_multitail() {
    check_binary
    
    # Check if multitail is installed
    if ! command -v multitail &> /dev/null; then
        echo -e "${RED}Error: multitail is not installed${NC}"
        echo ""
        echo "Install with:"
        echo "  macOS:  brew install multitail"
        echo "  Ubuntu: sudo apt install multitail"
        echo ""
        echo "Alternative: use '$0 watch' for simple tail -f"
        exit 1
    fi
    
    kill_existing
    setup_logs
    
    echo ""
    echo -e "Starting nodes and launching multitail..."
    echo -e "${YELLOW}Press 'q' in multitail to exit${NC}"
    echo ""
    
    start_workers
    start_master
    
    # Launch multitail with 2x2 grid layout
    # -s 2 = 2 columns
    # -t sets the window title, -ci sets color
    multitail -s 2 \
        -t "Party 0 (Master)" -ci green "$LOG_DIR/party0.log" \
        -t "Party 1 (Worker)" -ci cyan "$LOG_DIR/party1.log" \
        -t "Party 2 (Worker)" -ci yellow "$LOG_DIR/party2.log" \
        -t "Party 3 (Worker)" -ci magenta "$LOG_DIR/party3.log"
    
    # Cleanup after multitail exits
    kill_existing
}

do_watch() {
    check_binary
    kill_existing
    setup_logs
    
    echo -e "${YELLOW}Starting nodes and tailing logs...${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
    echo ""
    
    start_workers
    start_master
    
    echo ""
    echo -e "${CYAN}═══ Tailing all logs (Ctrl+C to stop) ═══${NC}"
    echo ""
    
    # Simple tail of all logs with prefix
    tail -f "$LOG_DIR/party0.log" "$LOG_DIR/party1.log" "$LOG_DIR/party2.log" "$LOG_DIR/party3.log"
}

do_logs() {
    echo -e "${CYAN}═══ Previous Run Logs ═══${NC}"
    
    for i in 0 1 2 3; do
        if [[ $i -eq 0 ]]; then
            label="Master"
        else
            label="Worker $i"
        fi
        
        echo ""
        echo -e "${BLUE}─── Party $i ($label) ───${NC}"
        if [[ -f "$LOG_DIR/party$i.log" ]]; then
            cat "$LOG_DIR/party$i.log"
        else
            echo "(no log file)"
        fi
    done
}

do_clean() {
    echo -e "${YELLOW}Cleaning up...${NC}"
    kill_existing
    if [[ -d "$LOG_DIR" ]]; then
        rm -rf "$LOG_DIR"
        echo "Removed $LOG_DIR"
    fi
    echo -e "${GREEN}Done${NC}"
}

# Main
print_header

case "${1:-run}" in
    build)
        do_build
        ;;
    run)
        do_run
        ;;
    multitail)
        do_multitail
        ;;
    watch)
        do_watch
        ;;
    logs)
        do_logs
        ;;
    clean)
        do_clean
        ;;
    -h|--help|help)
        print_usage
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        print_usage
        exit 1
        ;;
esac
