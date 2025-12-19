#!/usr/bin/env bash
#
# Run AFL++ fuzzing on mTLS library
#
# This script runs AFL++ fuzzing with proper configuration for the mTLS library.
# It supports parallel fuzzing with multiple workers.
#
# Requirements:
#   - AFL++ installed
#   - AFL++ instrumented build (run build_afl.sh first)
#
# Usage:
#   ./tests/fuzz/scripts/run_afl.sh [options]
#
# Options:
#   -t TARGET     Fuzzing target (fuzz_oversized_sans, or test_identity, etc.)
#   -w WORKERS    Number of parallel workers (default: 4)
#   -d DURATION   Fuzzing duration in seconds (default: unlimited)
#   -i INPUT_DIR  Input corpus directory (default: tests/fuzz/corpus/<target>)
#   -o OUTPUT_DIR Output directory (default: build_afl/afl_output/<target>)
#   -m MEMORY     Memory limit in MB (default: none)
#   -h            Show this help message
#
# Examples:
#   # Fuzz oversized SANs with default settings
#   ./tests/fuzz/scripts/run_afl.sh -t fuzz_oversized_sans
#
#   # Fuzz with 8 workers for 1 hour
#   ./tests/fuzz/scripts/run_afl.sh -t fuzz_oversized_sans -w 8 -d 3600
#

set -euo pipefail

# Configuration defaults
TARGET=""
WORKERS=4
DURATION=""
INPUT_DIR=""
OUTPUT_DIR=""
MEMORY_LIMIT="none"
BUILD_DIR="build_afl"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

# Usage information
usage() {
    grep '^#' "$0" | grep -v '#!/usr/bin/env' | sed 's/^# \?//'
    exit 1
}

# Parse arguments
while getopts "t:w:d:i:o:m:h" opt; do
    case $opt in
        t) TARGET="$OPTARG" ;;
        w) WORKERS="$OPTARG" ;;
        d) DURATION="$OPTARG" ;;
        i) INPUT_DIR="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        m) MEMORY_LIMIT="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Validate target
if [ -z "$TARGET" ]; then
    echo -e "${RED}[!] Error: Target is required${NC}"
    echo "    Available targets:"
    echo "      - fuzz_oversized_sans"
    echo "      - test_identity"
    echo "      - test_san_validation"
    echo ""
    usage
fi

# Check for AFL++
if ! command -v afl-fuzz &> /dev/null; then
    echo -e "${RED}[!] Error: afl-fuzz not found${NC}"
    echo "    Install AFL++: https://github.com/AFLplusplus/AFLplusplus"
    exit 1
fi

# Set default directories
if [ -z "$INPUT_DIR" ]; then
    # Try to find corpus in project
    if [ -d "${PROJECT_ROOT}/tests/fuzz/corpus/${TARGET}" ]; then
        INPUT_DIR="${PROJECT_ROOT}/tests/fuzz/corpus/${TARGET}"
    else
        # Create minimal corpus
        INPUT_DIR="${PROJECT_ROOT}/${BUILD_DIR}/afl_input/${TARGET}"
        mkdir -p "$INPUT_DIR"
        # Create minimal seed files
        echo "example.com" > "${INPUT_DIR}/seed1.txt"
        echo "*.example.com" > "${INPUT_DIR}/seed2.txt"
        echo "spiffe://trust-domain/service" > "${INPUT_DIR}/seed3.txt"
        echo -e "${YELLOW}[!] Created minimal corpus in ${INPUT_DIR}${NC}"
    fi
fi

if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="${PROJECT_ROOT}/${BUILD_DIR}/afl_output/${TARGET}"
fi

# Check if target binary exists
TARGET_BINARY="${PROJECT_ROOT}/${BUILD_DIR}/tests/${TARGET}"
if [ ! -f "$TARGET_BINARY" ]; then
    echo -e "${RED}[!] Error: Target binary not found: ${TARGET_BINARY}${NC}"
    echo "    Run build_afl.sh first to build AFL++ instrumented binaries."
    exit 1
fi

# Check if target is instrumented
if ! nm "$TARGET_BINARY" 2>/dev/null | grep -q "__afl"; then
    echo -e "${RED}[!] Error: Target binary is not AFL++ instrumented${NC}"
    echo "    Run build_afl.sh to rebuild with AFL++ instrumentation."
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# AFL++ environment setup
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_AUTORESUME=1

# Display configuration
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  AFL++ Fuzzing Configuration${NC}"
echo -e "${GREEN}========================================${NC}"
echo "  Target:       $TARGET"
echo "  Binary:       $TARGET_BINARY"
echo "  Workers:      $WORKERS"
echo "  Input Dir:    $INPUT_DIR"
echo "  Output Dir:   $OUTPUT_DIR"
echo "  Memory Limit: $MEMORY_LIMIT"
if [ -n "$DURATION" ]; then
    echo "  Duration:     ${DURATION}s ($(($DURATION / 60)) minutes)"
fi
echo -e "${GREEN}========================================${NC}"
echo ""

# Check corpus
CORPUS_FILES=$(find "$INPUT_DIR" -type f 2>/dev/null | wc -l)
if [ "$CORPUS_FILES" -eq 0 ]; then
    echo -e "${RED}[!] Error: No corpus files found in ${INPUT_DIR}${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Found ${CORPUS_FILES} corpus files${NC}"

# AFL++ fuzzing command builder
build_afl_cmd() {
    local worker_id=$1
    local cmd="afl-fuzz"

    # Worker configuration
    if [ "$worker_id" -eq 0 ]; then
        cmd="$cmd -M fuzzer00"  # Main fuzzer
    else
        cmd="$cmd -S fuzzer$(printf '%02d' $worker_id)"  # Secondary fuzzer
    fi

    # Input/Output
    cmd="$cmd -i $INPUT_DIR"
    cmd="$cmd -o $OUTPUT_DIR"

    # Memory limit
    if [ "$MEMORY_LIMIT" != "none" ]; then
        cmd="$cmd -m $MEMORY_LIMIT"
    fi

    # Duration
    if [ -n "$DURATION" ]; then
        cmd="$cmd -V $DURATION"
    fi

    # Power schedules (different for each worker)
    case $((worker_id % 4)) in
        0) cmd="$cmd -p fast" ;;
        1) cmd="$cmd -p explore" ;;
        2) cmd="$cmd -p exploit" ;;
        3) cmd="$cmd -p coe" ;;
    esac

    # Target binary (bare invocation, AFL will handle input)
    cmd="$cmd -- $TARGET_BINARY @@"

    echo "$cmd"
}

# Cleanup handler
cleanup() {
    echo ""
    echo -e "${YELLOW}[!] Stopping all fuzzing workers...${NC}"
    pkill -P $$ afl-fuzz 2>/dev/null || true
    wait
    echo -e "${GREEN}[+] Fuzzing stopped${NC}"
    echo ""
    echo "Results in: $OUTPUT_DIR"
    echo "View stats: afl-whatsup -s $OUTPUT_DIR"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start fuzzing workers
echo -e "${GREEN}[+] Starting $WORKERS AFL++ fuzzing workers...${NC}"
echo ""

PIDS=()
for i in $(seq 0 $((WORKERS - 1))); do
    CMD=$(build_afl_cmd $i)

    if [ "$i" -eq 0 ]; then
        echo -e "${BLUE}[Worker $i - Main]${NC} $CMD"
    else
        echo -e "${BLUE}[Worker $i]${NC} $CMD"
    fi

    # Run in background, redirect output to log file
    LOG_FILE="$OUTPUT_DIR/worker_${i}.log"
    eval "$CMD" > "$LOG_FILE" 2>&1 &
    PIDS+=($!)

    # Small delay between workers
    sleep 1
done

echo ""
echo -e "${GREEN}[+] All workers started${NC}"
echo ""
echo "Monitor progress:"
echo "  - Status:      afl-whatsup -s $OUTPUT_DIR"
echo "  - Live view:   watch -n 5 'afl-whatsup -s $OUTPUT_DIR'"
echo "  - Worker logs: tail -f $OUTPUT_DIR/worker_*.log"
echo ""
echo "Press Ctrl+C to stop fuzzing"
echo ""

# Wait for all workers
wait "${PIDS[@]}"

echo -e "${GREEN}[+] Fuzzing completed${NC}"
echo "Results in: $OUTPUT_DIR"
