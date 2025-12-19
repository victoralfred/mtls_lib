#!/usr/bin/env bash
#
# Manage AFL++ fuzzing corpus
#
# This script provides utilities for managing AFL++ fuzzing corpuses:
# - Minimize corpus (remove redundant inputs)
# - Minimize test cases (reduce individual file sizes)
# - Merge corpuses from multiple runs
# - Analyze coverage statistics
# - Export/import corpus files
#
# Requirements:
#   - AFL++ installed (afl-cmin, afl-tmin, afl-showmap)
#   - AFL++ instrumented build (run build_afl.sh first)
#
# Usage:
#   ./tests/fuzz/scripts/manage_corpus.sh <command> [options]
#
# Commands:
#   minimize    Minimize corpus by removing redundant inputs
#   tmin        Minimize individual test cases
#   merge       Merge corpuses from multiple runs
#   analyze     Analyze corpus coverage statistics
#   export      Export corpus to tarball
#   import      Import corpus from tarball
#
# Examples:
#   # Minimize corpus for a target
#   ./tests/fuzz/scripts/manage_corpus.sh minimize -t fuzz_oversized_sans
#
#   # Minimize a specific crashing input
#   ./tests/fuzz/scripts/manage_corpus.sh tmin -t fuzz_oversized_sans -i crash.txt
#
#   # Merge all worker corpuses
#   ./tests/fuzz/scripts/manage_corpus.sh merge -t fuzz_oversized_sans
#
#   # Analyze coverage
#   ./tests/fuzz/scripts/manage_corpus.sh analyze -t fuzz_oversized_sans
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../" && pwd)"
BUILD_DIR="build_afl"

# Usage information
usage() {
    grep '^#' "$0" | grep -v '#!/usr/bin/env' | sed 's/^# \?//'
    exit 1
}

# Check for AFL++ tools
check_afl_tools() {
    local missing=0

    if ! command -v afl-cmin &> /dev/null; then
        echo -e "${RED}[!] Error: afl-cmin not found${NC}"
        missing=1
    fi

    if ! command -v afl-tmin &> /dev/null; then
        echo -e "${RED}[!] Error: afl-tmin not found${NC}"
        missing=1
    fi

    if ! command -v afl-showmap &> /dev/null; then
        echo -e "${RED}[!] Error: afl-showmap not found${NC}"
        missing=1
    fi

    if [ $missing -eq 1 ]; then
        echo "    Install AFL++: https://github.com/AFLplusplus/AFLplusplus"
        exit 1
    fi
}

# Minimize corpus
cmd_minimize() {
    local TARGET=""
    local INPUT_DIR=""
    local OUTPUT_DIR=""
    local MEMORY_LIMIT="none"

    # Parse arguments
    while getopts "t:i:o:m:" opt; do
        case $opt in
            t) TARGET="$OPTARG" ;;
            i) INPUT_DIR="$OPTARG" ;;
            o) OUTPUT_DIR="$OPTARG" ;;
            m) MEMORY_LIMIT="$OPTARG" ;;
            *) usage ;;
        esac
    done

    if [ -z "$TARGET" ]; then
        echo -e "${RED}[!] Error: Target is required (-t)${NC}"
        exit 1
    fi

    # Set default directories
    if [ -z "$INPUT_DIR" ]; then
        INPUT_DIR="${PROJECT_ROOT}/${BUILD_DIR}/afl_output/${TARGET}"
    fi

    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="${PROJECT_ROOT}/${BUILD_DIR}/afl_minimized/${TARGET}"
    fi

    TARGET_BINARY="${PROJECT_ROOT}/${BUILD_DIR}/tests/${TARGET}"

    if [ ! -f "$TARGET_BINARY" ]; then
        echo -e "${RED}[!] Error: Target binary not found: ${TARGET_BINARY}${NC}"
        exit 1
    fi

    if [ ! -d "$INPUT_DIR" ]; then
        echo -e "${RED}[!] Error: Input directory not found: ${INPUT_DIR}${NC}"
        exit 1
    fi

    echo -e "${GREEN}[+] Minimizing corpus for ${TARGET}${NC}"
    echo "    Input:  ${INPUT_DIR}"
    echo "    Output: ${OUTPUT_DIR}"
    echo ""

    # Count input files
    INPUT_COUNT=$(find "$INPUT_DIR" -type f | wc -l)
    echo -e "${BLUE}[*] Input corpus: ${INPUT_COUNT} files${NC}"

    # Run afl-cmin
    mkdir -p "$OUTPUT_DIR"

    local CMIN_CMD="afl-cmin -i $INPUT_DIR -o $OUTPUT_DIR"

    if [ "$MEMORY_LIMIT" != "none" ]; then
        CMIN_CMD="$CMIN_CMD -m $MEMORY_LIMIT"
    fi

    CMIN_CMD="$CMIN_CMD -- $TARGET_BINARY @@"

    echo -e "${BLUE}[*] Running: $CMIN_CMD${NC}"
    eval "$CMIN_CMD"

    # Count output files
    OUTPUT_COUNT=$(find "$OUTPUT_DIR" -type f | wc -l)

    echo ""
    echo -e "${GREEN}[+] Corpus minimization complete${NC}"
    echo "    Before: ${INPUT_COUNT} files"
    echo "    After:  ${OUTPUT_COUNT} files"
    echo "    Saved:  $((INPUT_COUNT - OUTPUT_COUNT)) files ($(( (INPUT_COUNT - OUTPUT_COUNT) * 100 / INPUT_COUNT ))% reduction)"
}

# Minimize test case
cmd_tmin() {
    local TARGET=""
    local INPUT_FILE=""
    local OUTPUT_FILE=""
    local MEMORY_LIMIT="none"

    # Parse arguments
    while getopts "t:i:o:m:" opt; do
        case $opt in
            t) TARGET="$OPTARG" ;;
            i) INPUT_FILE="$OPTARG" ;;
            o) OUTPUT_FILE="$OPTARG" ;;
            m) MEMORY_LIMIT="$OPTARG" ;;
            *) usage ;;
        esac
    done

    if [ -z "$TARGET" ]; then
        echo -e "${RED}[!] Error: Target is required (-t)${NC}"
        exit 1
    fi

    if [ -z "$INPUT_FILE" ]; then
        echo -e "${RED}[!] Error: Input file is required (-i)${NC}"
        exit 1
    fi

    if [ ! -f "$INPUT_FILE" ]; then
        echo -e "${RED}[!] Error: Input file not found: ${INPUT_FILE}${NC}"
        exit 1
    fi

    if [ -z "$OUTPUT_FILE" ]; then
        OUTPUT_FILE="${INPUT_FILE}.min"
    fi

    TARGET_BINARY="${PROJECT_ROOT}/${BUILD_DIR}/tests/${TARGET}"

    if [ ! -f "$TARGET_BINARY" ]; then
        echo -e "${RED}[!] Error: Target binary not found: ${TARGET_BINARY}${NC}"
        exit 1
    fi

    INPUT_SIZE=$(stat -c%s "$INPUT_FILE")

    echo -e "${GREEN}[+] Minimizing test case for ${TARGET}${NC}"
    echo "    Input:  ${INPUT_FILE} (${INPUT_SIZE} bytes)"
    echo "    Output: ${OUTPUT_FILE}"
    echo ""

    # Run afl-tmin
    local TMIN_CMD="afl-tmin -i $INPUT_FILE -o $OUTPUT_FILE"

    if [ "$MEMORY_LIMIT" != "none" ]; then
        TMIN_CMD="$TMIN_CMD -m $MEMORY_LIMIT"
    fi

    TMIN_CMD="$TMIN_CMD -- $TARGET_BINARY @@"

    echo -e "${BLUE}[*] Running: $TMIN_CMD${NC}"
    eval "$TMIN_CMD"

    OUTPUT_SIZE=$(stat -c%s "$OUTPUT_FILE")

    echo ""
    echo -e "${GREEN}[+] Test case minimization complete${NC}"
    echo "    Before: ${INPUT_SIZE} bytes"
    echo "    After:  ${OUTPUT_SIZE} bytes"
    echo "    Saved:  $((INPUT_SIZE - OUTPUT_SIZE)) bytes ($(( (INPUT_SIZE - OUTPUT_SIZE) * 100 / INPUT_SIZE ))% reduction)"
}

# Merge corpuses
cmd_merge() {
    local TARGET=""
    local OUTPUT_DIR=""

    # Parse arguments
    while getopts "t:o:" opt; do
        case $opt in
            t) TARGET="$OPTARG" ;;
            o) OUTPUT_DIR="$OPTARG" ;;
            *) usage ;;
        esac
    done

    if [ -z "$TARGET" ]; then
        echo -e "${RED}[!] Error: Target is required (-t)${NC}"
        exit 1
    fi

    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="${PROJECT_ROOT}/${BUILD_DIR}/afl_merged/${TARGET}"
    fi

    INPUT_BASE="${PROJECT_ROOT}/${BUILD_DIR}/afl_output/${TARGET}"

    if [ ! -d "$INPUT_BASE" ]; then
        echo -e "${RED}[!] Error: AFL output directory not found: ${INPUT_BASE}${NC}"
        exit 1
    fi

    echo -e "${GREEN}[+] Merging corpuses for ${TARGET}${NC}"
    echo "    Base:   ${INPUT_BASE}"
    echo "    Output: ${OUTPUT_DIR}"
    echo ""

    # Find all fuzzer queue directories
    QUEUES=$(find "$INPUT_BASE" -type d -name "queue" 2>/dev/null)

    if [ -z "$QUEUES" ]; then
        echo -e "${RED}[!] Error: No fuzzer queue directories found${NC}"
        exit 1
    fi

    QUEUE_COUNT=$(echo "$QUEUES" | wc -l)
    echo -e "${BLUE}[*] Found ${QUEUE_COUNT} fuzzer queue(s)${NC}"

    # Create output directory
    mkdir -p "$OUTPUT_DIR"

    # Copy all queue files
    FILE_COUNT=0
    for queue in $QUEUES; do
        FUZZER_NAME=$(basename "$(dirname "$queue")")
        echo -e "${BLUE}[*] Merging ${FUZZER_NAME}...${NC}"

        for file in "$queue"/*; do
            if [ -f "$file" ]; then
                cp "$file" "$OUTPUT_DIR/$(basename "$file")_${FUZZER_NAME}"
                FILE_COUNT=$((FILE_COUNT + 1))
            fi
        done
    done

    echo ""
    echo -e "${GREEN}[+] Corpus merge complete${NC}"
    echo "    Merged: ${FILE_COUNT} files from ${QUEUE_COUNT} fuzzer(s)"
    echo ""
    echo "Next: Minimize the merged corpus:"
    echo "  ./tests/fuzz/scripts/manage_corpus.sh minimize -t ${TARGET} -i ${OUTPUT_DIR}"
}

# Analyze corpus
cmd_analyze() {
    local TARGET=""
    local INPUT_DIR=""

    # Parse arguments
    while getopts "t:i:" opt; do
        case $opt in
            t) TARGET="$OPTARG" ;;
            i) INPUT_DIR="$OPTARG" ;;
            *) usage ;;
        esac
    done

    if [ -z "$TARGET" ]; then
        echo -e "${RED}[!] Error: Target is required (-t)${NC}"
        exit 1
    fi

    if [ -z "$INPUT_DIR" ]; then
        INPUT_DIR="${PROJECT_ROOT}/${BUILD_DIR}/afl_output/${TARGET}"
    fi

    if [ ! -d "$INPUT_DIR" ]; then
        echo -e "${RED}[!] Error: Input directory not found: ${INPUT_DIR}${NC}"
        exit 1
    fi

    TARGET_BINARY="${PROJECT_ROOT}/${BUILD_DIR}/tests/${TARGET}"

    if [ ! -f "$TARGET_BINARY" ]; then
        echo -e "${RED}[!] Error: Target binary not found: ${TARGET_BINARY}${NC}"
        exit 1
    fi

    echo -e "${GREEN}[+] Analyzing corpus for ${TARGET}${NC}"
    echo "    Input:  ${INPUT_DIR}"
    echo ""

    # Count files by type
    QUEUE_FILES=$(find "$INPUT_DIR" -path "*/queue/*" -type f 2>/dev/null | wc -l)
    CRASH_FILES=$(find "$INPUT_DIR" -path "*/crashes/*" -type f 2>/dev/null | wc -l)
    HANG_FILES=$(find "$INPUT_DIR" -path "*/hangs/*" -type f 2>/dev/null | wc -l)

    echo -e "${BLUE}Corpus Statistics:${NC}"
    echo "  Queue files:  ${QUEUE_FILES}"
    echo "  Crashes:      ${CRASH_FILES}"
    echo "  Hangs:        ${HANG_FILES}"
    echo ""

    # Analyze coverage for queue files
    if [ $QUEUE_FILES -gt 0 ]; then
        echo -e "${BLUE}Coverage Analysis:${NC}"

        TEMP_MAP=$(mktemp)
        TOTAL_EDGES=0

        # Get first queue directory
        QUEUE_DIR=$(find "$INPUT_DIR" -type d -name "queue" 2>/dev/null | head -n 1)

        if [ -n "$QUEUE_DIR" ]; then
            # Count files to analyze
            SAMPLE_SIZE=$(find "$QUEUE_DIR" -type f | wc -l)
            echo "  Analyzing ${SAMPLE_SIZE} files..."

            # Run afl-showmap on a sample
            for file in "$QUEUE_DIR"/*; do
                if [ -f "$file" ]; then
                    afl-showmap -o "$TEMP_MAP" -q -- "$TARGET_BINARY" "$file" 2>/dev/null || true
                fi
            done

            if [ -f "$TEMP_MAP" ]; then
                TOTAL_EDGES=$(wc -l < "$TEMP_MAP")
                echo "  Edge coverage: ${TOTAL_EDGES} edges"
            fi
        fi

        rm -f "$TEMP_MAP"
    fi

    echo ""

    # List crashes if any
    if [ $CRASH_FILES -gt 0 ]; then
        echo -e "${YELLOW}Crashes found:${NC}"
        find "$INPUT_DIR" -path "*/crashes/*" -type f 2>/dev/null | while read -r crash; do
            SIZE=$(stat -c%s "$crash")
            echo "  - $(basename "$crash") (${SIZE} bytes)"
        done
        echo ""
    fi

    # List hangs if any
    if [ $HANG_FILES -gt 0 ]; then
        echo -e "${YELLOW}Hangs found:${NC}"
        find "$INPUT_DIR" -path "*/hangs/*" -type f 2>/dev/null | while read -r hang; do
            SIZE=$(stat -c%s "$hang")
            echo "  - $(basename "$hang") (${SIZE} bytes)"
        done
        echo ""
    fi
}

# Export corpus
cmd_export() {
    local TARGET=""
    local INPUT_DIR=""
    local OUTPUT_FILE=""

    # Parse arguments
    while getopts "t:i:o:" opt; do
        case $opt in
            t) TARGET="$OPTARG" ;;
            i) INPUT_DIR="$OPTARG" ;;
            o) OUTPUT_FILE="$OPTARG" ;;
            *) usage ;;
        esac
    done

    if [ -z "$TARGET" ]; then
        echo -e "${RED}[!] Error: Target is required (-t)${NC}"
        exit 1
    fi

    if [ -z "$INPUT_DIR" ]; then
        INPUT_DIR="${PROJECT_ROOT}/${BUILD_DIR}/afl_output/${TARGET}"
    fi

    if [ ! -d "$INPUT_DIR" ]; then
        echo -e "${RED}[!] Error: Input directory not found: ${INPUT_DIR}${NC}"
        exit 1
    fi

    if [ -z "$OUTPUT_FILE" ]; then
        OUTPUT_FILE="${PROJECT_ROOT}/${TARGET}_corpus_$(date +%Y%m%d_%H%M%S).tar.gz"
    fi

    echo -e "${GREEN}[+] Exporting corpus for ${TARGET}${NC}"
    echo "    Input:  ${INPUT_DIR}"
    echo "    Output: ${OUTPUT_FILE}"
    echo ""

    tar -czf "$OUTPUT_FILE" -C "$(dirname "$INPUT_DIR")" "$(basename "$INPUT_DIR")"

    SIZE=$(stat -c%s "$OUTPUT_FILE")
    SIZE_MB=$((SIZE / 1024 / 1024))

    echo -e "${GREEN}[+] Corpus exported successfully${NC}"
    echo "    File: ${OUTPUT_FILE}"
    echo "    Size: ${SIZE_MB} MB"
}

# Import corpus
cmd_import() {
    local TARGET=""
    local INPUT_FILE=""
    local OUTPUT_DIR=""

    # Parse arguments
    while getopts "t:i:o:" opt; do
        case $opt in
            t) TARGET="$OPTARG" ;;
            i) INPUT_FILE="$OPTARG" ;;
            o) OUTPUT_DIR="$OPTARG" ;;
            *) usage ;;
        esac
    done

    if [ -z "$TARGET" ]; then
        echo -e "${RED}[!] Error: Target is required (-t)${NC}"
        exit 1
    fi

    if [ -z "$INPUT_FILE" ]; then
        echo -e "${RED}[!] Error: Input file is required (-i)${NC}"
        exit 1
    fi

    if [ ! -f "$INPUT_FILE" ]; then
        echo -e "${RED}[!] Error: Input file not found: ${INPUT_FILE}${NC}"
        exit 1
    fi

    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="${PROJECT_ROOT}/${BUILD_DIR}/afl_imported/${TARGET}"
    fi

    echo -e "${GREEN}[+] Importing corpus for ${TARGET}${NC}"
    echo "    Input:  ${INPUT_FILE}"
    echo "    Output: ${OUTPUT_DIR}"
    echo ""

    mkdir -p "$OUTPUT_DIR"
    tar -xzf "$INPUT_FILE" -C "$OUTPUT_DIR" --strip-components=1

    FILE_COUNT=$(find "$OUTPUT_DIR" -type f | wc -l)

    echo -e "${GREEN}[+] Corpus imported successfully${NC}"
    echo "    Files: ${FILE_COUNT}"
    echo "    Directory: ${OUTPUT_DIR}"
}

# Main command dispatcher
main() {
    if [ $# -eq 0 ]; then
        usage
    fi

    check_afl_tools

    COMMAND=$1
    shift

    case $COMMAND in
        minimize) cmd_minimize "$@" ;;
        tmin) cmd_tmin "$@" ;;
        merge) cmd_merge "$@" ;;
        analyze) cmd_analyze "$@" ;;
        export) cmd_export "$@" ;;
        import) cmd_import "$@" ;;
        *)
            echo -e "${RED}[!] Error: Unknown command: ${COMMAND}${NC}"
            usage
            ;;
    esac
}

main "$@"
