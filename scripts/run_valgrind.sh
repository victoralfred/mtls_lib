#!/bin/bash
# Run Valgrind memory leak detection on mTLS library tests
# Usage: ./scripts/run_valgrind.sh [test_pattern]
# Example: ./scripts/run_valgrind.sh test_identity

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"
SUPP_FILE="$PROJECT_ROOT/.valgrind.supp"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check for valgrind
if ! command -v valgrind &> /dev/null; then
    echo -e "${RED}Error: valgrind is not installed${NC}"
    echo "Install with: sudo apt-get install valgrind"
    exit 1
fi

# Check build directory
if [ ! -d "$BUILD_DIR" ]; then
    echo -e "${RED}Error: Build directory not found${NC}"
    echo "Run: mkdir build && cd build && cmake .. && make"
    exit 1
fi

# Find test executables
TEST_PATTERN="${1:-test_*}"
TESTS=$(find "$BUILD_DIR/tests" -maxdepth 1 -type f -executable -name "$TEST_PATTERN" 2>/dev/null || true)

if [ -z "$TESTS" ]; then
    echo -e "${YELLOW}No tests matching pattern: $TEST_PATTERN${NC}"
    echo "Available tests:"
    find "$BUILD_DIR/tests" -maxdepth 1 -type f -executable -name "test_*" -printf "  %f\n" 2>/dev/null || echo "  (none found)"
    exit 1
fi

# Valgrind options
VALGRIND_OPTS=(
    --leak-check=full
    --show-leak-kinds=definite,possible
    --track-origins=yes
    --error-exitcode=1
    --gen-suppressions=all
)

# Add suppression file if exists
if [ -f "$SUPP_FILE" ]; then
    VALGRIND_OPTS+=(--suppressions="$SUPP_FILE")
fi

echo -e "${YELLOW}Running Valgrind memory leak detection${NC}"
echo "Suppression file: $SUPP_FILE"
echo ""

FAILED=0
PASSED=0

for TEST in $TESTS; do
    TEST_NAME=$(basename "$TEST")
    echo -e "${YELLOW}Testing: $TEST_NAME${NC}"

    if valgrind "${VALGRIND_OPTS[@]}" "$TEST" > /dev/null 2>&1; then
        echo -e "${GREEN}  PASSED${NC}"
        ((PASSED++))
    else
        echo -e "${RED}  FAILED - Running with full output:${NC}"
        valgrind "${VALGRIND_OPTS[@]}" "$TEST" 2>&1 | head -50
        ((FAILED++))
    fi
done

echo ""
echo "================================"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo "================================"

if [ $FAILED -gt 0 ]; then
    exit 1
fi

echo -e "${GREEN}All tests passed memory leak detection${NC}"
