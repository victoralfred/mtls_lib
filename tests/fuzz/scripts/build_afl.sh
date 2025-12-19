#!/usr/bin/env bash
#
# Build mTLS library with AFL++ instrumentation
#
# This script builds the mTLS library and fuzzing harnesses with AFL++
# instrumentation for coverage-guided fuzzing.
#
# Requirements:
#   - AFL++ installed (afl-clang-fast or afl-gcc)
#   - Run from project root directory
#
# Usage:
#   ./tests/fuzz/scripts/build_afl.sh [build_dir]
#
# Arguments:
#   build_dir - Optional build directory (default: build_afl)
#

set -euo pipefail

# Configuration
BUILD_DIR="${1:-build_afl}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "${PROJECT_ROOT}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}[+] Building mTLS library with AFL++ instrumentation${NC}"
echo "    Build directory: ${BUILD_DIR}"

# Check for AFL++ compiler
if command -v afl-clang-fast &> /dev/null; then
    AFL_CC="afl-clang-fast"
    AFL_CXX="afl-clang-fast++"
    echo -e "${GREEN}[+] Using afl-clang-fast${NC}"
elif command -v afl-gcc &> /dev/null; then
    AFL_CC="afl-gcc"
    AFL_CXX="afl-g++"
    echo -e "${YELLOW}[!] Using afl-gcc (afl-clang-fast recommended)${NC}"
else
    echo -e "${RED}[!] Error: AFL++ compiler not found${NC}"
    echo "    Install AFL++: https://github.com/AFLplusplus/AFLplusplus"
    exit 1
fi

# Create build directory
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

# Configure with AFL++ compiler
echo -e "${GREEN}[+] Configuring CMake with AFL++ instrumentation${NC}"
CC="${AFL_CC}" CXX="${AFL_CXX}" cmake \
    -DCMAKE_BUILD_TYPE=Debug \
    -DMTLS_BUILD_TESTS=ON \
    -DMTLS_BUILD_EXAMPLES=OFF \
    -DCMAKE_C_FLAGS="-g -O1 -fno-omit-frame-pointer" \
    ..

# Build
echo -e "${GREEN}[+] Building library and fuzzing harnesses${NC}"
cmake --build . --parallel "$(nproc 2>/dev/null || echo 4)"

# Verify AFL++ instrumentation
echo -e "${GREEN}[+] Verifying AFL++ instrumentation${NC}"
INSTRUMENTED=0
NOT_INSTRUMENTED=0
for binary in tests/fuzz_oversized_sans tests/test_*; do
    if [ -f "$binary" ] && [ -x "$binary" ]; then
        if nm "$binary" 2>/dev/null | grep -q "__afl"; then
            echo -e "${GREEN}  ✓ ${binary} is instrumented${NC}"
            INSTRUMENTED=$((INSTRUMENTED + 1))
        else
            echo -e "${YELLOW}  ⚠ ${binary} may not be instrumented${NC}"
            NOT_INSTRUMENTED=$((NOT_INSTRUMENTED + 1))
        fi
    fi
done

if [ $INSTRUMENTED -eq 0 ]; then
    echo -e "${RED}[!] Error: No AFL++ instrumentation detected!${NC}"
    echo "    Make sure AFL++ is properly installed and configured."
    exit 1
fi

echo -e "${GREEN}[+] Build complete!${NC}"
echo "    Instrumented: $INSTRUMENTED binaries"
if [ $NOT_INSTRUMENTED -gt 0 ]; then
    echo -e "${YELLOW}    Not instrumented: $NOT_INSTRUMENTED binaries${NC}"
fi

echo ""
echo "Next steps:"
echo "  1. Run AFL++ fuzzer: ./tests/fuzz/scripts/run_afl.sh"
echo "  2. Monitor progress: afl-whatsup -s ${BUILD_DIR}/afl_output"
