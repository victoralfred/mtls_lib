#!/bin/bash
#
# Install git hooks and development tools
#

set -e

PROJECT_ROOT=$(git rev-parse --show-toplevel)

echo "=========================================="
echo "  mTLS Development Tools Setup"
echo "=========================================="
echo ""

#
# 1. Install git hooks
#
echo "[1/3] Installing git hooks..."

# Create hooks directory if it doesn't exist
mkdir -p "$PROJECT_ROOT/.git/hooks"

# Copy pre-commit hook
if [ -f "$PROJECT_ROOT/.githooks/pre-commit" ]; then
    cp "$PROJECT_ROOT/.githooks/pre-commit" "$PROJECT_ROOT/.git/hooks/pre-commit"
    chmod +x "$PROJECT_ROOT/.git/hooks/pre-commit"
    echo "  ✓ Pre-commit hook installed"
else
    echo "  ✗ Pre-commit hook not found at .githooks/pre-commit"
    exit 1
fi

#
# 2. Configure git to use .githooks directory
#
echo ""
echo "[2/3] Configuring git hooks path..."
git config core.hooksPath "$PROJECT_ROOT/.githooks"
echo "  ✓ Git configured to use .githooks/"

#
# 3. Check for required tools
#
echo ""
echo "[3/3] Checking development tools..."

MISSING_TOOLS=0

check_tool() {
    local tool=$1
    local install_cmd=$2

    if command -v "$tool" &> /dev/null; then
        echo "  ✓ $tool found"
        return 0
    else
        echo "  ✗ $tool not found"
        echo "    Install: $install_cmd"
        MISSING_TOOLS=1
        return 1
    fi
}

# Check for clang-format
check_tool "clang-format" "sudo apt-get install clang-format"

# Check for clang-tidy
check_tool "clang-tidy" "sudo apt-get install clang-tidy"

# Check for cppcheck
check_tool "cppcheck" "sudo apt-get install cppcheck"

# Check for cmake
check_tool "cmake" "sudo apt-get install cmake"

# Check for git
check_tool "git" "sudo apt-get install git"

echo ""
if [ $MISSING_TOOLS -eq 0 ]; then
    echo "=========================================="
    echo "✓ Setup complete!"
    echo ""
    echo "All required tools are installed."
    echo "Git pre-commit hook is active."
    echo ""
    echo "To bypass hook: git commit --no-verify"
    echo "=========================================="
    echo ""
else
    echo "=========================================="
    echo "⚠ Setup complete with warnings"
    echo ""
    echo "Some tools are missing (see above)."
    echo "Install them for full validation."
    echo ""
    echo "The pre-commit hook will skip missing tools."
    echo "=========================================="
    echo ""
fi

# Make the hook executable
chmod +x "$PROJECT_ROOT/.githooks/pre-commit"

exit 0
