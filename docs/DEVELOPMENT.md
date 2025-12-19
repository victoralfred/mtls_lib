# Development Guide

**Industrial-Standard Development Workflow**

This document describes the development workflow, tooling, and quality standards for the mTLS library.

## Quick Start

### 1. Install Development Tools

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    clang-format \
    clang-tidy \
    cppcheck \
    git

# macOS
brew install cmake openssl clang-format cppcheck
```

### 2. Install Git Hooks

```bash
# Install pre-commit hook
make install-hooks

# Or manually:
bash scripts/install-hooks.sh
```

### 3. Verify Setup

```bash
# Check status
make status

# Run a test commit
git commit --allow-empty -m "Test commit"
```

---

## Pre-Commit Hook

The pre-commit hook enforces industrial code quality standards before allowing commits.

### Validation Steps

The hook performs **7 validation steps**:

#### 1. Code Formatting (clang-format)
- Checks all staged `.c` and `.h` files
- Uses `.clang-format` configuration
- Enforces:
  - 4-space indentation
  - 100-character line limit
  - Linux kernel brace style
  - Consistent spacing and alignment

**Auto-fix**:
```bash
make format
# or
clang-format -i <file>
```

#### 2. Static Analysis (clang-tidy)
- Analyzes C source files for:
  - Bug-prone patterns
  - Security vulnerabilities
  - Performance issues
  - Portability problems
- Uses `.clang-tidy` configuration

**View details**:
```bash
make check-tidy
```

#### 3. Code Quality (cppcheck)
- Additional static analysis
- Checks for:
  - Memory leaks
  - Null pointer dereferences
  - Buffer overflows
  - Unused variables

**Run manually**:
```bash
make check-cppcheck
```

#### 4. Build Verification
- Performs clean build
- Ensures code compiles without errors
- Captures warnings for review

**Build only**:
```bash
make build
```

#### 5. Test Execution
- Runs all unit tests
- Must have 100% pass rate
- Includes:
  - Identity verification tests (20 cases)
  - SAN validation tests (21 cases)
  - Security fixes tests

**Test only**:
```bash
make test
```

#### 6. Security Checks
- Scans for dangerous functions:
  - `strcpy`, `strcat`, `sprintf`, `gets`
- Flags fixed-size buffer usage
- Prevents common vulnerabilities

#### 7. Commit Message Validation
- Minimum 10 characters
- No Claude attribution (as per project requirements)
- Should be descriptive and meaningful

---

## Code Quality Standards

### Formatting Rules

Based on `.clang-format` configuration:

```c
// Good: Properly formatted
int mtls_connect(mtls_ctx* ctx, const char* addr, mtls_err* err) {
    if (!ctx) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Context is NULL");
        return -1;
    }

    // Implementation...
    return 0;
}

// Bad: Wrong indentation, line too long
int mtls_connect(mtls_ctx* ctx, const char* addr, mtls_err* err){
if(!ctx){
MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "This is a very long error message that exceeds the 100 character limit");
return -1;
}
return 0;
}
```

### Security Standards

```c
// Good: Safe string handling
char buffer[256];
snprintf(buffer, sizeof(buffer), "Value: %s", input);

// Bad: Unsafe functions
char buffer[256];
strcpy(buffer, input);  // ✗ Rejected by pre-commit hook
sprintf(buffer, "Value: %s", input);  // ✗ Rejected
```

### Naming Conventions

```c
// Good: Consistent naming
typedef struct mtls_connection mtls_connection;
int mtls_send_data(mtls_conn* conn, const void* data);
#define MTLS_MAX_BUFFER_SIZE 1024

// Bad: Inconsistent
typedef struct Connection conn_t;
int SendData(mtls_conn* c, void* d);
#define max_buffer 1024
```

---

## Development Workflow

### Normal Development

```bash
# 1. Make changes
vim src/mtls_conn.c

# 2. Format code
make format

# 3. Run tests
make test

# 4. Commit (hook runs automatically)
git add src/mtls_conn.c
git commit -m "Fix connection timeout handling"

# Hook output:
# [1/7] Checking code formatting... ✓
# [2/7] Running static analysis... ✓
# [3/7] Running cppcheck... ✓
# [4/7] Building project... ✓
# [5/7] Running tests... ✓
# [6/7] Running security checks... ✓
# [7/7] Validating commit message... ✓
# ✓ All validation checks passed!
```

### Emergency Bypass

For emergencies only:

```bash
# Skip pre-commit hook
git commit --no-verify -m "Emergency fix"

# Fix validation issues later
make format
make check
make test
git add -u
git commit --amend
```

### Failed Validation

If the hook fails:

```bash
# Example failure output:
# [1/7] Checking code formatting... ✗
#   ✗ Formatting issues in: src/mtls_conn.c
#   Fix with: clang-format -i src/mtls_conn.c

# Fix the issue
clang-format -i src/mtls_conn.c

# Try commit again
git add src/mtls_conn.c
git commit -m "Fix connection timeout handling"
```

---

## Available Make Targets

```bash
# Build
make build          # Build library
make clean          # Remove build artifacts
make rebuild        # Clean + build

# Testing
make test           # Run all tests
make test-verbose   # Verbose test output

# Code Quality
make format         # Format all files
make check          # Run static analysis
make lint           # Format + check

# Development
make install-hooks  # Install git hooks
make status         # Show project status
make docs           # Generate documentation
make coverage       # Generate coverage report
```

---

## Tool Configuration Files

### `.clang-format`

Defines code formatting rules:
- **Indentation**: 4 spaces, no tabs
- **Line length**: 100 characters
- **Brace style**: Linux kernel (K&R variant)
- **Pointer alignment**: Right (`int* ptr`)

### `.clang-tidy`

Configures static analysis:
- **Enabled checks**: bugprone, cert, security, performance
- **Disabled checks**: Magic numbers, cognitive complexity
- **Naming conventions**: lower_case for variables/functions

### `.githooks/pre-commit`

The main validation script:
- Runs automatically on `git commit`
- Can be bypassed with `--no-verify`
- Provides detailed error messages

---

## Continuous Integration

The project is designed for CI/CD integration:

```yaml
# Example GitHub Actions
name: CI

on: [push, pull_request]

jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y clang-format clang-tidy cppcheck

      - name: Run validation
        run: |
          make format
          make check
          make build
          make test
```

---

## Troubleshooting

### Hook Not Running

```bash
# Check if hook is executable
ls -l .git/hooks/pre-commit

# Reinstall hooks
make install-hooks
```

### clang-format Not Found

```bash
# Ubuntu/Debian
sudo apt-get install clang-format

# macOS
brew install clang-format

# Verify installation
clang-format --version
```

### Build Failures

```bash
# Clean rebuild
make clean
make build

# Check build log
cd build
make VERBOSE=1
```

### Test Failures

```bash
# Run tests with details
make test-verbose

# Run specific test
cd build/tests
./test_identity
```

---

## Best Practices

### Before Committing

1. ✅ Format code: `make format`
2. ✅ Run tests: `make test`
3. ✅ Check for warnings: `make build`
4. ✅ Review changes: `git diff`
5. ✅ Write clear commit message

### Code Review Checklist

- [ ] Code is properly formatted
- [ ] No compiler warnings
- [ ] All tests pass
- [ ] No security vulnerabilities
- [ ] Memory is properly managed
- [ ] Error handling is complete
- [ ] Comments explain complex logic
- [ ] Functions have clear purpose

### Security Guidelines

1. **Never use**: `strcpy`, `strcat`, `sprintf`, `gets`
2. **Always use**: `strncpy`, `strncat`, `snprintf`, `fgets`
3. **Check return values** of all functions
4. **Validate inputs** at API boundaries
5. **Initialize variables** before use
6. **Free allocated memory** in all paths
7. **Use const** for read-only parameters
8. **Use constant-time comparisons** for security-sensitive data

### Constant-Time Operations

For security-sensitive comparisons (credentials, tokens, cryptographic data), use the constant-time functions to prevent timing attacks:

```c
#include "internal/platform.h"

// For memory comparison (recommended for most cases)
int platform_consttime_memcmp(const void *lhs, const void *rhs, size_t len);

// For string comparison
int platform_consttime_strcmp(const char *lhs, const char *rhs);
```

**When to use constant-time:**
- Password/token verification
- Cryptographic key comparison
- Certificate/identity validation
- Any comparison where timing could leak information

**Example:**
```c
// Good: Constant-time comparison
if (platform_consttime_memcmp(user_token, expected_token, TOKEN_LEN) == 0) {
    // Authenticated
}

// Bad: Standard comparison leaks timing information
if (memcmp(user_token, expected_token, TOKEN_LEN) == 0) {
    // Timing attack possible
}
```

---

## Performance Considerations

### Hook Performance

The pre-commit hook typically takes:
- **Formatting check**: ~100ms
- **Static analysis**: ~500ms (incremental)
- **Build**: ~2-3s (clean), ~1s (incremental)
- **Tests**: ~40ms
- **Total**: ~3-5s for typical commits

### Optimization Tips

- Hook only checks **staged files**
- Build is **incremental** (only changed files)
- Tools run in **parallel** where possible
- Caching reduces **repeated analysis**

---

## Advanced Usage

### Custom Validation Rules

Edit `.clang-tidy` to add/remove checks:

```yaml
Checks: >
  -*,
  bugprone-*,
  your-custom-check-*
```

### Skipping Specific Checks

```bash
# Skip format check only
SKIP_FORMAT=1 git commit -m "message"

# Skip all checks (not recommended)
git commit --no-verify -m "message"
```

### Integration with IDE

Most IDEs support clang-format and clang-tidy:

**VS Code**:
```json
{
  "C_Cpp.clang_format_style": "file",
  "editor.formatOnSave": true
}
```

**CLion**:
- Settings → Editor → Code Style → C/C++
- Import `.clang-format`

---

## CI Static Analysis Enforcement

Static analysis is **enforced in CI** - violations will fail the build. This ensures the codebase maintains industrial-grade quality.

### Enforced Tools

| Tool | Configuration | CI Behavior |
|------|---------------|-------------|
| **clang-tidy** | `.clang-tidy` | `--warnings-as-errors=*` - any warning fails build |
| **cppcheck** | inline suppression | `--error-exitcode=1` - any error fails build |

### Running Locally (Before Push)

```bash
# Generate compile_commands.json (required for analysis)
cd build
cmake .. -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build .

# Run cppcheck
cppcheck --enable=all --suppress=missingIncludeSystem \
  --suppress=unusedFunction --error-exitcode=1 \
  --project=compile_commands.json

# Run clang-tidy (excludes non-native platform files)
find ../src ../include \( -name "*.c" -o -name "*.h" \) \
  ! -name "platform_win32.c" ! -name "platform_darwin.c" | \
  xargs clang-tidy -p . --warnings-as-errors=*
```

### Suppression Mechanism

#### When to Suppress

Suppression should be a **last resort**. Only suppress when:
1. The warning is a **false positive** (tool bug or context misunderstanding)
2. The pattern is **intentional** and documented
3. Fixing would introduce **worse problems**

#### Inline Suppression

**clang-tidy** - use `NOLINT` comments:
```c
// Suppress specific check with justification
void* ptr = malloc(size);  // NOLINT(cppcoreguidelines-no-malloc) - low-level API

// Suppress for next line
// NOLINTNEXTLINE(bugprone-suspicious-include)
#include "generated_code.c"
```

**cppcheck** - use inline suppression:
```c
// cppcheck-suppress unusedFunction
// Justification: Called only via function pointer
static void callback_handler(void) { ... }
```

#### Project-Level Suppression

Configured in `.clang-tidy`:
- `bugprone-easily-swappable-parameters` - disabled (common in C APIs)
- `readability-magic-numbers` - disabled (too noisy for constants)
- `clang-analyzer-valist.Uninitialized` - disabled (false positives with va_list)

#### Documentation Requirement

All suppressions **must** include:
1. The specific check being suppressed
2. A brief justification explaining why

```c
// Good: Clear justification
// NOLINTNEXTLINE(cert-err33-c) - fprintf return value not critical for logging
fprintf(stderr, "Debug: %s\n", msg);

// Bad: No justification
// NOLINTNEXTLINE
fprintf(stderr, "Debug: %s\n", msg);
```

---

## Summary

✅ **Pre-commit hook** enforces 7 validation steps
✅ **clang-format** ensures consistent code style
✅ **clang-tidy** catches bugs and security issues
✅ **cppcheck** provides additional static analysis
✅ **Automated tests** ensure functionality
✅ **Security scans** prevent vulnerabilities
✅ **CI enforces** static analysis (build fails on violations)

The development workflow is designed to maintain industrial-standard code quality while remaining fast and developer-friendly.
