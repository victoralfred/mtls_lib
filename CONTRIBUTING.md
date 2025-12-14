# Contributing to mTLS Library

Thank you for your interest in contributing to the mTLS Library project!

## Development Setup

### Prerequisites

- C11-compatible compiler (GCC 7+, Clang 10+, or MSVC 2019+)
- CMake 3.16 or later
- OpenSSL 1.1+ or BoringSSL
- Git

### Building

```bash
# Clone the repository
git clone https://github.com/victoralfred/mtls_lib.git
cd mtls_lib

# Option 1: Use system OpenSSL
mkdir build && cd build
cmake ..
make

# Option 2: Use BoringSSL (recommended)
git submodule add https://boringssl.googlesource.com/boringssl third_party/boringssl
git submodule update --init --recursive
mkdir build && cd build
cmake ..
make
```

### Running Tests

```bash
cd build
ctest --output-on-failure
```

## Project Structure

```
mtls_lib/
├── include/mtls/          # Public API headers
├── src/                   # Implementation files
│   └── internal/          # Platform-specific code
├── tests/                 # Unit and integration tests
├── examples/              # Example programs
├── docs/                  # Documentation
├── bindings/              # Language bindings (Go, Rust, Java)
├── third_party/           # External dependencies
└── cmake/                 # CMake modules
```

## Coding Standards

### C Code Style

- **Standard**: C11
- **Indentation**: 4 spaces (no tabs)
- **Line length**: 100 characters maximum
- **Naming conventions**:
  - Functions: `mtls_function_name()`
  - Types: `mtls_type_name`
  - Constants: `MTLS_CONSTANT_NAME`
  - Private functions: `static` with descriptive names

### Documentation

- All public API functions must have comments
- Use Doxygen-style comments for API documentation
- Include usage examples for complex functions

### Example

```c
/**
 * Connect to a remote server with mTLS
 *
 * @param ctx Context created with mtls_ctx_create()
 * @param addr Address in format "host:port"
 * @param err Error structure to populate on failure
 * @return Connection handle on success, NULL on failure
 */
MTLS_API mtls_conn* mtls_connect(mtls_ctx* ctx, const char* addr, mtls_err* err);
```

## Security Guidelines

1. **Memory Safety**:
   - Always validate pointer arguments
   - Use `platform_secure_zero()` for sensitive data
   - Check buffer bounds

2. **Error Handling**:
   - Never ignore errors from system calls
   - Always populate error structures
   - Use appropriate error codes

3. **Fail-Closed**:
   - Security decisions must fail closed
   - Validate all inputs at API boundaries
   - Check kill-switch before connections

4. **Constant-Time Operations**:
   - Use constant-time comparison for secrets
   - Avoid timing-dependent branches on sensitive data

## Contribution Workflow

1. **Fork & Branch**:
   ```bash
   git checkout -b feature/my-feature
   ```

2. **Make Changes**:
   - Follow coding standards
   - Add tests for new features
   - Update documentation

3. **Test**:
   ```bash
   mkdir build && cd build
   cmake -DMTLS_ENABLE_ASAN=ON -DMTLS_ENABLE_UBSAN=ON ..
   make
   ctest
   ```

4. **Commit**:
   - Write clear commit messages
   - Reference issues if applicable
   - Sign commits if required

5. **Submit Pull Request**:
   - Describe what changed and why
   - Include test results
   - Wait for review

## Commit Message Format

```
<type>: <short summary>

<detailed description>

Fixes: #123
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `test`: Adding tests
- `refactor`: Code refactoring
- `perf`: Performance improvement
- `security`: Security fix

## Code Review Process

1. All submissions require review
2. At least one maintainer approval required
3. All tests must pass
4. Security-critical changes require additional review

## Testing Requirements

- Unit tests for all new functions
- Integration tests for API changes
- Platform tests (Linux, macOS, Windows)
- Memory leak tests (Valgrind/sanitizers)

## Documentation

- Update README.md for user-facing changes
- Update API documentation in headers
- Add examples for new features
- Update IMPLEMENTATION_STATUS.md for phase completions

## Questions?

- Open an issue for questions
- Join discussions in pull requests
- Check existing issues and documentation

## License

By contributing, you agree that your contributions will be licensed under the dual MIT/Apache 2.0 license.
