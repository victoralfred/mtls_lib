# Java Bindings Testing Guide

This document describes how to run tests for the mTLS Java bindings.

## Test Structure

The test suite is organized into two categories:

### Unit Tests

Pure Java tests that don't require native library loading:

- **ConfigTest** - Tests for `Config` class and builder pattern
- **MtlsExceptionTest** - Tests for exception handling and error categorization
- **PeerIdentityTest** - Tests for peer identity and certificate information
- **ConnectionTest** - Tests for `Connection.State` enum

### Integration Tests

Tests that require the native JNI library to be compiled and loaded:

- **IntegrationTest** - Tests native library loading and basic API calls

## Running Tests

### Run All Unit Tests

```bash
cd bindings/java
mvn test
```

This runs all unit tests. Integration tests are skipped by default.

### Run Specific Test Class

```bash
mvn test -Dtest=ConfigTest
mvn test -Dtest=MtlsExceptionTest
```

### Run Specific Test Method

```bash
mvn test -Dtest=ConfigTest#testBuilderWithFiles
```

### Run Integration Tests

Integration tests require the native library to be built first:

```bash
# Build the mTLS C library
cd ../..
mkdir -p build && cd build
cmake ..
make

# Build the JNI library
cd ../bindings/java
mkdir -p build && cd build
cmake ..
make
cd ..

# Run integration tests
mvn test -Dmtls.native.test=true
```

### Run All Tests (Unit + Integration)

```bash
# Build everything first
./build-all.sh  # (if available)

# Run all tests
mvn test -Dmtls.native.test=true
```

## Test Reports

Maven Surefire generates test reports in:

```
target/surefire-reports/
```

### View HTML Reports

```bash
mvn surefire-report:report
open target/site/surefire-report.html
```

## Test Coverage

Generate test coverage report with JaCoCo:

```bash
mvn clean test jacoco:report
open target/site/jacoco/index.html
```

## Continuous Integration

The GitHub Actions workflow (`.github/workflows/java-bindings.yml`) automatically:

1. Builds the C library
2. Compiles the JNI library
3. Runs all unit tests
4. Generates test reports
5. Uploads artifacts

## Test Statistics

Current test coverage:

| Class | Unit Tests | Integration Tests | Total |
|-------|------------|------------------|-------|
| Config | 13 | 0 | 13 |
| MtlsException | 12 | 0 | 12 |
| PeerIdentity | 15 | 0 | 15 |
| Connection | 7 | 0 | 7 |
| Integration | 0 | 5 | 5 |
| **Total** | **47** | **5** | **52** |

## Writing New Tests

### Unit Test Template

```java
package com.mtls;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

class MyClassTest {

    @Test
    @DisplayName("Description of what this test does")
    void testSomething() {
        // Arrange
        MyClass obj = new MyClass();

        // Act
        boolean result = obj.doSomething();

        // Assert
        assertTrue(result);
    }
}
```

### Integration Test Template

```java
package com.mtls;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

@EnabledIfSystemProperty(named = "mtls.native.test", matches = "true")
class MyIntegrationTest {

    @Test
    void testWithNativeLibrary() {
        assumeNativeLibraryAvailable();

        // Test that requires native library...
    }

    private void assumeNativeLibraryAvailable() {
        try {
            System.loadLibrary("mtls_jni");
        } catch (UnsatisfiedLinkError e) {
            assumeTrue(false, "Native library not available");
        }
    }
}
```

## Debugging Tests

### Enable Verbose Output

```bash
mvn test -X
```

### Run Tests in Debug Mode

```bash
mvn test -Dmaven.surefire.debug
```

Then attach your IDE debugger to port 5005.

### Print Test Output to Console

```bash
mvn test -Dsurefire.printSummary=true
```

## Common Issues

### Native Library Not Found

**Error**: `UnsatisfiedLinkError: no mtls_jni in java.library.path`

**Solution**: Build the JNI library first:

```bash
cd bindings/java/build
cmake ..
make
```

### OpenSSL Not Found

**Error**: `undefined symbol: SSL_CTX_new`

**Solution**: Ensure OpenSSL is installed and linked:

```bash
# Ubuntu
sudo apt-get install libssl-dev

# macOS
brew install openssl@3
export OPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
```

### Tests Fail on CI

Check the GitHub Actions workflow logs:

1. Go to your repository on GitHub
2. Click "Actions" tab
3. Select the "Java Bindings CI" workflow
4. Review the test results

## Best Practices

1. **Write unit tests first** - Test Java logic without native dependencies
2. **Use descriptive names** - Test method names should describe what they test
3. **One assertion per test** - Keep tests focused and simple
4. **Use @DisplayName** - Provide human-readable test descriptions
5. **Test edge cases** - Null values, empty strings, boundary conditions
6. **Clean up resources** - Use try-with-resources or @AfterEach
7. **Mock when possible** - Reduce dependencies on native code

## Resources

- [JUnit 5 User Guide](https://junit.org/junit5/docs/current/user-guide/)
- [Maven Surefire Plugin](https://maven.apache.org/surefire/maven-surefire-plugin/)
- [JaCoCo Documentation](https://www.jacoco.org/jacoco/trunk/doc/)
