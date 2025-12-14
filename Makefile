# Makefile for mTLS library development tasks
#
# This Makefile provides convenience targets for common development tasks
#

.PHONY: help build clean test format check install-hooks

# Default target
help:
	@echo "mTLS Library - Development Tasks"
	@echo "================================="
	@echo ""
	@echo "Build targets:"
	@echo "  make build          - Build the library"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make rebuild        - Clean and build"
	@echo ""
	@echo "Testing targets:"
	@echo "  make test           - Run all tests"
	@echo "  make test-verbose   - Run tests with verbose output"
	@echo ""
	@echo "Code quality targets:"
	@echo "  make format         - Format all C/H files with clang-format"
	@echo "  make check          - Run static analysis (clang-tidy + cppcheck)"
	@echo "  make lint           - Run all linters"
	@echo ""
	@echo "Git hooks:"
	@echo "  make install-hooks  - Install pre-commit hooks"
	@echo ""
	@echo "Documentation:"
	@echo "  make docs           - Generate documentation (if Doxygen available)"
	@echo ""

# Build targets
build:
	@mkdir -p build
	@cd build && cmake .. && make -j$$(nproc)

clean:
	@rm -rf build
	@find . -name "*.o" -delete
	@find . -name "*.a" -delete

rebuild: clean build

# Testing targets
test: build
	@cd build && ctest --output-on-failure

test-verbose: build
	@cd build && ctest -V

# Code formatting
format:
	@echo "Formatting C/H files with clang-format..."
	@find src include tests -name "*.c" -o -name "*.h" | xargs clang-format -i --style=file
	@echo "✓ Formatting complete"

# Static analysis
check-tidy:
	@echo "Running clang-tidy..."
	@find src -name "*.c" | xargs -I {} clang-tidy {} -p build -- -Iinclude -Isrc

check-cppcheck:
	@echo "Running cppcheck..."
	@cppcheck --enable=warning,style,performance,portability \
	          --error-exitcode=1 \
	          --suppress=missingIncludeSystem \
	          -Iinclude \
	          src

check: check-cppcheck check-tidy
	@echo "✓ Static analysis complete"

lint: format check
	@echo "✓ All linting complete"

# Git hooks
install-hooks:
	@bash scripts/install-hooks.sh

# Documentation (if Doxygen is available)
docs:
	@if command -v doxygen >/dev/null 2>&1; then \
		doxygen Doxyfile 2>/dev/null || echo "Doxyfile not found"; \
	else \
		echo "Doxygen not installed. Install: sudo apt-get install doxygen"; \
	fi

# Security scan
scan-build: clean
	@echo "Running scan-build..."
	@mkdir -p build
	@cd build && scan-build cmake .. && scan-build make

# Coverage (if lcov is available)
coverage:
	@if command -v lcov >/dev/null 2>&1; then \
		mkdir -p build; \
		cd build && cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_COVERAGE=ON .. && make && make test; \
		lcov --capture --directory . --output-file coverage.info; \
		lcov --remove coverage.info '/usr/*' --output-file coverage.info; \
		lcov --list coverage.info; \
	else \
		echo "lcov not installed. Install: sudo apt-get install lcov"; \
	fi

# Show current status
status:
	@echo "Build status:"
	@if [ -f build/libmtls.a ]; then \
		echo "  ✓ Library built"; \
		ls -lh build/libmtls.a; \
	else \
		echo "  ✗ Library not built"; \
	fi
	@echo ""
	@echo "Git hooks:"
	@if [ -x .git/hooks/pre-commit ]; then \
		echo "  ✓ Pre-commit hook installed"; \
	else \
		echo "  ✗ Pre-commit hook not installed"; \
		echo "    Run: make install-hooks"; \
	fi
	@echo ""
	@echo "Tests:"
	@cd build && ctest --show-only 2>/dev/null | grep "Test #" || echo "  No tests configured"
