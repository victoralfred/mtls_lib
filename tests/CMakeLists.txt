# MTLS Tests

# Test helper function
function(mtls_add_test name)
    add_executable(${name} ${name}.c)
    target_link_libraries(${name} PRIVATE mtls)

    # Link the same SSL libraries as the main library
    if(BORINGSSL_LIBRARIES)
        target_link_libraries(${name} PRIVATE ${BORINGSSL_LIBRARIES})
    endif()

    # Link pthread for thread tests (required for atomic operations)
    if(UNIX)
        target_link_libraries(${name} PRIVATE pthread)
    endif()

    target_include_directories(${name} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )

    if(BORINGSSL_INCLUDE_DIR)
        target_include_directories(${name} PRIVATE ${BORINGSSL_INCLUDE_DIR})
    endif()

    # Suppress MSVC security warnings for test code
    if(MSVC)
        target_compile_definitions(${name} PRIVATE _CRT_SECURE_NO_WARNINGS)
    endif()

    add_test(NAME ${name} COMMAND ${name})
endfunction()

# Security fixes tests (pthread-dependent, Unix only)
if(UNIX)
    mtls_add_test(test_security_fixes)
endif()

# Identity verification tests
mtls_add_test(test_identity)
mtls_add_test(test_san_validation)

# Phase 4 features tests (constant-time comparison, certificate reload)
mtls_add_test(test_phase4_features)

# Fuzz test for oversized SAN handling
mtls_add_test(fuzz_oversized_sans)

# Memory safety and bug fix validation tests
mtls_add_test(test_memory_safety)

# Certificate reload tests
mtls_add_test(test_cert_reload)

# Observability layer tests (pthread-dependent, Unix only)
if(UNIX)
    mtls_add_test(test_observability)
endif()

# Add more tests here (examples)
# mtls_add_test(test_error)
# mtls_add_test(test_config)
# mtls_add_test(test_context)
# mtls_add_test(test_connection)

# Fuzzing targets (libFuzzer)
if(MTLS_ENABLE_FUZZING)
    add_subdirectory(fuzz)
endif()
