# Fuzzing targets for mTLS library
# Build: cmake -DMTLS_ENABLE_FUZZING=ON -DCMAKE_C_COMPILER=clang ..

if(NOT MTLS_ENABLE_FUZZING)
    return()
endif()

message(STATUS "Configuring fuzzing targets")

# Shared fuzzing utilities
add_library(fuzz_common STATIC fuzz_common.c)
target_include_directories(fuzz_common PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
target_link_libraries(fuzz_common PRIVATE mtls)

if(BORINGSSL_INCLUDE_DIR)
    target_include_directories(fuzz_common PRIVATE ${BORINGSSL_INCLUDE_DIR})
endif()

# Macro to define fuzzing targets
function(add_fuzz_target name)
    add_executable(${name} ${name}.c)

    # Apply fuzzing-specific compile and link flags
    target_compile_options(${name} PRIVATE -fsanitize=fuzzer,address -g -O1)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer,address)

    target_include_directories(${name} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )

    if(BORINGSSL_INCLUDE_DIR)
        target_include_directories(${name} PRIVATE ${BORINGSSL_INCLUDE_DIR})
    endif()

    target_link_libraries(${name} PRIVATE mtls fuzz_common)

    if(BORINGSSL_LIBRARIES)
        target_link_libraries(${name} PRIVATE ${BORINGSSL_LIBRARIES})
    endif()

    # Copy corpus directory if it exists
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/corpus/${name})
        add_custom_command(TARGET ${name} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_CURRENT_SOURCE_DIR}/corpus/${name}
            ${CMAKE_CURRENT_BINARY_DIR}/corpus/${name}
            COMMENT "Copying corpus for ${name}"
        )
    endif()
endfunction()

# Define all fuzzing targets
add_fuzz_target(fuzz_san_validation)
add_fuzz_target(fuzz_pem_parsing)
add_fuzz_target(fuzz_certificate_validation)
add_fuzz_target(fuzz_address_parsing)

# Custom target to list all fuzzers
add_custom_target(list-fuzzers
    COMMAND ${CMAKE_COMMAND} -E echo "Available fuzzing targets:"
    COMMAND ${CMAKE_COMMAND} -E echo "  - fuzz_san_validation"
    COMMAND ${CMAKE_COMMAND} -E echo "  - fuzz_pem_parsing"
    COMMAND ${CMAKE_COMMAND} -E echo "  - fuzz_certificate_validation"
    COMMAND ${CMAKE_COMMAND} -E echo "  - fuzz_address_parsing"
    COMMAND ${CMAKE_COMMAND} -E echo ""
    COMMAND ${CMAKE_COMMAND} -E echo "Run with: ./tests/fuzz/<target> corpus/"
)
