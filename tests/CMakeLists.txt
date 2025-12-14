# MTLS Tests

# Test helper function
function(mtls_add_test name)
    add_executable(${name} ${name}.c)
    target_link_libraries(${name} PRIVATE mtls ${BORINGSSL_LIBRARIES})
    target_include_directories(${name} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${BORINGSSL_INCLUDE_DIR}
    )
    add_test(NAME ${name} COMMAND ${name})
endfunction()

# Add tests here (examples)
# mtls_add_test(test_error)
# mtls_add_test(test_config)
# mtls_add_test(test_context)
# mtls_add_test(test_connection)
# mtls_add_test(test_identity)

message(STATUS "Tests will be added in future phases")
