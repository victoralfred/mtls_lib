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
    )
    
    if(BORINGSSL_INCLUDE_DIR)
        target_include_directories(${name} PRIVATE ${BORINGSSL_INCLUDE_DIR})
    endif()
    
    add_test(NAME ${name} COMMAND ${name})
endfunction()

# Security fixes tests
mtls_add_test(test_security_fixes)

# Add more tests here (examples)
# mtls_add_test(test_error)
# mtls_add_test(test_config)
# mtls_add_test(test_context)
# mtls_add_test(test_connection)
# mtls_add_test(test_identity)
