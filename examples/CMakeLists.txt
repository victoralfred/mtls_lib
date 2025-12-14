# MTLS Examples

# Example helper function
function(mtls_add_example name)
    add_executable(${name} ${name}.c)
    target_link_libraries(${name} PRIVATE mtls ${BORINGSSL_LIBRARIES})
    target_include_directories(${name} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${BORINGSSL_INCLUDE_DIR}
    )
endfunction()

# Add examples here (to be implemented)
# mtls_add_example(simple_client)
# mtls_add_example(simple_server)
# mtls_add_example(echo_server)
# mtls_add_example(identity_verification)

message(STATUS "Examples will be added in future phases")
