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

# Add examples
mtls_add_example(simple_client)
mtls_add_example(simple_server)
mtls_add_example(advanced_client)
mtls_add_example(echo_server)
mtls_add_example(kill_switch_demo)
mtls_add_example(cert_reload_demo)
mtls_add_example(observability_demo)

# Observability demo needs pthread for metrics tracking
if(UNIX)
    target_link_libraries(observability_demo PRIVATE pthread)
endif()

message(STATUS "Building 7 example programs")
