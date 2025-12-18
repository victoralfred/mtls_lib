cmake_minimum_required(VERSION 3.16)
project(mtls-jni C)

# Find JNI
find_package(JNI REQUIRED)

# Include directories
include_directories(${JNI_INCLUDE_DIRS})
include_directories(${CMAKE_SOURCE_DIR}/../../include)

# Source files
set(JNI_SOURCES
    src/main/c/mtls_jni.c
)

# Create shared library
add_library(mtls_jni SHARED ${JNI_SOURCES})

# Link against the mTLS C library
target_link_libraries(mtls_jni
    ${CMAKE_SOURCE_DIR}/../../build/libmtls.a  # Adjust path as needed
    ${OPENSSL_LIBRARIES}
)

# Set output directory
set_target_properties(mtls_jni PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/natives
)

# Platform-specific library name
if(APPLE)
    set_target_properties(mtls_jni PROPERTIES
        SUFFIX ".dylib"
        PREFIX "lib"
    )
elseif(UNIX)
    set_target_properties(mtls_jni PROPERTIES
        SUFFIX ".so"
        PREFIX "lib"
    )
elseif(WIN32)
    set_target_properties(mtls_jni PROPERTIES
        SUFFIX ".dll"
        PREFIX ""
    )
endif()
