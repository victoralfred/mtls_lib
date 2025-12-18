cmake_minimum_required(VERSION 3.16)
project(mtls-jni C)

# Find JNI
find_package(JNI REQUIRED)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(${JNI_INCLUDE_DIRS})
include_directories(${CMAKE_SOURCE_DIR}/../../include)
include_directories(${OPENSSL_INCLUDE_DIR})

# Source files
set(JNI_SOURCES
    src/main/c/mtls_jni.c
)

# Create shared library
add_library(mtls_jni SHARED ${JNI_SOURCES})

# Link against the mTLS C library
target_link_libraries(mtls_jni
    ${CMAKE_SOURCE_DIR}/../../build/libmtls.a
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
)

# Output directory
# - Default: checked-in resources folder (used by docs/examples)
# - Maven: set -DMTLS_JNI_OUTPUT_DIR=... to drop the built library directly into target/classes/natives
if(DEFINED MTLS_JNI_OUTPUT_DIR AND NOT "${MTLS_JNI_OUTPUT_DIR}" STREQUAL "")
    set(MTLS_JNI_OUTDIR "${MTLS_JNI_OUTPUT_DIR}")
else()
    set(MTLS_JNI_OUTDIR "${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/natives")
endif()

file(MAKE_DIRECTORY "${MTLS_JNI_OUTDIR}")

set_target_properties(mtls_jni PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${MTLS_JNI_OUTDIR}"
    RUNTIME_OUTPUT_DIRECTORY "${MTLS_JNI_OUTDIR}"
    ARCHIVE_OUTPUT_DIRECTORY "${MTLS_JNI_OUTDIR}"
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
