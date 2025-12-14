cmake_minimum_required(VERSION 3.16)
project(mtls VERSION 0.1.0 LANGUAGES C)

# Require out-of-source builds
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "In-source builds are not allowed. Please use a separate build directory.")
endif()

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Build type defaults to Release
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Options
option(MTLS_BUILD_TESTS "Build tests" ON)
option(MTLS_BUILD_EXAMPLES "Build examples" ON)
option(MTLS_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(MTLS_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)

# Platform detection
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(MTLS_PLATFORM_LINUX ON)
    add_compile_definitions(MTLS_PLATFORM_LINUX)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(MTLS_PLATFORM_DARWIN ON)
    add_compile_definitions(MTLS_PLATFORM_DARWIN)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(MTLS_PLATFORM_WINDOWS ON)
    add_compile_definitions(MTLS_PLATFORM_WINDOWS)
else()
    message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}")
endif()

# Compiler-specific flags
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    # Security hardening flags
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Werror=implicit-function-declaration
        -Werror=return-type
        -Wformat=2
        -Wformat-security
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
    )

    # Position Independent Code for shared libraries
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)

    # Linker flags for security
    if(NOT MTLS_PLATFORM_DARWIN)
        add_link_options(
            -Wl,-z,relro
            -Wl,-z,now
            -Wl,-z,noexecstack
        )
    endif()

    # Sanitizers (debug builds only)
    if(MTLS_ENABLE_ASAN)
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    endif()

    if(MTLS_ENABLE_UBSAN)
        add_compile_options(-fsanitize=undefined)
        add_link_options(-fsanitize=undefined)
    endif()

elseif(MSVC)
    # Enable C11 standard for atomic support
    # MSVC requires /std:c11 flag to enable C11 atomics
    add_compile_options(
        /std:c11
        /W4
        /WX
        /GS
    )
    
    # Linker flags for security
    add_link_options(
        /DYNAMICBASE
        /NXCOMPAT
    )
endif()

# Find or build BoringSSL
if(EXISTS "${CMAKE_SOURCE_DIR}/third_party/boringssl/CMakeLists.txt")
    message(STATUS "Building BoringSSL from submodule")
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    add_subdirectory(third_party/boringssl EXCLUDE_FROM_ALL)
    set(BORINGSSL_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/third_party/boringssl/include")
    set(BORINGSSL_LIBRARIES ssl crypto)
else()
    message(STATUS "Looking for system BoringSSL or OpenSSL")
    find_package(OpenSSL REQUIRED)
    set(BORINGSSL_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR})
    set(BORINGSSL_LIBRARIES ${OPENSSL_LIBRARIES})
endif()

# Export compile commands for IDEs
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Source files
set(MTLS_SOURCES
    src/mtls_error.c
    src/mtls_ctx.c
    src/mtls_conn.c
    src/mtls_listener.c
    src/mtls_tls.c
    src/mtls_identity.c
)

# Platform-specific sources
if(MTLS_PLATFORM_LINUX)
    list(APPEND MTLS_SOURCES src/internal/platform_linux.c)
elseif(MTLS_PLATFORM_DARWIN)
    list(APPEND MTLS_SOURCES src/internal/platform_darwin.c)
elseif(MTLS_PLATFORM_WINDOWS)
    list(APPEND MTLS_SOURCES src/internal/platform_win32.c)
endif()

# Create the library
add_library(mtls ${MTLS_SOURCES})

# Include directories
target_include_directories(mtls
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${BORINGSSL_INCLUDE_DIR}
)

# Link dependencies
target_link_libraries(mtls
    PRIVATE
        ${BORINGSSL_LIBRARIES}
)

# Platform-specific link libraries
if(MTLS_PLATFORM_LINUX)
    target_link_libraries(mtls PRIVATE pthread)
elseif(MTLS_PLATFORM_WINDOWS)
    target_link_libraries(mtls PRIVATE ws2_32 crypt32)
endif()

# Compiler features
target_compile_features(mtls PUBLIC c_std_11)

# Symbol visibility
set_target_properties(mtls PROPERTIES
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# Define export macro
target_compile_definitions(mtls PRIVATE MTLS_BUILDING_LIB)

# Add subdirectories
if(MTLS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(MTLS_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Installation
include(GNUInstallDirs)

install(TARGETS mtls
    EXPORT mtlsTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY include/mtls
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Package configuration
include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/mtlsConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/mtlsConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/mtlsConfig.cmake"
    @ONLY
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/mtlsConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/mtlsConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/mtls
)

install(EXPORT mtlsTargets
    FILE mtlsTargets.cmake
    NAMESPACE mtls::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/mtls
)

# Summary
message(STATUS "")
message(STATUS "=== MTLS Library Configuration ===")
message(STATUS "Version:        ${PROJECT_VERSION}")
message(STATUS "Platform:       ${CMAKE_SYSTEM_NAME}")
message(STATUS "Build type:     ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler:     ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Build tests:    ${MTLS_BUILD_TESTS}")
message(STATUS "Build examples: ${MTLS_BUILD_EXAMPLES}")
message(STATUS "ASAN enabled:   ${MTLS_ENABLE_ASAN}")
message(STATUS "UBSAN enabled:  ${MTLS_ENABLE_UBSAN}")
message(STATUS "")
