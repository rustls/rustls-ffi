cmake_minimum_required(VERSION 3.15)

project(rustls-ffi)

set(CRYPTO_PROVIDER "aws-lc-rs" CACHE STRING "Crypto provider to use (aws-lc-rs or ring)")

if (NOT (CRYPTO_PROVIDER STREQUAL "aws-lc-rs" OR CRYPTO_PROVIDER STREQUAL "ring"))
    message(FATAL_ERROR "Invalid crypto provider specified: ${CRYPTO_PROVIDER}. Must be 'aws-lc-rs' or 'ring'.")
endif ()

set(CERT_COMPRESSION "false" CACHE STRING "Whether to enable brotli and zlib certificate compression support")

set(FIPS "false" CACHE STRING "Whether to enable aws-lc-rs and FIPS support")

set(CARGO_FEATURES --no-default-features)
if (CRYPTO_PROVIDER STREQUAL "aws-lc-rs")
    list(APPEND CARGO_FEATURES --features=aws-lc-rs)
elseif (CRYPTO_PROVIDER STREQUAL "ring")
    list(APPEND CARGO_FEATURES --features=ring)
endif ()

if (CERT_COMPRESSION STREQUAL "true")
    list(APPEND CARGO_FEATURES --features=cert_compression)
endif ()

# See https://docs.rs/rustls/latest/rustls/manual/_06_fips/index.html
if (FIPS STREQUAL "true")
    list(APPEND CARGO_FEATURES --features=fips)
endif ()

add_subdirectory(tests)

include(ExternalProject)
set_directory_properties(PROPERTIES EP_PREFIX ${CMAKE_BINARY_DIR}/rust)

ExternalProject_Add(
        rustls-ffi
        DOWNLOAD_COMMAND ""
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ""
        COMMAND cargo build --locked ${CARGO_FEATURES} "$<IF:$<CONFIG:Release>,--release,-->"
        # Rely on cargo checking timestamps, rather than tell CMake where every
        # output is.
        BUILD_ALWAYS true
        INSTALL_COMMAND ""
        # Run cargo test with --quiet because msbuild will treat the presence
        # of "error" in stdout as an error, and we have some test functions that
        # end in "_error". Quiet mode suppresses test names, so this is a
        # sufficient workaround.
        TEST_COMMAND cargo test --locked ${CARGO_FEATURES} "$<IF:$<CONFIG:Release>,--release,-->" --quiet
)
