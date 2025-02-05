set(CRYPTO_PROVIDER
    "aws-lc-rs"
    CACHE STRING
    "Crypto provider to use (aws-lc-rs or ring)"
)

if(
    NOT (CRYPTO_PROVIDER STREQUAL "aws-lc-rs" OR CRYPTO_PROVIDER STREQUAL "ring")
)
    message(
        FATAL_ERROR
        "Invalid crypto provider specified: ${CRYPTO_PROVIDER}. Must be 'aws-lc-rs' or 'ring'."
    )
endif()

option(
    CERT_COMPRESSION
    "Whether to enable brotli and zlib certificate compression support"
)

option(FIPS "Whether to enable aws-lc-rs and FIPS support")

option(
    PREFER_POST_QUANTUM
    "Whether to enable aws-lc-rs and prefer post-quantum key exchange support"
)

option(DYN_LINK "Use dynamic linking for rustls library" OFF)

if(DYN_LINK AND FIPS AND (APPLE OR WIN32))
    message(
        FATAL_ERROR
        "Dynamic linking is not supported with FIPS on MacOS or Windows"
    )
endif()

set(CARGO_FEATURES --no-default-features)
if(CRYPTO_PROVIDER STREQUAL "aws-lc-rs")
    list(APPEND CARGO_FEATURES --features=aws-lc-rs)
elseif(CRYPTO_PROVIDER STREQUAL "ring")
    list(APPEND CARGO_FEATURES --features=ring)
endif()

if(CERT_COMPRESSION)
    list(APPEND CARGO_FEATURES --features=cert_compression)
endif()

# See https://docs.rs/rustls/latest/rustls/manual/_06_fips/index.html
if(FIPS)
    list(APPEND CARGO_FEATURES --features=fips)
endif()

if(PREFER_POST_QUANTUM)
    list(APPEND CARGO_FEATURES --features=prefer-post-quantum)
endif()

# By default w/ Makefile or Ninja generators (e.g. Linux/MacOS CLI)
# the `CMAKE_BUILD_TYPE` is "" when using the C/C++ project tooling.
#
# This is annoying to handle in places where we want to decide on
# release or debug so we conditionally set our own default.
#
# We don't do this if the user has already set a `CMAKE_BUILD_TYPE`
# explicitly. We also check `CMAKE_CONFIGURATION_TYPES` to exclude
# "multi-config" generators like Visual Studio that use --config and
# ignore `CMAKE_BUILD_TYPE`.
#
# Isn't cmake fun!?
set(default_build_type "Release")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Using default build type: ${default_build_type}")
    set(CMAKE_BUILD_TYPE
        "${default_build_type}"
        CACHE STRING
        "Choose the type of build."
        FORCE
    )
endif()
