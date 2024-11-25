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
