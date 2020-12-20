# C Rustls

This crate contains C bindings for the [rustls](https://docs.rs/rustls) TLS
library. It also contains a small demo C program that uses those bindings
to make an HTTPS request.

# Build

You'll need to [install the Rust toolchain](https://rustup.rs/) and a C
compiler (gcc and clang should both work). Once you've got the Rust toolchain
installed, run `cargo install cbindgen`. Then, to build in debug mode:

    make

To install:

    make install

To build and install in optimized mode:

    make PROFILE=release install
