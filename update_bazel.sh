#!/usr/bin/env bash

cargo generate-lockfile && \
cargo vendor --versioned-dirs --locked cargo/vendor && \
bazel run @cargo_raze//:raze -- --manifest-path=$(realpath Cargo.toml)
cat "cbindgen_rules.txt" >> "BUILD.bazel" 
