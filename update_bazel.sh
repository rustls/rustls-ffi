#!/usr/bin/env bash

cargo generate-lockfile && \
bazel run @cargo_raze//:raze -- --manifest-path=$(realpath Cargo.toml) && \
cat "cbindgen_rules.txt" >> "BUILD.bazel" 
