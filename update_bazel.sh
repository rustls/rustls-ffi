#!/usr/bin/env bash

cargo generate-lockfile && \
cargo vendor --versioned-dirs --locked cargo/vendor && \
bazel run @cargo_raze//:raze -- --manifest-path=$(realpath Cargo.toml)
cat >> "BUILD.bazel" <<- EOM

genrule(
    name = "cargo_metadata",
    srcs = [
        "Cargo.toml",
        "Cargo.lock",
        "//src:rust_srcs",
    ],
    outs = ["cargo_metadata.json"],
    cmd = "RUSTC=\$(location //:rustc) \$(location //:cargo) metadata --offline > \$(location cargo_metadata.json)",
    tools = [
        "//:cargo",
        "//:rustc",
    ]
)

genrule(
    name = "crustls_h",
    srcs = [
        "//:cargo_metadata",
        "cbindgen.toml",
        "Cargo.toml",
        "Cargo.lock",
    ],
    outs = ["crustls.h"],
    cmd = "cargo=\$(location //:cargo) \$(location //:cargo_bin_cbindgen) --metadata \$(location //:cargo_metadata) --lang C > \$(location crustls.h)",
    tools = [
        "//:cargo_bin_cbindgen",
        "//:cargo",
    ],
)

alias(
    name = "cargo",
    actual = select({
        "@rules_rust//rust/platform:aarch64-apple-darwin": "@rust_darwin_aarch64//:cargo",
        "@rules_rust//rust/platform:aarch64-unknown-linux-gnu": "@rust_linux_aarch64//:cargo",
        "@rules_rust//rust/platform:x86_64-apple-darwin": "@rust_darwin_x86_64//:cargo",
        "@rules_rust//rust/platform:x86_64-pc-windows-msvc": "@rust_windows_x86_64//:cargo",
        "@rules_rust//rust/platform:x86_64-unknown-linux-gnu": "@rust_linux_x86_64//:cargo",
    }),
)

alias(
    name = "rustc",
    actual = select({
        "@rules_rust//rust/platform:aarch64-apple-darwin": "@rust_darwin_aarch64//:rustc",
        "@rules_rust//rust/platform:aarch64-unknown-linux-gnu": "@rust_linux_aarch64//:rustc",
        "@rules_rust//rust/platform:x86_64-apple-darwin": "@rust_darwin_x86_64//:rustc",
        "@rules_rust//rust/platform:x86_64-pc-windows-msvc": "@rust_windows_x86_64//:rustc",
        "@rules_rust//rust/platform:x86_64-unknown-linux-gnu": "@rust_linux_x86_64//:rustc",
    }),
)
EOM
