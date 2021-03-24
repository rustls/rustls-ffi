load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

#
# Rust
#
http_archive(
    name = "rules_rust",
    sha256 = "419eb5b01c9bfac786b686c90fe1d732080cd8dad53ba1ffa93c0b0828d20b57",
    strip_prefix = "rules_rust-920256900c367357bf4dae5719b8ebf210e91a0f",
    urls = [
        # Master branch as of 2021-03-23
        "https://github.com/bazelbuild/rules_rust/archive/920256900c367357bf4dae5719b8ebf210e91a0f.tar.gz",
    ],
)

load("@rules_rust//rust:repositories.bzl", "rust_repositories")

rust_repositories(edition = "2018")

#
# BuildBuddy
#
http_archive(
    name = "io_buildbuddy_buildbuddy_toolchain",
    sha256 = "9055a3e6f45773cd61931eba7b7cf35d6477ab6ad8fb2f18bf9815271fc682fe",
    strip_prefix = "buildbuddy-toolchain-52aa5d2cc6c9ba7ee4063de35987be7d1b75f8e2",
    urls = ["https://github.com/buildbuddy-io/buildbuddy-toolchain/archive/52aa5d2cc6c9ba7ee4063de35987be7d1b75f8e2.tar.gz"],
)

load("@io_buildbuddy_buildbuddy_toolchain//:deps.bzl", "buildbuddy_deps")

buildbuddy_deps()

load("@io_buildbuddy_buildbuddy_toolchain//:rules.bzl", "buildbuddy")

buildbuddy(name = "buildbuddy_toolchain")

#
# Cargo Raze
#
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "cargo_raze",
    #sha256 = "d2421524482a2912d8e07e3f7d6341f1cf2bcc4663c0d36d75b2b869e1756780",
    strip_prefix = "cargo-raze-15487f803857089cd677c1f4faa83693c02cf4b7",
    url = "https://github.com/grafica/cargo-raze/archive/15487f803857089cd677c1f4faa83693c02cf4b7.tar.gz",
)

load("@cargo_raze//:repositories.bzl", "cargo_raze_repositories")

cargo_raze_repositories()

load("@cargo_raze//:transitive_deps.bzl", "cargo_raze_transitive_deps")

cargo_raze_transitive_deps()