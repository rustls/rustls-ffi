load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

#
# Rust
#
http_archive(
    name = "rules_rust",
#    sha256 = "e6d835ee673f388aa5b62dc23d82db8fc76497e93fa47d8a4afe97abaf09b10d",
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
    sha256 = "c664e258ea79e7e4ec2f2b57bca8b1c37f11c8d5748e02b8224810da969eb681",
    strip_prefix = "cargo-raze-0.11.0",
    url = "https://github.com/google/cargo-raze/archive/v0.11.0.tar.gz",
)

load("@cargo_raze//:repositories.bzl", "cargo_raze_repositories")

cargo_raze_repositories()

load("@cargo_raze//:transitive_deps.bzl", "cargo_raze_transitive_deps")

cargo_raze_transitive_deps()