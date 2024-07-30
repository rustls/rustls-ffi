use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use toml::Table;

use rustls_ffi::rustls_version;

/// Test that the output of `rustls_version()` matches what we expect based on Cargo.toml state.
///
/// In particular this ensures that the Rustls version reported in the rustls-ffi version string
/// matches the version of the Rustls dependency that rustls-ffi was built with.
///
/// If this test starts to fail, you probably forgot to update `RUSTLS_CRATE_VERSION` in
/// `build.rs`.
#[cfg_attr(miri, ignore)] // Requires file I/O
#[test]
fn rustls_version_match() {
    // Parse Cargo.toml as a generic TOML Table.
    let mut metadata_file =
        File::open(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("failed to open Cargo.toml");
    let mut metadata_content = String::new();
    metadata_file
        .read_to_string(&mut metadata_content)
        .expect("failed to read Cargo.toml");
    let metadata = metadata_content.parse::<Table>().unwrap();

    // Find the crate version specified in Cargo.toml
    let package_metadata = metadata["package"]
        .as_table()
        .expect("missing package metadata");
    let crate_version = package_metadata["version"]
        .as_str()
        .expect("missing crate version");

    let rustls_crypto_provider = {
        if cfg!(all(feature = "ring", not(feature = "aws-lc-rs"))) {
            "ring"
        } else {
            "aws-lc-rs"
        }
    };

    // Find the rustls dependency version specified in Cargo.toml
    let deps = metadata["dependencies"].as_table().unwrap();
    let rustls_dep = &deps["rustls"];
    let rustls_dep_version = match rustls_dep.as_table() {
        // Handle the `rustls = { version = "x.y.z", ... }` case
        Some(table) => table["version"].as_str(),
        // Handle the `rustls = "x.y.z"` case
        None => rustls_dep.as_str(),
    }
    .expect("missing rustls dependency version");

    // Assert that rustls_version() returns a string of the form:
    //   $CRATE_NAME/$CRATE_VERSION/rustls/$RUSTLS_VERSION
    // E.g.:
    //   rustls-ffi/0.13.0/rustls/0.23.4
    let rustls_ffi_version = rustls_version();
    let rustls_ffi_version = unsafe { rustls_ffi_version.to_str() };
    let rustls_ffi_version_parts = rustls_ffi_version.split('/').collect::<Vec<_>>();
    assert_eq!(
        rustls_ffi_version_parts,
        vec![
            env!("CARGO_PKG_NAME"),
            crate_version,
            "rustls",
            rustls_dep_version,
            rustls_crypto_provider,
        ]
    );
}
