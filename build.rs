use std::fs::File;
use std::io::Write;
use std::{env, fs, path::PathBuf};

// Keep in sync with Cargo.toml.
//
// We don't populate this automatically from the Cargo.toml at build time
// because doing so would require a heavy-weight deserialization lib dependency
// (and it couldn't be a _dev_ dep for use in a build script) or doing brittle
// by-hand parsing.
const RUSTLS_CRATE_VERSION: &str = "0.23.18";

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let include_dir = out_dir.join("include");

    fs::create_dir_all(&include_dir).unwrap();
    fs::copy("src/rustls.h", include_dir.join("rustls.h")).unwrap();

    println!("cargo:include={}", include_dir.to_str().unwrap());

    let rustls_crypto_provider = {
        if cfg!(all(feature = "ring", not(feature = "aws-lc-rs"))) {
            "ring"
        } else {
            "aws-lc-rs"
        }
    };

    let dest_path = out_dir.join("version.rs");
    let mut f = File::create(dest_path).expect("Could not create file");
    let pkg_version = env!("CARGO_PKG_VERSION");
    writeln!(
        &mut f,
        r#"const RUSTLS_FFI_VERSION: &str = "rustls-ffi/{}/rustls/{}/{}";"#,
        pkg_version, RUSTLS_CRATE_VERSION, rustls_crypto_provider
    )
    .expect("Could not write file");

    println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");
}
