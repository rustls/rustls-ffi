use std::{env, fs, path::PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let include_dir = out_dir.join("include");

    fs::create_dir_all(&include_dir).unwrap();
    fs::copy("src/crustls.h", include_dir.join("crustls.h")).unwrap();

    println!("cargo:include={}", include_dir.to_str().unwrap());
}
