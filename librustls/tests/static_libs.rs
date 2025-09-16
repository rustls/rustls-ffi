use std::process::Command;
use std::str;

#[test]
#[ignore] // This test recompiles the crate and can be slow (~5s).
fn verify_static_libs() {
    // Build the crate, printing native-static-lib requirements.
    let result = Command::new("cargo")
        .args(["build", "--color", "never"])
        .env("RUSTFLAGS", "--print native-static-libs")
        .output()
        .expect("failed to execute process");
    assert!(result.status.success());

    // Search for the expected native-static-libs output in the cargo stderr.
    let mut native_libs = Vec::new();
    for ln in result.stderr.split(|&b| b == b'\n') {
        let Some(libs_str) = ln.strip_prefix(b"note: native-static-libs: ") else {
            continue;
        };

        let libs_str = str::from_utf8(libs_str).unwrap().trim();
        native_libs.extend(libs_str.split_whitespace().map(String::from));
    }

    assert!(
        !native_libs.is_empty(),
        "missing expected native-static-libs output"
    );

    // We should find the expected native-static-libs output for the platform in question.
    assert_eq!(
        native_libs,
        expected_linker_parts(),
        "unexpected list of static libraries. Fix or update README"
    )
}

fn expected_linker_parts() -> &'static [&'static str] {
    #[cfg(target_os = "linux")]
    {
        &[
            "-lgcc_s",
            "-lutil",
            "-lrt",
            "-lpthread",
            "-lm",
            "-ldl",
            "-lc",
        ]
    }
    #[cfg(target_os = "macos")]
    {
        &[
            "-framework",
            "Security",
            "-framework",
            "CoreFoundation",
            "-liconv",
            "-lSystem",
            "-lc",
            "-lm",
        ]
    }
    #[cfg(target_os = "windows")]
    {
        &[
            "advapi32.lib",
            "bcrypt.lib",
            "crypt32.lib",
            "cryptnet.lib",
            "kernel32.lib",
            "ncrypt.lib",
            "bcrypt.lib",
            "advapi32.lib",
            "legacy_stdio_definitions.lib",
            "kernel32.lib",
            "advapi32.lib",
            "kernel32.lib",
            "ntdll.lib",
            "userenv.lib",
            "ws2_32.lib",
            "synchronization.lib",
            "kernel32.lib",
            "ws2_32.lib",
            "kernel32.lib",
            "msvcrt.lib",
        ]
    }
}
