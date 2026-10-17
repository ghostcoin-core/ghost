//! Records the compiler version and the build flags, so every result names the
//! toolchain it was produced with.

use std::env;
use std::process::Command;

fn main() {
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let version = Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=GHOST_REVEAL_RUSTC_VERSION={version}");

    let flags = env::var("CARGO_ENCODED_RUSTFLAGS")
        .map(|f| f.replace('\u{1f}', " "))
        .unwrap_or_default();
    let profile = env::var("PROFILE").unwrap_or_default();
    let target = env::var("TARGET").unwrap_or_default();
    println!("cargo:rustc-env=GHOST_REVEAL_BUILD_FLAGS=profile={profile} target={target} rustflags=[{flags}]");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    println!("cargo:rerun-if-env-changed=RUSTC");
}
