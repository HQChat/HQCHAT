//! Compiles the prepared HQC tree named by `HQC_SOURCE` (set by `nix develop`;
//! `nix build .#hqc.source` prints it) together with `csrc/hqc_sys.c`.
//!
//! One source and one set of flags for every target, whatever the Cargo
//! profile: the same as `native/hqc/package.nix` and `build-apple.sh`, so the
//! library is byte-compatible with every shipped client. Never
//! `-march=native`: the reference C is portable and has no CPU-specific path.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const INCLUDES: [&str; 6] = [
    "src/common",
    "src/common/hqc-5",
    "src/ref",
    "src/ref/hqc-5",
    "lib/fips202",
    ".",
];

fn main() {
    println!("cargo:rerun-if-env-changed=HQC_SOURCE");
    println!("cargo:rerun-if-changed=csrc/hqc_sys.c");

    let src = PathBuf::from(env::var_os("HQC_SOURCE").unwrap_or_else(|| {
        panic!(
            "HQC_SOURCE is not set: run inside `nix develop`, or export \
             HQC_SOURCE=$(nix build --no-link --print-out-paths .#hqc.source)"
        )
    }));
    let portability = src.join("hqc_portability.h");
    assert!(
        portability.is_file(),
        "HQC_SOURCE={} is not a prepared HQC tree (no hqc_portability.h)",
        src.display()
    );

    let mut build = cc::Build::new();
    for dir in INCLUDES {
        build.include(src.join(dir));
    }
    build
        .define("HQC_ARCH_REF", "1")
        .opt_level(2)
        // Upstream code, compiled as upstream ships it.
        .warnings(false);
    if build.get_compiler().is_like_msvc() {
        build.flag(format!("/FI{}", portability.display()));
    } else {
        build
            .flag("-include")
            .flag(portability.display().to_string());
    }

    let mut files = c_files(&src.join("src/common"));
    files.extend(c_files(&src.join("src/ref")));
    files.push(src.join("lib/fips202/fips202.c"));
    files.push(src.join("low_wrap.c"));
    files.push(PathBuf::from("csrc/hqc_sys.c"));
    build.files(&files).compile("hqc");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        // hqc_getrandom (hqc_portability.h) calls BCryptGenRandom.
        println!("cargo:rustc-link-lib=bcrypt");
    }
}

/// The `.c` files directly in `dir`, sorted so the build is reproducible.
fn c_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "c"))
        .collect();
    files.sort();
    files
}
