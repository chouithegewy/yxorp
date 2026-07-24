//! Builds vendored liburing 2.15 (the `-ffi` static variant, which exports the
//! `static inline` API as real linkable symbols) and generates Rust bindings.
//!
//! The liburing source is copied into `OUT_DIR` before `configure`/`make` run, so
//! the submodule working tree stays pristine and the build works even when the
//! source tree is read-only (vendored/CI/sandbox).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // crates/runtime-uring-sys -> workspace root -> third_party/liburing
    let src_root = manifest_dir
        .join("../../third_party/liburing")
        .canonicalize()
        .expect("third_party/liburing submodule missing; run `git submodule update --init`");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let build_root = out_dir.join("liburing");

    // Rebuild only when the vendored source or our wrapper changes — never on the
    // generated artifacts we drop into OUT_DIR.
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=build.rs");
    println!(
        "cargo:rerun-if-changed={}",
        src_root.join("src/version.c").display()
    );

    copy_tree(&src_root, &build_root);

    // liburing ships a hand-written (non-autoconf) configure that writes
    // config-host.mak / config-host.h and enables the generated compat headers.
    run(
        Command::new("sh")
            .arg("configure")
            .current_dir(&build_root),
        "liburing ./configure",
    );

    // Only the static FFI archive is needed; ENABLE_SHARED=0 skips the .so link.
    run(
        Command::new("make")
            .arg("-C")
            .arg("src")
            .arg("ENABLE_SHARED=0")
            .arg("liburing-ffi.a")
            .current_dir(&build_root),
        "make liburing-ffi.a",
    );

    let lib_dir = build_root.join("src");
    let include_dir = build_root.join("src/include");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=uring-ffi");
    // Export for downstream crates / consumers.
    println!("cargo:include={}", include_dir.display());
    println!("cargo:lib={}", lib_dir.display());

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{}", include_dir.display()))
        // liburing's API is `static inline`; emit extern decls that bind to the
        // real symbols exported by liburing-ffi.a.
        .generate_inline_functions(true)
        .allowlist_function("io_uring_.*")
        .allowlist_type("io_uring_.*")
        .allowlist_type("__kernel_timespec")
        .allowlist_var("IORING_.*")
        .allowlist_var("IOSQE_.*")
        .allowlist_var("IORING_SETUP_.*")
        .allowlist_var("IORING_FEAT_.*")
        .allowlist_var("IORING_REGISTER_.*")
        .allowlist_var("IORING_ASYNC_CANCEL_.*")
        // Keep the surface small and stable.
        .layout_tests(false)
        .generate_comments(false)
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        .generate()
        .expect("bindgen failed to generate liburing bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("failed to write bindings.rs");
}

fn run(cmd: &mut Command, what: &str) {
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn {what}: {e}"));
    assert!(status.success(), "{what} failed with {status}");
}

/// Recursively copy `from` into `to`, skipping the submodule's `.git` pointer and
/// any pre-existing build artifacts.
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if name == ".git" {
            continue;
        }
        let src = entry.path();
        let dst = to.join(&name);
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&src, &dst);
        } else {
            // Overwrite is fine; OUT_DIR is ours.
            let _ = fs::copy(&src, &dst);
        }
    }
}
