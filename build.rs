use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/ebpf/quic_route.c");

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = PathBuf::from(out_dir).join("quic_route.o");

    let status = Command::new("clang")
        .args(&[
            "-target",
            "bpf",
            "-O2",
            "-c",
            "src/ebpf/quic_route.c",
            "-o",
            dest_path.to_str().unwrap(),
        ])
        .status();

    match status {
        Ok(s) if s.success() => {
            println!(
                "cargo:rustc-env=EBPF_PROGRAM_PATH={}",
                dest_path.to_str().unwrap()
            );
        }
        _ => {
            // Fallback: If clang fails or is not present, we will fallback to using the pre-compiled
            // file in src/ebpf/quic_route.o if it exists.
            let fallback_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
                .join("src/ebpf/quic_route.o");
            if fallback_path.exists() {
                println!(
                    "cargo:rustc-env=EBPF_PROGRAM_PATH={}",
                    fallback_path.to_str().unwrap()
                );
            } else {
                panic!(
                    "Failed to compile eBPF program with clang and no pre-compiled fallback exists."
                );
            }
        }
    }
}
