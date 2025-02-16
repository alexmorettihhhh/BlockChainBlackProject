fn main() {
    println!("cargo:rustc-env=RUST_BACKTRACE=1");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
} 