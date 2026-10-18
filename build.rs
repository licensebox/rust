fn main() {
    println!("cargo:rerun-if-env-changed=LICENSEBOX_LIB_DIR");
    if let Ok(path) = std::env::var("LICENSEBOX_LIB_DIR") {
        println!("cargo:rustc-link-search=native={path}");
    }
    println!("cargo:rustc-link-lib=dylib=licensebox");
}
