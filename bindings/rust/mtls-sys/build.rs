use std::env;
use std::path::PathBuf;

fn main() {
    // Get the project root (mtls_lib directory)
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let project_root = PathBuf::from(&manifest_dir)
        .parent() // rust/
        .unwrap()
        .parent() // bindings/
        .unwrap()
        .parent() // mtls_lib/
        .unwrap()
        .to_path_buf();

    let include_dir = project_root.join("include");
    let build_dir = project_root.join("build");

    // Tell cargo to look for libraries in the build directory
    println!("cargo:rustc-link-search=native={}", build_dir.display());

    // Link the mTLS library and its dependencies
    println!("cargo:rustc-link-lib=mtls");
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=pthread");

    // Rerun if headers change
    println!("cargo:rerun-if-changed=wrapper.h");
    println!(
        "cargo:rerun-if-changed={}",
        include_dir.join("mtls/mtls.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        include_dir.join("mtls/mtls_types.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        include_dir.join("mtls/mtls_error.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        include_dir.join("mtls/mtls_config.h").display()
    );

    // Generate bindings using bindgen
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{}", include_dir.display()))
        // Only generate bindings for mTLS API
        .allowlist_function("mtls_.*")
        .allowlist_type("mtls_.*")
        .allowlist_var("MTLS_.*")
        // Generate proper Rust enums for C enums
        .rustified_enum("mtls_error_code")
        .rustified_enum("mtls_tls_version")
        .rustified_enum("mtls_conn_state")
        .rustified_enum("mtls_event_type")
        // Derive useful traits
        .derive_debug(true)
        .derive_default(true)
        .derive_copy(true)
        .derive_eq(true)
        .derive_hash(true)
        // Generate layout tests
        .layout_tests(true)
        // Use core instead of std where possible
        .use_core()
        // Generate documentation
        .generate_comments(true)
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
