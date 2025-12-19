use std::env;
use std::path::PathBuf;
use std::process::Command;

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

    // Use MTLS_LIB_DIR if set (from CI), otherwise use default build directory
    let build_dir = if let Ok(lib_dir) = env::var("MTLS_LIB_DIR") {
        PathBuf::from(lib_dir)
    } else {
        // On Windows, CMake creates build/Release or build/Debug
        // Try to detect which one exists
        let base_build_dir = project_root.join("build");
        if cfg!(target_os = "windows") {
            let release_dir = base_build_dir.join("Release");
            let debug_dir = base_build_dir.join("Debug");

            if release_dir.exists() {
                release_dir
            } else if debug_dir.exists() {
                debug_dir
            } else {
                base_build_dir
            }
        } else {
            base_build_dir
        }
    };

    // Tell cargo to look for libraries in the build directory
    println!("cargo:rustc-link-search=native={}", build_dir.display());

    // Find OpenSSL library path (especially needed on macOS where Homebrew installs it)
    find_openssl();

    // Link the mTLS library and its dependencies
    println!("cargo:rustc-link-lib=mtls");

    // OpenSSL libraries have different names on Windows
    if cfg!(target_os = "windows") {
        println!("cargo:rustc-link-lib=libssl");
        println!("cargo:rustc-link-lib=libcrypto");

        // When statically linking OpenSSL on Windows, we need to link Windows system libraries
        println!("cargo:rustc-link-lib=crypt32");  // Windows Cryptography API
        println!("cargo:rustc-link-lib=ws2_32");   // Windows Sockets
        println!("cargo:rustc-link-lib=advapi32"); // Advanced Windows API
        println!("cargo:rustc-link-lib=user32");   // Windows User API

        // Windows doesn't use pthread
    } else {
        println!("cargo:rustc-link-lib=ssl");
        println!("cargo:rustc-link-lib=crypto");
        println!("cargo:rustc-link-lib=pthread");
    }

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

/// Find OpenSSL library path and add it to the linker search path.
/// This is especially important on macOS where Homebrew installs OpenSSL
/// in a non-standard location.
fn find_openssl() {
    // Try pkg-config first (works on Linux and macOS with Homebrew)
    if let Ok(output) = Command::new("pkg-config")
        .args(["--libs", "openssl"])
        .output()
    {
        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            // Parse all -L paths from pkg-config output
            for part in output_str.split_whitespace() {
                if let Some(lib_path) = part.strip_prefix("-L") {
                    if PathBuf::from(lib_path).exists() {
                        println!("cargo:rustc-link-search=native={}", lib_path);
                    }
                }
            }
            // If we found any paths via pkg-config, we're done
            if output_str.contains("-L") {
                return;
            }
        }
    }

    // Fallback: Try common Homebrew paths on macOS
    if cfg!(target_os = "macos") {
        let homebrew_paths = [
            "/opt/homebrew/opt/openssl@3/lib", // Apple Silicon (openssl@3)
            "/opt/homebrew/opt/openssl/lib",   // Apple Silicon (default)
            "/usr/local/opt/openssl@3/lib",    // Intel (openssl@3)
            "/usr/local/opt/openssl/lib",      // Intel (default)
        ];

        for path in &homebrew_paths {
            if PathBuf::from(path).exists() {
                println!("cargo:rustc-link-search=native={}", path);
                return;
            }
        }
    }

    // Windows: Use OPENSSL_DIR or OPENSSL_LIB_DIR environment variables
    if cfg!(target_os = "windows") {
        // First try OPENSSL_LIB_DIR (set by CI workflow)
        if let Ok(lib_dir) = env::var("OPENSSL_LIB_DIR") {
            println!("cargo:rustc-link-search=native={}", lib_dir);
            return;
        }

        // Then try OPENSSL_DIR/lib
        if let Ok(openssl_dir) = env::var("OPENSSL_DIR") {
            let lib_path = PathBuf::from(openssl_dir).join("lib");
            if lib_path.exists() {
                println!("cargo:rustc-link-search=native={}", lib_path.display());
                return;
            }
        }

        // Fallback: Common choco install paths
        let common_paths = [
            "C:\\Program Files\\OpenSSL\\lib",
            "C:\\Program Files\\OpenSSL-Win64\\lib",
            "C:\\OpenSSL-Win64\\lib",
        ];

        for path in &common_paths {
            if PathBuf::from(path).exists() {
                println!("cargo:rustc-link-search=native={}", path);
                return;
            }
        }
    }
}
