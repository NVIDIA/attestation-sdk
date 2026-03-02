/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::env;
use std::path::{Path, PathBuf};

fn main() {
    // Check if we should use system-installed library
    // Only enable if explicitly set to "1" (allows NVAT_USE_SYSTEM_LIB=0 to disable)
    let use_system_lib = env::var("NVAT_USE_SYSTEM_LIB")
        .map(|v| v == "1")
        .unwrap_or(false);

    if use_system_lib {
        // Use system-installed library (e.g., from nvattest package)
        // The library should be in standard system paths (/usr/lib, /usr/local/lib, etc.)
        println!("cargo:rustc-link-lib=dylib=nvat");
        eprintln!("Using system-installed libnvat (NVAT_USE_SYSTEM_LIB is set)");

        // For system library, we still need to generate bindings
        // Assume header is in standard location
        let header_path = PathBuf::from("/usr/include/nvat.h");
        if header_path.exists() {
            generate_bindings(&header_path, &PathBuf::from("/usr/include"));
        } else {
            panic!(
                "Header file not found at {:?}.\n\
                 Please ensure the nvattest development package is installed.",
                header_path
            );
        }
    } else {
        // Development mode: use local C++ build
        // Use CARGO_MANIFEST_DIR to get absolute path
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let manifest_path = PathBuf::from(&manifest_dir);
        let cpp_dir = manifest_path
            .parent()
            .unwrap()
            .join("../nv-attestation-sdk-cpp");
        let build_dir = cpp_dir.join("build");
        let include_dir = build_dir.join("include");
        let header_path = include_dir.join("nvat.h");

        // Verify the header exists
        if !header_path.exists() {
            panic!(
                "Header file not found at {:?}.\n\
                 \n\
                 If you're building from source, please build the C++ SDK first.\n\
                 If you have the library installed (e.g., nvattest package), set:\n\
                 export NVAT_USE_SYSTEM_LIB=1",
                header_path
            );
        }

        // Tell cargo where to find the library
        println!("cargo:rustc-link-search=native={}", build_dir.display());
        println!("cargo:rustc-link-lib=dylib=nvat");

        // Tell cargo to invalidate the built crate whenever the header changes
        println!("cargo:rerun-if-changed={}", header_path.display());

        // Always generate bindings at build time
        generate_bindings(&header_path, &include_dir);
    }

    println!("cargo:rerun-if-env-changed=NVAT_USE_SYSTEM_LIB");
}

fn generate_bindings(header_path: &Path, include_dir: &Path) {
    // Generate Rust bindings from the header file
    let bindings = bindgen::Builder::default()
        // Point to the generated header
        .header(header_path.to_str().unwrap())
        // Tell bindgen where to find included headers
        .clang_arg(format!("-I{}", include_dir.display()))
        // Generate bindings for C code (not C++)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Opaque types for opaque pointers (struct forward declarations)
        .opaque_type("nvat_str_st")
        .opaque_type("nvat_sdk_opts_st")
        .opaque_type("nvat_logger_st")
        .opaque_type("nvat_http_options_st")
        .opaque_type("nvat_ocsp_client_st")
        .opaque_type("nvat_rim_store_st")
        .opaque_type("nvat_nonce_st")
        .opaque_type("nvat_gpu_evidence_st")
        .opaque_type("nvat_gpu_evidence_source_st")
        .opaque_type("nvat_switch_evidence_st")
        .opaque_type("nvat_switch_evidence_source_st")
        .opaque_type("nvat_claims_st")
        .opaque_type("nvat_detached_eat_options_st")
        .opaque_type("nvat_claims_collection_st")
        .opaque_type("nvat_evidence_policy_st")
        .opaque_type("nvat_gpu_verifier_st")
        .opaque_type("nvat_gpu_nras_verifier_st")
        .opaque_type("nvat_gpu_local_verifier_st")
        .opaque_type("nvat_switch_verifier_st")
        .opaque_type("nvat_switch_nras_verifier_st")
        .opaque_type("nvat_switch_local_verifier_st")
        .opaque_type("nvat_relying_party_policy_st")
        .opaque_type("nvat_attestation_ctx_st")
        // Allowlist only the nvat API
        .allowlist_function("nvat_.*")
        .allowlist_type("nvat_.*")
        .allowlist_var("NVAT_.*")
        // Generate the bindings
        .generate()
        .expect("Unable to generate bindings");

    // Write bindings to OUT_DIR (build-time generation)
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
