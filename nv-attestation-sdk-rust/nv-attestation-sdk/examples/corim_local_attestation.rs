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

/// CORIM local verification example - appraises GPU evidence against
/// reference values using the local CoRIM verifier
use nv_attestation_sdk::{
    AiaOptions, CmwCollection, CmwFormat, CorimStore, GpuEvidenceSource, HttpOptions,
    LocalCorimVerifier, Nonce, NvatSdk, OcspClient, SdkOptions,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== NVIDIA Attestation SDK - CoRIM Verification ===");

    // Set up SDK options
    let opts = SdkOptions::new()?;

    // Initialize the SDK
    let _client = NvatSdk::init(opts)?;
    println!("NVAT SDK Version: {}", NvatSdk::version());
    println!("SDK initialized");

    // Create HTTP options for RIM and OCSP services
    let mut http_opts = HttpOptions::default_options()?;
    http_opts.set_max_retry_count(5);
    http_opts.set_connection_timeout_ms(10000);
    http_opts.set_request_timeout_ms(30000);
    println!("HTTP options configured");

    // Generate a secure random nonce
    // Set NVAT_NONCE_HEX to replay recorded evidence, which only verifies
    // against the nonce it was collected with
    let nonce = match std::env::var("NVAT_NONCE_HEX") {
        Ok(hex) => Nonce::from_hex(&hex)?,
        Err(_) => Nonce::generate(32)?,
    };
    println!("Nonce: {}", nonce.to_hex_string()?);
    println!("  Length: {} bytes", nonce.len());

    // Collect GPU evidence
    // Using NVML - can also replay recorded evidence by setting
    // NVAT_GPU_EVIDENCE_JSON=/path/to/gpu_evidence.json
    let source = match std::env::var("NVAT_GPU_EVIDENCE_JSON") {
        Ok(path) => {
            println!("Using recorded GPU evidence from {path}");
            GpuEvidenceSource::from_json_file(&path)?
        }
        Err(_) => {
            println!("Collecting GPU evidence via NVML");
            GpuEvidenceSource::from_nvml()?
        }
    };
    let evidence = source.collect(&nonce)?;
    println!("Collected evidence for {} device(s)", evidence.len());

    // Wrap the evidence in a CMW input collection - the input the CoRIM
    // verifier consumes
    let cmw = CmwCollection::from_gpu_evidence(&evidence, &nonce)?;
    println!("CMW input collection built");

    // Create CoRIM store
    // Fetches reference values from the rim-locator URLs carried in the
    // evidence
    let mut store = CorimStore::new(
        None, // Service key (optional)
        Some(&http_opts),
    )?;
    println!("CoRIM store created");

    // Cache fetched CoRIMs so repeat verifications skip the network. Must be
    // enabled before the verifier takes ownership of the store.
    store.enable_in_memory_cache(16 * 1024 * 1024, 3600)?;
    println!("CoRIM store cache enabled (16 MiB, 1h TTL)");

    // To fetch CoRIMs from a mirror instead, rewrite the URL prefix:
    // store.add_url_rewrite("https://rim.attestation.nvidia.com/", "file:///opt/corims/")?;

    // Create OCSP client for certificate revocation checking
    // The CoRIM verifier expects the AIA client - responder URLs come from
    // the certificates themselves
    let ocsp_client = OcspClient::create_aia(AiaOptions {
        http_options: Some(&http_opts),
        ..Default::default()
    })?;
    println!("OCSP client created");

    // Create the local CoRIM verifier
    let verifier = LocalCorimVerifier::new(store, Some(&ocsp_client))?;
    println!("Local CoRIM verifier created");

    // Appraise the evidence against the CoRIM reference values
    println!("Performing CoRIM verification...");
    println!("  • Normalizing CMW evidence into environment-claims tuples");
    println!("  • Fetching CoRIMs from rim-locator URLs");
    println!("  • Matching reference values against evidence claims");

    // No signing options leaves the EAR JWT unsigned. To sign it, pass
    // EarSigningOptions to verify_cmw_collection.
    match verifier.verify_cmw_collection(&cmw, CmwFormat::Json, None) {
        Ok(ear) => {
            println!("CoRIM verification completed!");

            // Findings are collected. Parse the EAR and apply your own policy.
            println!("EAR (JSON):");
            println!("{}", ear.json);
            println!("EAR (JWT):");
            println!("{}", ear.jwt);
        }
        Err(e) => {
            eprintln!("✗ CoRIM verification failed: {e}");
            eprintln!("Troubleshooting:");
            eprintln!("  • Verify the evidence carries CoRIM rim-locator URLs");
            eprintln!("  • Verify the RIM service serving the CoRIMs is reachable");
            eprintln!("  • Verify OCSP service is reachable");
            eprintln!("  • Check firewall/network settings");
            return Err(e.into());
        }
    }

    println!("Attestation completed successfully");

    Ok(())
}
