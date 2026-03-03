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

/// Low-level remote attestation example using direct verifier API
///
/// This example demonstrates the complete low-level attestation flow:
/// 1. Collect GPU evidence directly using the evidence collection API
/// 2. Create a remote NRAS verifier
/// 3. Verify the evidence remotely using the verifier API
use nv_attestation_sdk::{
    EvidencePolicy, GpuEvidenceSource, GpuNrasVerifier, HttpOptions, Nonce, NvatSdk, SdkOptions,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== NVIDIA Attestation SDK - Low-Level Remote Attestation ===");
    println!();

    // Set up SDK options
    let opts = SdkOptions::new()?;

    // Initialize the SDK
    let _client = NvatSdk::init(opts)?;
    println!("NVAT SDK Version: {}", NvatSdk::version());
    println!("SDK initialized");
    println!();

    // =================================================================
    // STEP 1: Collect GPU Evidence (Low-Level API)
    // =================================================================
    println!("STEP 1: Collecting GPU Evidence");
    println!("--------------------------------");

    // Create a GPU evidence source using NVML (auto-detect GPUs)
    println!("Creating GPU evidence source (NVML)...");
    let source = GpuEvidenceSource::from_nvml()?;
    println!("GPU evidence source created");

    // Generate a secure random nonce
    let nonce = Nonce::generate(32)?;
    println!("Generated nonce: {}", nonce.to_hex_string()?);

    // Collect GPU evidence from the source
    println!("Collecting GPU evidence from devices...");
    let evidence = source.collect(&nonce)?;
    println!("Collected {} evidence item(s)", evidence.len());

    if evidence.is_empty() {
        eprintln!("No evidence collected - no GPUs found?");
        return Err("No GPUs found".into());
    }

    // Serialize evidence to JSON for inspection
    println!("Serializing evidence to JSON...");
    let evidence_json = evidence.to_json()?;
    println!("Evidence JSON ({} bytes):", evidence_json.len());
    println!("{}", evidence_json);
    println!();

    // =================================================================
    // STEP 2: Verify GPU Evidence Remotely via NRAS Using Verifier API
    // =================================================================
    println!("STEP 2: Verifying GPU Evidence Remotely via NRAS");
    println!("-------------------------------------------------");

    // Create HTTP options for NRAS communication
    let http_opts = HttpOptions::builder()
        .max_retry_count(5)
        .connection_timeout_ms(10000)
        .request_timeout_ms(30000)
        .build()?;
    println!("HTTP options configured");

    // Create a remote GPU verifier (NRAS) - low-level API
    // This verifier will send evidence to NRAS for remote verification
    // Optionally provide custom NRAS URL and service key:
    // let verifier = GpuNrasVerifier::new(
    //     Some("https://nras.attestation.nvidia.com"),
    //     Some("your-service-key"),
    //     Some(&http_opts)
    // )?;
    let verifier = GpuNrasVerifier::new(
        None, // Use default NRAS URL
        None, // No service key
        Some(&http_opts),
    )?;
    println!("GPU NRAS verifier created");

    // Create evidence policy for verification
    // The policy defines what checks should be performed
    let policy = EvidencePolicy::builder()
        .verify_rim_signature(true)
        .verify_rim_cert_chain(true)
        .build()?;
    println!("Evidence policy created");
    println!();

    // Perform direct verification using the NRAS verifier API
    println!("Verifying GPU evidence with NRAS verifier...");
    println!("  • Sending evidence to NRAS");
    println!("  • NRAS will verify evidence signatures");
    println!("  • NRAS will check certificate chains");
    println!("  • NRAS will validate measurements against RIMs");
    println!("  • NRAS will verify OCSP certificate status");
    println!();

    match verifier.verify(&evidence, &policy) {
        Ok(result) => {
            println!("GPU Evidence Remote Verification Successful!");
            println!();

            // Display the verification results
            if let Ok(eat) = result.eat_json() {
                println!("Entity Attestation Token (EAT):");
                println!("{}", eat);
                println!();
            }

            if let Ok(claims) = result.claims_json() {
                println!("Claims Collection (Verification Results):");
                println!("{}", claims);
                println!();
            }

            println!("=== Summary ===");
            println!(
                "1. Successfully collected {} GPU evidence item(s)",
                evidence.len()
            );
            println!("2. Successfully verified evidence using GpuNrasVerifier");
            println!("3. All measurements and signatures validated by NRAS");
        }
        Err(e) => {
            eprintln!("✗ GPU evidence remote verification FAILED: {}", e);
            eprintln!();
            eprintln!("Troubleshooting:");
            eprintln!("  • Check GPU is accessible (nvidia-smi)");
            eprintln!("  • Verify NRAS service is reachable");
            eprintln!("  • Check firewall/network settings");
            eprintln!("  • Verify internet connectivity");
            eprintln!("  • Ensure evidence was collected with valid nonce");
            return Err(e.into());
        }
    }

    Ok(())
}
