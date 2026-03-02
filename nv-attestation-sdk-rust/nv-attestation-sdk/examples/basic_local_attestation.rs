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

/// Local verification example - performs GPU attestation using local verifier
use nv_attestation_sdk::{
    AttestationContext, DeviceType, HttpOptions, Nonce, NvatSdk, OcspClient, RimStore, SdkOptions,
    VerifierType,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== NVIDIA Attestation SDK - Local Verification ===");

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

    // Create RIM store
    // Using NVIDIA's RIM service - can also use filesystem with:
    // let rim_store = RimStore::create_filesystem("/path/to/rims")?;
    // Note: Keep this alive - the C SDK registers it internally and expects it to remain valid
    let rim_store = RimStore::create_remote(
        None, // Use default URL (https://rim.attestation.nvidia.com)
        None, // API key (optional - set via env var NVAT_RIM_SERVICE_BASE_URL)
        Some(&http_opts),
    )?;
    println!("RIM store created");

    // Create OCSP client for certificate revocation checking
    // Note: Keep this alive - the C SDK registers it internally and expects it to remain valid
    let ocsp_client = OcspClient::create_default(
        None, // Use default URL (https://ocsp.attestation.nvidia.com)
        None, // API key (optional - set via env var NVAT_OCSP_BASE_URL)
        Some(&http_opts),
    )?;
    println!("OCSP client created");

    // Keep these objects alive - the C SDK registers them globally and expects them to remain valid.
    // We don't use them directly in Rust, but dropping them early causes use-after-free in the C SDK.
    let _ = (&rim_store, &ocsp_client);

    // Create attestation context
    let ctx = AttestationContext::builder()
        .device_type(DeviceType::Gpu)
        .verifier_type(VerifierType::Local)
        // Optional: Set custom URLs for RIM store and OCSP
        // .rim_store_url("https://rim.attestation.nvidia.com")
        // .ocsp_url("https://ocsp.attestation.nvidia.com")
        // .service_key("your-api-key")
        // Or use pre-collected evidence from files:
        // .gpu_evidence_from_json_file("/path/to/gpu_evidence.json")
        .build()?;
    println!("Attestation context created and configured for GPU attestation with LOCAL verifier");

    // Generate a secure random nonce
    let nonce = Nonce::generate(32)?;
    println!("Generated nonce: {}", nonce.to_hex_string()?);
    println!("  Length: {} bytes", nonce.len());

    // Perform attestation with local verification
    println!("Performing local attestation...");
    println!("  • Collecting GPU evidence via NVML");
    println!("  • Fetching RIMs from remote store");
    println!("  • Checking OCSP certificate status");
    println!("  • Verifying measurements locally");

    match ctx.attest_device(Some(&nonce)) {
        Ok(result) => {
            println!("Local attestation successful!");

            // Display the detached EAT (Entity Attestation Token)
            if let Ok(eat) = result.eat_json() {
                println!("Detached EAT (signed locally):");
                println!("{}", eat);
            }

            // Display the claims
            if let Ok(claims) = result.claims_json() {
                println!("Claims Collection:");
                println!("{}", claims);
            }
        }
        Err(e) => {
            eprintln!("✗ Local attestation failed: {}", e);
            eprintln!("Troubleshooting:");
            eprintln!("  • Check GPU is accessible (nvidia-smi)");
            eprintln!("  • Verify RIM store is reachable");
            eprintln!("  • Verify OCSP service is reachable");
            eprintln!("  • Check firewall/network settings");
            return Err(e.into());
        }
    }

    println!("Attestation completed successfully");

    Ok(())
}
