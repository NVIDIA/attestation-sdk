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

/// Remote verification example - performs GPU attestation using NRAS
use nv_attestation_sdk::{
    AttestationContext, DeviceType, Nonce, NvatSdk, SdkOptions, VerifierType,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== NVIDIA Attestation SDK - Remote Attestation ===");

    // Set up SDK options
    let opts = SdkOptions::new()?;

    // Initialize the SDK
    let _client = NvatSdk::init(opts)?;
    println!("NVAT SDK Version: {}", NvatSdk::version());
    println!("SDK initialized");

    // Create attestation context
    let ctx = AttestationContext::builder()
        .device_type(DeviceType::Gpu)
        .verifier_type(VerifierType::Remote)
        // Optionally set custom URLs (uncomment to use)
        // .nras_url("https://nras.attestation.nvidia.com")
        // .ocsp_url("https://ocsp.attestation.nvidia.com")
        // .rim_store_url("https://rim.attestation.nvidia.com")
        .build()?;
    println!("Attestation context created and configured for GPU attestation with remote verifier");

    // Generate a secure random nonce
    let nonce = Nonce::generate(32)?;
    println!("Generated nonce: {}", nonce.to_hex_string()?);
    println!("  Length: {} bytes", nonce.len());

    // Perform attestation
    println!("Performing attestation...");
    match ctx.attest_device(Some(&nonce)) {
        Ok(result) => {
            println!("Attestation successful!");

            // Display the detached EAT (Entity Attestation Token)
            if let Ok(eat) = result.eat_json() {
                println!("Detached EAT (JSON):");
                println!("{}", eat);
            }

            // Display the claims
            if let Ok(claims) = result.claims_json() {
                println!("Claims Collection (JSON):");
                println!("{}", claims);
            }
        }
        Err(e) => {
            eprintln!("✗ Attestation failed: {}", e);
            return Err(e.into());
        }
    }

    println!("Attestation completed successfully");

    Ok(())
}
