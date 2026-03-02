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

/// Logging integration example - demonstrates how to use the logging feature
///
/// This example shows how to integrate the NVIDIA Attestation SDK with Rust's
/// logging ecosystem (using env_logger and the log crate). It demonstrates:
/// 1. Initializing env_logger to handle Rust logging
/// 2. Setting up the Logger to integrate C SDK logs with Rust's log facade
/// 3. Using log macros (info!, warn!, error!, etc.) throughout the application
///
/// To run this example:
///     cargo run --example logging_example --features logging
///
/// Control log level via RUST_LOG environment variable:
///     RUST_LOG=debug cargo run --example logging_example --features logging
///     RUST_LOG=trace cargo run --example logging_example --features logging
use log::{debug, error, info, warn};
use nv_attestation_sdk::{
    AttestationContext, DeviceType, HttpOptions, Logger, Nonce, NvatSdk, OcspClient, RimStore,
    SdkOptions, VerifierType,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize env_logger to handle all logging (both Rust and C SDK)
    // This reads the RUST_LOG environment variable to set the log level
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("=== NVIDIA Attestation SDK - Logging Example ===");
    info!("");

    // Set up SDK options with logger integration
    // The Logger bridges C SDK logging to Rust's log facade (handled by env_logger)
    let mut opts = SdkOptions::new()?;
    let logger = Logger::new()?;
    opts.set_logger(logger);
    info!("Logger configured to bridge C SDK logs to Rust log ecosystem");

    // Initialize the SDK
    let _client = NvatSdk::init(opts)?;
    info!("NVAT SDK Version: {}", NvatSdk::version());
    info!("SDK initialized");
    info!("");

    // Create HTTP options for RIM and OCSP services
    debug!("Configuring HTTP options...");
    let mut http_opts = HttpOptions::default_options()?;
    http_opts.set_max_retry_count(5);
    http_opts.set_connection_timeout_ms(10000);
    http_opts.set_request_timeout_ms(30000);
    info!(
        "HTTP options configured (retry: {}, timeout: {}ms)",
        5, 30000
    );

    // Create RIM store
    debug!("Creating RIM store...");
    let rim_store = RimStore::create_remote(
        None, // Use default URL (https://rim.attestation.nvidia.com)
        None, // API key (optional - set via env var NVAT_RIM_SERVICE_BASE_URL)
        Some(&http_opts),
    )?;
    info!("RIM store created (remote)");

    // Create OCSP client for certificate revocation checking
    debug!("Creating OCSP client...");
    let ocsp_client = OcspClient::create_default(
        None, // Use default URL (https://ocsp.attestation.nvidia.com)
        None, // API key (optional - set via env var NVAT_OCSP_BASE_URL)
        Some(&http_opts),
    )?;
    info!("OCSP client created");

    // Keep these objects alive - the C SDK registers them globally and expects them to remain valid
    let _ = (&rim_store, &ocsp_client);

    // Create attestation context
    debug!("Building attestation context...");
    let ctx = AttestationContext::builder()
        .device_type(DeviceType::Gpu)
        .verifier_type(VerifierType::Local)
        .build()?;
    info!("Attestation context created and configured for GPU attestation with LOCAL verifier");
    info!("");

    // Generate a secure random nonce
    debug!("Generating nonce...");
    let nonce = Nonce::generate(32)?;
    info!("Generated nonce: {}", nonce.to_hex_string()?);
    debug!("  Nonce length: {} bytes", nonce.len());
    info!("");

    // Perform attestation with local verification
    info!("Starting local attestation process...");
    info!("  Step 1: Collecting GPU evidence via NVML");
    info!("  Step 2: Fetching RIMs from remote store");
    info!("  Step 3: Checking OCSP certificate status");
    info!("  Step 4: Verifying measurements locally");
    info!("");

    match ctx.attest_device(Some(&nonce)) {
        Ok(result) => {
            info!("✓ Local attestation successful!");
            info!("");

            // Display the detached EAT (Entity Attestation Token)
            if let Ok(eat) = result.eat_json() {
                info!("Detached EAT (signed locally):");
                debug!("EAT length: {} bytes", eat.len());
                info!("{}", eat);
                info!("");
            }

            // Display the claims
            if let Ok(claims) = result.claims_json() {
                info!("Claims Collection:");
                debug!("Claims length: {} bytes", claims.len());
                info!("{}", claims);
                info!("");
            }
        }
        Err(e) => {
            error!("✗ Local attestation failed: {}", e);
            error!("");
            warn!("Troubleshooting tips:");
            warn!("  • Check GPU is accessible (nvidia-smi)");
            warn!("  • Verify RIM store is reachable");
            warn!("  • Verify OCSP service is reachable");
            warn!("  • Check firewall/network settings");
            warn!("  • Try running with RUST_LOG=debug for more details");
            return Err(e.into());
        }
    }

    info!("Attestation completed successfully");

    info!("");
    info!("=== Logging Example Complete ===");
    info!("Tip: Run with RUST_LOG=debug or RUST_LOG=trace for more detailed logs");

    Ok(())
}
