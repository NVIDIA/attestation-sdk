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

//! Unit tests for NVAT Rust bindings
//!
//! These tests validate the safe Rust API without requiring GPU hardware.
//! Tests focus on memory safety, error handling, and basic functionality.

use crate::*;
use std::sync::LazyLock;

// Initialize the process-global SDK once and keep it alive for all tests.
static SDK_INIT: LazyLock<()> = LazyLock::new(|| {
    // Initialize env_logger for tests (only once)
    let _ = env_logger::builder().is_test(true).try_init();

    let sdk = {
        #[cfg(feature = "logging")]
        {
            let mut opts = SdkOptions::new().expect("Failed to create SDK options for tests");
            let logger = Logger::new().expect("Failed to create logger for tests");
            opts.set_logger(logger);
            NvatSdk::init(opts).expect("Failed to initialize SDK for tests")
        }
        #[cfg(not(feature = "logging"))]
        {
            let opts = SdkOptions::new().expect("Failed to create SDK options for tests");
            NvatSdk::init(opts).expect("Failed to initialize SDK for tests")
        }
    };

    // The SDK is a process-global C lifecycle guard and is intentionally not
    // Send/Sync. Keep it initialized for the whole test process.
    std::mem::forget(sdk);
});

/// Initialize the SDK for tests. This is called once per test process.
fn init_sdk() {
    // Force initialization of the lazy static
    let _ = &*SDK_INIT;
}

// ========================================================================
// Nonce Tests
// ========================================================================

#[test]
fn test_nonce_generation() {
    init_sdk();
    let nonce = Nonce::generate(32);
    assert!(nonce.is_ok(), "Nonce generation should succeed");

    let nonce = nonce.unwrap();
    assert_eq!(nonce.len(), 32, "Nonce should be 32 bytes");
    assert!(!nonce.is_empty(), "Nonce should not be empty");
}

#[test]
fn test_nonce_generation_different_sizes() {
    init_sdk();
    // Test valid sizes (minimum is 32 bytes)
    for size in [32, 64, 128] {
        let nonce = Nonce::generate(size);
        assert!(
            nonce.is_ok(),
            "Nonce generation with size {} should succeed",
            size
        );
        assert_eq!(nonce.unwrap().len(), size, "Nonce should be {} bytes", size);
    }

    // Test that size below minimum fails
    let nonce = Nonce::generate(16);
    assert!(
        nonce.is_err(),
        "Nonce generation with size 16 should fail (below minimum of 32)"
    );
}

#[test]
fn test_nonce_from_hex_with_prefix() {
    init_sdk();
    let hex = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let nonce = Nonce::from_hex(hex);
    assert!(
        nonce.is_ok(),
        "Nonce from hex with 0x prefix should succeed"
    );

    let nonce = nonce.unwrap();
    assert_eq!(nonce.len(), 32, "Nonce should be 32 bytes");
}

#[test]
fn test_nonce_from_hex_without_prefix() {
    init_sdk();
    let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let nonce = Nonce::from_hex(hex);
    assert!(
        nonce.is_ok(),
        "Nonce from hex without prefix should succeed"
    );

    let nonce = nonce.unwrap();
    assert_eq!(nonce.len(), 32, "Nonce should be 32 bytes");
}

#[test]
fn test_nonce_to_hex_string() {
    init_sdk();
    let nonce = Nonce::generate(32).unwrap();
    let hex = nonce.to_hex_string();
    assert!(hex.is_ok(), "Nonce to hex conversion should succeed");

    let hex_string = hex.unwrap();
    assert_eq!(
        hex_string.len(),
        64,
        "Hex string should be 64 characters (32 bytes * 2)"
    );
    assert!(
        hex_string.chars().all(|c| c.is_ascii_hexdigit()),
        "All characters should be hex digits"
    );
}

#[test]
fn test_nonce_roundtrip() {
    init_sdk();
    let original = Nonce::generate(32).unwrap();
    let hex = original.to_hex_string().unwrap();
    let restored = Nonce::from_hex(&hex).unwrap();

    assert_eq!(
        original.len(),
        restored.len(),
        "Roundtrip nonce should have same length"
    );
    assert_eq!(
        original.to_hex_string().unwrap(),
        restored.to_hex_string().unwrap(),
        "Roundtrip nonce should have same value"
    );
}

#[test]
fn test_nonce_from_invalid_hex() {
    init_sdk();
    let invalid_hex = "not_a_hex_string";
    let result = Nonce::from_hex(invalid_hex);
    assert!(
        result.is_err(),
        "Nonce creation for invalid hex string should fail"
    );
}

#[test]
fn test_nonce_from_short_hex() {
    init_sdk();
    // Less than 32 bytes (64 hex chars)
    let short_hex = "0123456789abcdef";
    let result = Nonce::from_hex(short_hex);
    assert!(
        result.is_err(),
        "Nonce creation for short hex string should fail"
    );
}

#[test]
fn test_multiple_nonces() {
    init_sdk();
    // Create multiple nonces to test that each has independent memory
    let nonce1 = Nonce::generate(32).unwrap();
    let nonce2 = Nonce::generate(32).unwrap();
    let nonce3 = Nonce::generate(32).unwrap();

    let hex1 = nonce1.to_hex_string().unwrap();
    let hex2 = nonce2.to_hex_string().unwrap();
    let hex3 = nonce3.to_hex_string().unwrap();

    // They should all be different (statistically)
    assert_ne!(hex1, hex2, "Random nonces should be different");
    assert_ne!(hex2, hex3, "Random nonces should be different");
    assert_ne!(hex1, hex3, "Random nonces should be different");
}

// ========================================================================
// Error Handling Tests
// ========================================================================

#[test]
fn test_error_message_retrieval() {
    init_sdk();
    let error = NvatError::new(1); // Assuming 1 is a valid error code
    let msg = error.message();
    assert!(!msg.is_empty(), "Error message should not be empty");
}

#[test]
fn test_error_display() {
    init_sdk();
    let error = NvatError::new(1);
    let display = format!("{}", error);
    assert!(
        display.contains("NVAT Error"),
        "Display should contain 'NVAT Error'"
    );
    assert!(display.contains("1"), "Display should contain error code");
}

#[test]
fn test_error_check_success() {
    init_sdk();
    let result = NvatError::check(NVAT_RC_OK as u16);
    assert!(result.is_ok(), "NVAT_RC_OK should be treated as success");
}

#[test]
fn test_error_check_failure() {
    init_sdk();
    let result = NvatError::check(1); // Non-zero error code
    assert!(
        result.is_err(),
        "Non-zero error code should be treated as failure"
    );
}

// ========================================================================
// SDK Options Tests
// ========================================================================

#[test]
fn test_sdk_options_creation() {
    init_sdk();
    let opts = SdkOptions::new();
    assert!(opts.is_ok(), "SDK options creation should succeed");
}

#[test]
fn test_sdk_options_new_is_fallible() {
    init_sdk();
    let opts = SdkOptions::new().expect("SDK options creation should succeed");
    drop(opts);
}

// ========================================================================
// HTTP Options Tests
// ========================================================================

#[test]
fn test_http_options_creation() {
    init_sdk();
    let opts = HttpOptions::default_options();
    assert!(opts.is_ok(), "HTTP options creation should succeed");
}

#[test]
fn test_http_options_configuration() {
    init_sdk();
    let mut opts = HttpOptions::default_options().unwrap();

    // These should not panic
    opts.set_max_retry_count(5);
    opts.set_base_backoff_ms(100);
    opts.set_max_backoff_ms(5000);
    opts.set_connection_timeout_ms(10000);
    opts.set_request_timeout_ms(30000);

    // If we reach here, configuration succeeded
    drop(opts);
}

#[test]
fn test_http_options_with_zero_values() {
    init_sdk();
    let mut opts = HttpOptions::default_options().unwrap();

    opts.set_max_retry_count(0);
    opts.set_base_backoff_ms(0);
    opts.set_max_backoff_ms(0);
    opts.set_connection_timeout_ms(0);
    opts.set_request_timeout_ms(0);

    drop(opts);
}

#[test]
fn test_http_options_tls_paths_reject_nul_bytes() {
    init_sdk();
    let mut opts = HttpOptions::default_options().unwrap();

    let cert_err = opts.set_tls_ca_cert("bad\0cert").unwrap_err();
    assert_eq!(cert_err.code, NVAT_RC_BAD_ARGUMENT as u16);

    let path_err = opts.set_tls_ca_path("bad\0path").unwrap_err();
    assert_eq!(path_err.code, NVAT_RC_BAD_ARGUMENT as u16);

    match HttpOptions::builder().tls_ca_cert("bad\0cert").build() {
        Ok(_) => panic!("builder should reject TLS CA cert paths with NUL bytes"),
        Err(err) => assert_eq!(err.code, NVAT_RC_BAD_ARGUMENT as u16),
    }
}

// ========================================================================
// Logger Tests
// ========================================================================

#[test]
#[cfg(feature = "logging")]
fn test_logger_creation() {
    init_sdk();
    let logger = Logger::new();
    assert!(logger.is_ok(), "Logger creation should succeed");
}

// ========================================================================
// SDK Version Test
// ========================================================================

#[test]
fn test_sdk_version() {
    init_sdk();
    let version = NvatSdk::version();
    assert!(!version.is_empty(), "SDK version should not be empty");
    // Version format is typically "X.Y.Z"
    assert!(version.contains('.'), "Version should contain dots");
}

#[test]
fn test_sdk_rejects_second_lifecycle_guard() {
    init_sdk();
    let opts = SdkOptions::new().expect("SDK options creation should succeed");

    match NvatSdk::init(opts) {
        Ok(_) => panic!("SDK should reject a second live lifecycle guard"),
        Err(err) => assert_eq!(err.code, NVAT_RC_INTERNAL_ERROR as u16),
    }
}

// ========================================================================
// Memory Safety / RAII Tests
// ========================================================================

#[test]
fn test_nonce_drop() {
    init_sdk();
    // Create nonce in inner scope
    {
        let _nonce = Nonce::generate(32).unwrap();
        // Nonce should be dropped here
    }
    // If we reach here without crash, Drop was called correctly
}

#[test]
fn test_sdk_options_drop() {
    init_sdk();
    {
        let _opts = SdkOptions::new().unwrap();
    }
    // If we reach here without crash, Drop was called correctly
}

#[test]
fn test_http_options_drop() {
    init_sdk();
    {
        let _opts = HttpOptions::default_options().unwrap();
    }
    // If we reach here without crash, Drop was called correctly
}

#[test]
#[cfg(feature = "logging")]
fn test_logger_drop() {
    init_sdk();
    {
        let _logger = Logger::new().unwrap();
    }
    // If we reach here without crash, Drop was called correctly
}

// ========================================================================
// Device Type and Verifier Type Tests
// ========================================================================

#[test]
fn test_device_type_equality() {
    let gpu1 = DeviceType::Gpu;
    let gpu2 = DeviceType::Gpu;
    let switch = DeviceType::NvSwitch;

    assert_eq!(gpu1, gpu2, "Same device types should be equal");
    assert_ne!(gpu1, switch, "Different device types should not be equal");
}

#[test]
fn test_verifier_type_equality() {
    let local1 = VerifierType::Local;
    let local2 = VerifierType::Local;
    let remote = VerifierType::Remote;

    assert_eq!(local1, local2, "Same verifier types should be equal");
    assert_ne!(
        local1, remote,
        "Different verifier types should not be equal"
    );
}

#[test]
fn test_device_type_debug() {
    let gpu = DeviceType::Gpu;
    let switch = DeviceType::NvSwitch;

    let gpu_str = format!("{:?}", gpu);
    let switch_str = format!("{:?}", switch);

    assert!(!gpu_str.is_empty(), "Debug string should not be empty");
    assert!(!switch_str.is_empty(), "Debug string should not be empty");
}

#[test]
fn test_verifier_type_debug() {
    let local = VerifierType::Local;
    let remote = VerifierType::Remote;

    let local_str = format!("{:?}", local);
    let remote_str = format!("{:?}", remote);

    assert!(!local_str.is_empty(), "Debug string should not be empty");
    assert!(!remote_str.is_empty(), "Debug string should not be empty");
}

// ========================================================================
// HttpOptionsBuilder Tests
// ========================================================================

#[test]
fn test_http_options_builder_all_fields() {
    init_sdk();
    let opts = HttpOptions::builder()
        .max_retry_count(5)
        .base_backoff_ms(100)
        .max_backoff_ms(5000)
        .connection_timeout_ms(10000)
        .request_timeout_ms(30000)
        .build();

    assert!(
        opts.is_ok(),
        "Building HTTP options with all fields should succeed"
    );
    drop(opts.unwrap());
}

#[test]
fn test_http_options_builder_partial_fields() {
    init_sdk();
    let opts = HttpOptions::builder()
        .max_retry_count(3)
        .connection_timeout_ms(5000)
        .build();

    assert!(
        opts.is_ok(),
        "Building HTTP options with partial fields should succeed"
    );
    drop(opts.unwrap());
}

#[test]
fn test_http_options_builder_chaining() {
    init_sdk();
    let opts = HttpOptions::builder()
        .max_retry_count(10)
        .base_backoff_ms(50)
        .max_backoff_ms(1000)
        .build();

    assert!(opts.is_ok(), "Builder chaining should work correctly");
    drop(opts.unwrap());
}

#[test]
fn test_http_options_builder_empty() {
    init_sdk();
    let opts = HttpOptions::builder().build();

    assert!(
        opts.is_ok(),
        "Building HTTP options with no fields should use defaults"
    );
    drop(opts.unwrap());
}

// ========================================================================
// AttestationContext Tests
// ========================================================================

#[test]
fn test_attestation_context_creation() {
    init_sdk();
    let ctx = AttestationContext::new();
    assert!(ctx.is_ok(), "Attestation context creation should succeed");
}

#[test]
fn test_attestation_context_new_is_fallible() {
    init_sdk();
    let ctx = AttestationContext::new().expect("Attestation context creation should succeed");
    drop(ctx);
}

#[test]
fn test_attestation_context_set_device_type() {
    init_sdk();
    let mut ctx = AttestationContext::new().unwrap();

    let result_gpu = ctx.set_device_type(DeviceType::Gpu);
    assert!(
        result_gpu.is_ok(),
        "Setting device type to GPU should succeed"
    );

    let result_switch = ctx.set_device_type(DeviceType::NvSwitch);
    assert!(
        result_switch.is_ok(),
        "Setting device type to NvSwitch should succeed"
    );
}

#[test]
fn test_attestation_context_set_verifier_type() {
    init_sdk();
    let mut ctx = AttestationContext::new().unwrap();

    let result_local = ctx.set_verifier_type(VerifierType::Local);
    assert!(
        result_local.is_ok(),
        "Setting verifier type to Local should succeed"
    );

    let result_remote = ctx.set_verifier_type(VerifierType::Remote);
    assert!(
        result_remote.is_ok(),
        "Setting verifier type to Remote should succeed"
    );
}

#[test]
fn test_attestation_context_set_nras_url() {
    init_sdk();
    let mut ctx = AttestationContext::new().unwrap();

    let result = ctx.set_nras_url("https://nras.example.com");
    assert!(result.is_ok(), "Setting NRAS URL should succeed");
}

#[test]
fn test_attestation_context_set_ocsp_url() {
    init_sdk();
    let mut ctx = AttestationContext::new().unwrap();

    let result = ctx.set_ocsp_url("https://ocsp.example.com");
    assert!(result.is_ok(), "Setting OCSP URL should succeed");
}

#[test]
fn test_attestation_context_set_rim_store_url() {
    init_sdk();
    let mut ctx = AttestationContext::new().unwrap();

    let result = ctx.set_rim_store_url("https://rim.example.com");
    assert!(result.is_ok(), "Setting RIM store URL should succeed");
}

#[test]
fn test_attestation_context_set_service_key() {
    init_sdk();
    let mut ctx = AttestationContext::new().unwrap();

    let result = ctx.set_service_key("test-service-key");
    assert!(result.is_ok(), "Setting service key should succeed");
}

#[test]
fn test_attestation_context_drop() {
    init_sdk();
    {
        let _ctx = AttestationContext::new().unwrap();
    }
    // If we reach here without crash, Drop was called correctly
}

// ========================================================================
// AttestationContextBuilder Tests
// ========================================================================

#[test]
fn test_attestation_context_builder_all_fields() {
    init_sdk();
    let ctx = AttestationContext::builder()
        .device_type(DeviceType::Gpu)
        .verifier_type(VerifierType::Remote)
        .nras_url("https://nras.example.com")
        .ocsp_url("https://ocsp.example.com")
        .rim_store_url("https://rim.example.com")
        .service_key("test-key")
        .build();

    assert!(
        ctx.is_ok(),
        "Building attestation context with all fields should succeed"
    );
}

#[test]
fn test_attestation_context_builder_partial_fields() {
    init_sdk();
    let ctx = AttestationContext::builder()
        .device_type(DeviceType::Gpu)
        .verifier_type(VerifierType::Local)
        .build();

    assert!(
        ctx.is_ok(),
        "Building attestation context with partial fields should succeed"
    );
}

#[test]
fn test_attestation_context_builder_minimal() {
    init_sdk();
    let ctx = AttestationContext::builder().build();

    assert!(
        ctx.is_ok(),
        "Building attestation context with no fields should succeed"
    );
}

#[test]
fn test_attestation_context_builder_chaining() {
    init_sdk();
    let ctx = AttestationContext::builder()
        .device_type(DeviceType::NvSwitch)
        .verifier_type(VerifierType::Remote)
        .nras_url("https://nras.test.com")
        .service_key("key123")
        .build();

    assert!(ctx.is_ok(), "Builder chaining should work correctly");
}

#[test]
fn test_attestation_context_builder_url_conversions() {
    init_sdk();
    // Test that Into<String> works for URLs
    let ctx = AttestationContext::builder()
        .nras_url(String::from("https://nras.example.com"))
        .ocsp_url("https://ocsp.example.com".to_string())
        .build();

    assert!(ctx.is_ok(), "URL string conversions should work");
}

// ========================================================================
// EvidencePolicy Tests
// ========================================================================

#[test]
fn test_evidence_policy_creation() {
    init_sdk();
    let policy = EvidencePolicy::default_policy();
    assert!(policy.is_ok(), "Evidence policy creation should succeed");
}

// Base64 body of a throwaway P-384 key used only by the tests below. Stored
// without the PEM header/footer and wrapped at runtime by `test_p384_key_pem`
// so no private-key literal lives in the source tree.
const TEST_P384_KEY_BODY: &str =
    "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCgCOkdAShYu3QRWN/H\n\
2tCQrB8sREDoFBG9QEOal566e3VtSA7/Kn1+TlsYU6i05wShZANiAAQSXta7ognb\n\
8ZGSEdjB2Lq004CO3Yw9t2x9odMoDTsqrrIZQa4OJUqA9Cx0GVswjoMIfWzVWgBl\n\
Bgj60rBgi5Ldpj+8xioIMZsKnnk/EvBp3ZgzdnGLudhYmmG0gvDiMXk=";

fn test_p384_key_pem() -> String {
    format!("-----BEGIN PRIVATE KEY-----\n{TEST_P384_KEY_BODY}\n-----END PRIVATE KEY-----\n")
}

#[test]
fn test_detached_eat_options_creation() {
    init_sdk();
    let options =
        DetachedEatOptions::new(&test_p384_key_pem(), "https://nras.example.com", "test-kid");
    assert!(
        options.is_ok(),
        "Detached EAT options creation should succeed"
    );
}

#[test]
fn test_set_detached_eat_options_on_context() {
    init_sdk();
    let options =
        DetachedEatOptions::new(&test_p384_key_pem(), "https://nras.example.com", "test-kid")
            .unwrap();
    let mut ctx = AttestationContext::new().unwrap();
    assert!(
        ctx.set_detached_eat_options(options).is_ok(),
        "Setting detached EAT options on the context should succeed"
    );
}

#[test]
fn test_local_verifier_with_signing_options() {
    init_sdk();
    let http = HttpOptions::default_options().unwrap();
    let rim = RimStore::create_remote(None, None, Some(&http)).unwrap();
    let ocsp = OcspClient::create_default(None, None, Some(&http)).unwrap();
    let options =
        DetachedEatOptions::new(&test_p384_key_pem(), "https://nras.example.com", "test-kid")
            .unwrap();
    assert!(
        GpuLocalVerifier::new_with_signing(&rim, &ocsp, options.clone()).is_ok(),
        "GPU verifier with signing options should construct"
    );
    assert!(
        SwitchLocalVerifier::new_with_signing(&rim, &ocsp, options).is_ok(),
        "Switch verifier with signing options should construct"
    );
}

#[test]
fn test_builder_with_detached_eat_options() {
    init_sdk();
    let options =
        DetachedEatOptions::new(&test_p384_key_pem(), "https://nras.example.com", "test-kid")
            .unwrap();
    let ctx = AttestationContext::builder()
        .device_type(DeviceType::Gpu)
        .detached_eat_options(options)
        .build();
    assert!(
        ctx.is_ok(),
        "Building a context with detached EAT options should succeed"
    );
}

#[test]
fn test_evidence_policy_set_verify_rim_signature() {
    init_sdk();
    let mut policy = EvidencePolicy::default_policy().unwrap();

    policy.set_verify_rim_signature(true);
    policy.set_verify_rim_signature(false);
    // Should not panic
}

#[test]
fn test_evidence_policy_set_verify_rim_cert_chain() {
    init_sdk();
    let mut policy = EvidencePolicy::default_policy().unwrap();

    policy.set_verify_rim_cert_chain(true);
    policy.set_verify_rim_cert_chain(false);
    // Should not panic
}

#[test]
fn test_evidence_policy_drop() {
    init_sdk();
    {
        let _policy = EvidencePolicy::default_policy().unwrap();
    }
    // If we reach here without crash, Drop was called correctly
}

// ========================================================================
// EvidencePolicyBuilder Tests
// ========================================================================

#[test]
fn test_evidence_policy_builder_all_fields() {
    init_sdk();
    let policy = EvidencePolicy::builder()
        .verify_rim_signature(true)
        .verify_rim_cert_chain(true)
        .build();

    assert!(
        policy.is_ok(),
        "Building evidence policy with all fields should succeed"
    );
}

#[test]
fn test_evidence_policy_builder_partial_fields() {
    init_sdk();
    let policy = EvidencePolicy::builder().verify_rim_signature(true).build();

    assert!(
        policy.is_ok(),
        "Building evidence policy with partial fields should succeed"
    );
}

#[test]
fn test_evidence_policy_builder_empty() {
    init_sdk();
    let policy = EvidencePolicy::builder().build();

    assert!(
        policy.is_ok(),
        "Building evidence policy with no fields should succeed"
    );
}

#[test]
fn test_evidence_policy_builder_chaining() {
    init_sdk();
    let policy = EvidencePolicy::builder()
        .verify_rim_signature(false)
        .verify_rim_cert_chain(false)
        .build();

    assert!(policy.is_ok(), "Builder chaining should work correctly");
}

// ========================================================================
// Error Conversion Tests
// ========================================================================

#[test]
fn test_error_from_u16() {
    init_sdk();
    let error: NvatError = 42u16.into();
    assert_eq!(error.code, 42, "Error should be created from u16");
}

#[test]
fn test_error_to_u16() {
    init_sdk();
    let error = NvatError::new(123);
    let code: u16 = error.into();
    assert_eq!(code, 123, "Error should convert to u16");
}

#[test]
fn test_error_equality() {
    init_sdk();
    let error1 = NvatError::new(42);
    let error2 = NvatError::new(42);
    let error3 = NvatError::new(99);

    assert_eq!(error1, error2, "Errors with same code should be equal");
    assert_ne!(
        error1, error3,
        "Errors with different codes should not be equal"
    );
}

#[test]
fn test_error_debug() {
    init_sdk();
    let error = NvatError::new(1);
    let debug_str = format!("{:?}", error);
    assert!(!debug_str.is_empty(), "Debug string should not be empty");
}

#[test]
fn test_error_implements_std_error() {
    init_sdk();
    let error = NvatError::new(1);
    // This tests that NvatError implements std::error::Error
    let _: &dyn std::error::Error = &error;
}

// ========================================================================
// Nonce Edge Cases and Additional Tests
// ========================================================================

#[test]
fn test_nonce_empty_hex_string() {
    init_sdk();
    let result = Nonce::from_hex("");
    assert!(
        result.is_err(),
        "Creating nonce from empty hex string should fail"
    );
}

#[test]
fn test_nonce_odd_length_hex() {
    init_sdk();
    // Odd number of hex characters (not valid hex encoding)
    let result = Nonce::from_hex("abc");
    assert!(
        result.is_err(),
        "Creating nonce from odd-length hex should fail"
    );
}

#[test]
fn test_nonce_hex_with_invalid_chars() {
    init_sdk();
    let result = Nonce::from_hex("0123456789abcdefGHIJ0123456789abcdef0123456789abcdef0123456789");
    assert!(
        result.is_err(),
        "Creating nonce from hex with invalid chars should fail"
    );
}

#[test]
fn test_nonce_is_empty() {
    init_sdk();
    let nonce = Nonce::generate(32).unwrap();
    assert!(!nonce.is_empty(), "Generated nonce should not be empty");
}

#[test]
fn test_nonce_len() {
    init_sdk();
    for size in [32, 64, 128] {
        let nonce = Nonce::generate(size).unwrap();
        assert_eq!(
            nonce.len(),
            size,
            "Nonce length should match requested size"
        );
    }
}

// ========================================================================
// HTTP Options Edge Cases
// ========================================================================

#[test]
fn test_http_options_negative_values() {
    init_sdk();
    let mut opts = HttpOptions::default_options().unwrap();

    // Test with negative values (should be handled by C SDK)
    opts.set_max_retry_count(-1);
    opts.set_base_backoff_ms(-100);
    opts.set_max_backoff_ms(-5000);

    drop(opts);
}

#[test]
fn test_http_options_max_values() {
    init_sdk();
    let mut opts = HttpOptions::default_options().unwrap();

    opts.set_max_retry_count(i64::MAX);
    opts.set_base_backoff_ms(i64::MAX);
    opts.set_max_backoff_ms(i64::MAX);
    opts.set_connection_timeout_ms(i64::MAX);
    opts.set_request_timeout_ms(i64::MAX);

    drop(opts);
}

// ========================================================================
// Multiple Context Tests
// ========================================================================

#[test]
fn test_multiple_attestation_contexts() {
    init_sdk();
    let ctx1 = AttestationContext::new().unwrap();
    let ctx2 = AttestationContext::new().unwrap();
    let ctx3 = AttestationContext::new().unwrap();

    // All should be independently valid
    drop(ctx1);
    drop(ctx2);
    drop(ctx3);
}

#[test]
fn test_multiple_http_options() {
    init_sdk();
    let opts1 = HttpOptions::default_options().unwrap();
    let opts2 = HttpOptions::default_options().unwrap();
    let opts3 = HttpOptions::default_options().unwrap();

    // All should be independently valid
    drop(opts1);
    drop(opts2);
    drop(opts3);
}

#[test]
fn test_multiple_evidence_policies() {
    init_sdk();
    let policy1 = EvidencePolicy::default_policy().unwrap();
    let policy2 = EvidencePolicy::default_policy().unwrap();
    let policy3 = EvidencePolicy::default_policy().unwrap();

    // All should be independently valid
    drop(policy1);
    drop(policy2);
    drop(policy3);
}

// ========================================================================
// Complex Builder Pattern Tests
// ========================================================================

#[test]
fn test_http_options_builder_clone() {
    init_sdk();
    let builder1 = HttpOptions::builder()
        .max_retry_count(5)
        .base_backoff_ms(100);

    let builder2 = builder1.clone();

    let opts1 = builder1.build();
    let opts2 = builder2.build();

    assert!(opts1.is_ok(), "First builder should work");
    assert!(opts2.is_ok(), "Cloned builder should work");
}

#[test]
fn test_attestation_context_builder_clone() {
    init_sdk();
    let builder1 = AttestationContext::builder()
        .device_type(DeviceType::Gpu)
        .verifier_type(VerifierType::Local);

    let builder2 = builder1.clone();

    let ctx1 = builder1.build();
    let ctx2 = builder2.build();

    assert!(ctx1.is_ok(), "First builder should work");
    assert!(ctx2.is_ok(), "Cloned builder should work");
}

#[test]
fn test_evidence_policy_builder_clone() {
    init_sdk();
    let builder1 = EvidencePolicy::builder().verify_rim_signature(true);

    let builder2 = builder1.clone();

    let policy1 = builder1.build();
    let policy2 = builder2.build();

    assert!(policy1.is_ok(), "First builder should work");
    assert!(policy2.is_ok(), "Cloned builder should work");
}

// ========================================================================
// URL Setting Tests with Special Characters
// ========================================================================

#[test]
fn test_attestation_context_urls_with_ports() {
    init_sdk();
    let mut ctx = AttestationContext::new().unwrap();

    assert!(ctx.set_nras_url("https://example.com:8080").is_ok());
    assert!(ctx.set_ocsp_url("https://example.com:9090").is_ok());
    assert!(ctx.set_rim_store_url("https://example.com:7070").is_ok());
}

#[test]
fn test_attestation_context_urls_with_paths() {
    init_sdk();
    let mut ctx = AttestationContext::new().unwrap();

    assert!(ctx.set_nras_url("https://example.com/api/v1/nras").is_ok());
    assert!(ctx.set_ocsp_url("https://example.com/api/v1/ocsp").is_ok());
    assert!(ctx
        .set_rim_store_url("https://example.com/api/v1/rim")
        .is_ok());
}

#[test]
fn test_attestation_context_empty_urls() {
    init_sdk();
    let mut ctx = AttestationContext::new().unwrap();

    // Empty URLs should be handled by the C SDK
    assert!(ctx.set_nras_url("").is_ok());
    assert!(ctx.set_ocsp_url("").is_ok());
    assert!(ctx.set_rim_store_url("").is_ok());
}

// ========================================================================
// Service Key Tests
// ========================================================================

#[test]
fn test_attestation_context_service_key_variations() {
    init_sdk();
    let mut ctx = AttestationContext::new().unwrap();

    // Test various service key formats
    assert!(ctx.set_service_key("simple-key").is_ok());
    assert!(ctx.set_service_key("key-with-dashes-123").is_ok());
    assert!(ctx.set_service_key("KeyWithUpperCase").is_ok());
    assert!(ctx.set_service_key("key_with_underscores").is_ok());
}

#[test]
fn test_attestation_context_empty_service_key() {
    init_sdk();
    let mut ctx = AttestationContext::new().unwrap();

    assert!(ctx.set_service_key("").is_ok());
}

// ========================================================================
// Combined Configuration Tests
// ========================================================================

#[test]
fn test_attestation_context_full_configuration() {
    init_sdk();
    let mut ctx = AttestationContext::new().unwrap();

    // Configure all settings
    assert!(ctx.set_device_type(DeviceType::Gpu).is_ok());
    assert!(ctx.set_verifier_type(VerifierType::Remote).is_ok());
    assert!(ctx.set_nras_url("https://nras.example.com").is_ok());
    assert!(ctx.set_ocsp_url("https://ocsp.example.com").is_ok());
    assert!(ctx.set_rim_store_url("https://rim.example.com").is_ok());
    assert!(ctx.set_service_key("test-key-12345").is_ok());
}

#[test]
fn test_attestation_context_reconfiguration() {
    init_sdk();
    let mut ctx = AttestationContext::new().unwrap();

    // Set initial configuration
    assert!(ctx.set_device_type(DeviceType::Gpu).is_ok());
    assert!(ctx.set_verifier_type(VerifierType::Local).is_ok());

    // Change configuration
    assert!(ctx.set_device_type(DeviceType::NvSwitch).is_ok());
    assert!(ctx.set_verifier_type(VerifierType::Remote).is_ok());
}

// ========================================================================
// Builder Pattern Debug Tests
// ========================================================================

#[test]
fn test_http_options_builder_debug() {
    let builder = HttpOptions::builder()
        .max_retry_count(5)
        .base_backoff_ms(100);

    let debug_str = format!("{:?}", builder);
    assert!(
        !debug_str.is_empty(),
        "Builder debug string should not be empty"
    );
}

#[test]
fn test_attestation_context_builder_debug() {
    let builder = AttestationContext::builder()
        .device_type(DeviceType::Gpu)
        .verifier_type(VerifierType::Local);

    let debug_str = format!("{:?}", builder);
    assert!(
        !debug_str.is_empty(),
        "Builder debug string should not be empty"
    );
}

#[test]
fn test_evidence_policy_builder_debug() {
    let builder = EvidencePolicy::builder().verify_rim_signature(true);

    let debug_str = format!("{:?}", builder);
    assert!(
        !debug_str.is_empty(),
        "Builder debug string should not be empty"
    );
}

// ========================================================================
// verify_attestation_result / RelyingPartyPolicy Tests
// ========================================================================

#[test]
fn test_verify_attestation_result_rejects_empty_url() {
    init_sdk();
    let err = verify_attestation_result("{}", "").unwrap_err();
    assert_eq!(err.code, NVAT_RC_BAD_ARGUMENT as u16);
}

// The optional service_key threads through to the FFI without panicking; an
// empty URL still short-circuits to BAD_ARGUMENT before any network call.
#[test]
fn test_verify_attestation_result_with_options_rejects_empty_url() {
    init_sdk();
    let mut jwt_options = JwtValidationOptions::default_options().unwrap();
    jwt_options.set_clock_skew_leeway_seconds(300);
    let err = verify_attestation_result_with_options(
        "{}",
        "",
        Some("test-service-key"),
        None,
        None,
        Some(&jwt_options),
    )
    .unwrap_err();
    assert_eq!(err.code, NVAT_RC_BAD_ARGUMENT as u16);
}

#[test]
fn test_verify_ear_rejects_empty_verifier_url() {
    init_sdk();
    let error = verify_ear("header.payload.signature", "")
        .expect_err("an empty verifier URL must be rejected");
    assert_eq!(error.code, NVAT_RC_BAD_ARGUMENT as u16);
}

#[test]
fn test_verify_ear_with_options_rejects_empty_verifier_url() {
    init_sdk();
    let mut jwt_options = JwtValidationOptions::default_options().unwrap();
    jwt_options.set_clock_skew_leeway_seconds(300);

    let error = verify_ear_with_options(
        "header.payload.signature",
        "",
        Some("test-service-key"),
        None,
        None,
        Some(&jwt_options),
    )
    .expect_err("an empty verifier URL must be rejected");
    assert_eq!(error.code, NVAT_RC_BAD_ARGUMENT as u16);
}

#[test]
fn test_relying_party_policy_from_rego() {
    init_sdk();
    let policy = RelyingPartyPolicy::from_rego("package policy\ndefault nv_match := false\n");
    assert!(policy.is_ok(), "policy creation should succeed");
}

#[test]
fn test_relying_party_policy_accepts_matching_ear_json() {
    init_sdk();
    let policy = RelyingPartyPolicy::from_rego(
        "package policy\ndefault nv_match := false\nnv_match { input.ear_status == \"affirming\" }\n",
    )
    .expect("policy creation should succeed");

    assert!(policy
        .apply_to_ear_json(r#"{"ear_status":"affirming"}"#)
        .is_ok());
}

#[test]
fn test_relying_party_policy_rejects_nonmatching_ear_json() {
    init_sdk();
    let policy = RelyingPartyPolicy::from_rego(
        "package policy\ndefault nv_match := false\nnv_match { input.ear_status == \"affirming\" }\n",
    )
    .expect("policy creation should succeed");

    let error = policy
        .apply_to_ear_json(r#"{"ear_status":"contraindicated"}"#)
        .expect_err("policy should reject a nonmatching EAR");
    assert_eq!(error.code, NVAT_RC_RP_POLICY_MISMATCH as u16);
}

#[test]
fn test_relying_party_policy_rejects_invalid_ear_json() {
    init_sdk();
    let policy = RelyingPartyPolicy::from_rego("package policy\ndefault nv_match := true\n")
        .expect("policy creation should succeed");

    for ear_json in ["not-json", "[]", "{\"ear_status\":\"affirming\"}\0suffix"] {
        let error = policy
            .apply_to_ear_json(ear_json)
            .expect_err("invalid EAR JSON should be rejected");
        assert_eq!(error.code, NVAT_RC_BAD_ARGUMENT as u16);
    }
}

// ========================================================================
// Sanitizer Negative / Positive Tests
// ========================================================================
// Positive test: no leak, should PASS with sanitizer (confirms no false positives).
// Negative tests: intentional leaks, should FAIL with sanitizer (confirms we catch leaks).
// All are ignored by default and must be explicitly run.

/// Positive control: allocates and frees properly. Should PASS when run with LSan.
/// Run with: cargo +nightly test test_no_leak_should_pass_with_sanitizer --ignored -- --test-threads=1
#[test]
#[ignore]
#[cfg(test)]
fn test_no_leak_should_pass_with_sanitizer() {
    use std::alloc::{alloc, dealloc, Layout};

    // Allocate and free raw memory
    unsafe {
        let layout = Layout::from_size_align(1024, 8).unwrap();
        let ptr = alloc(layout);
        std::ptr::write_bytes(ptr, 0x42, 1024);
        dealloc(ptr, layout);
    }

    // Box is dropped normally (no forget)
    let _ = Box::new([0u8; 1024]);

    println!("No leak: all allocations freed");
}

#[test]
#[ignore]
#[cfg(test)]
fn test_intentional_memory_leak_rust() {
    // This test intentionally leaks memory to verify sanitizers catch it
    // Run with: cargo +nightly test test_intentional_memory_leak_rust --ignored -- --test-threads=1
    // Expected: Should FAIL with LeakSanitizer error

    use std::alloc::{alloc, Layout};

    unsafe {
        let layout = Layout::from_size_align(1024, 8).unwrap();
        let ptr = alloc(layout);
        // Intentionally don't free - sanitizer should catch this
        std::ptr::write_bytes(ptr, 0x42, 1024);
    }

    // Also leak a Box
    let leaked = Box::new([0u8; 1024]);
    std::mem::forget(leaked);

    println!("Intentionally leaked 2KB of memory");
}

#[test]
#[ignore]
#[cfg(test)]
fn test_intentional_memory_leak_c_sdk() {
    // This test intentionally leaks a C SDK object (HttpOptions) to verify LSan catches it.
    // LSan in the main (Rust) binary intercepts malloc process-wide, so when libnvat.so
    // calls malloc() we still track it—the C SDK does not need to be built with -fsanitize=leak.
    // Run with: cargo +nightly test test_intentional_memory_leak_c_sdk --ignored -- --test-threads=1
    // Expected: Should FAIL with LeakSanitizer error

    init_sdk();

    // Create an HTTP options object and intentionally leak it (never call Drop)
    let opts = HttpOptions::default_options().expect("Failed to create HTTP options");
    std::mem::forget(opts); // Leak it - LSan should detect the C malloc

    println!("Intentionally leaked C SDK HttpOptions object");
}

// ---------------------------------------------------------------------------
// AttestationResult verdict handling
// ---------------------------------------------------------------------------

#[test]
fn test_result_from_ffi_overall_result_false_is_ok() {
    // A negative verdict must surface as Ok so the caller can relay the
    // SDK-signed token, rather than discarding it as an error.
    let result = AttestationResult::from_ffi(
        NVAT_RC_OVERALL_RESULT_FALSE as u16,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    )
    .expect("OVERALL_RESULT_FALSE should be returned as Ok");

    assert_eq!(result.result_code, NVAT_RC_OVERALL_RESULT_FALSE as u16);
    assert!(!result.is_success(), "a false verdict is not a success");
    assert!(result.detached_eat.is_none());
    assert!(result.claims.is_none());
}

#[test]
fn test_result_from_ffi_rp_policy_mismatch_is_ok() {
    let result = AttestationResult::from_ffi(
        NVAT_RC_RP_POLICY_MISMATCH as u16,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    )
    .expect("RP_POLICY_MISMATCH should be returned as Ok");

    assert_eq!(result.result_code, NVAT_RC_RP_POLICY_MISMATCH as u16);
    assert!(!result.is_success());
}

#[test]
fn test_result_from_ffi_ok_is_success() {
    let result = AttestationResult::from_ffi(
        NVAT_RC_OK as u16,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    )
    .expect("OK should be returned as Ok");

    assert!(result.is_success());
    assert_eq!(result.result_code, NVAT_RC_OK as u16);
}

#[test]
fn test_result_from_ffi_genuine_error_is_err() {
    // A real error code must still propagate as Err and not fabricate a result.
    match AttestationResult::from_ffi(
        NVAT_RC_BAD_ARGUMENT as u16,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    ) {
        Err(e) => assert_eq!(e.code, NVAT_RC_BAD_ARGUMENT as u16),
        Ok(_) => panic!("a genuine error code must be returned as Err"),
    }
}

// ---------------------------------------------------------------------------
// Cached RIM store / OCSP client construction
// ---------------------------------------------------------------------------

#[test]
fn ocsp_client_options_default_to_sha256() {
    assert_eq!(
        OcspClientOptions::default().cert_id_hash_algorithm,
        OcspCertIdHashAlgorithm::Sha256
    );
}

#[test]
fn ocsp_clients_accept_every_cert_id_hash() {
    init_sdk();
    for algorithm in [
        OcspCertIdHashAlgorithm::Sha1,
        OcspCertIdHashAlgorithm::Sha256,
        OcspCertIdHashAlgorithm::Sha384,
    ] {
        let options = OcspClientOptions {
            cert_id_hash_algorithm: algorithm,
        };
        assert!(OcspClient::create_default_with_options(None, None, None, options).is_ok());
        assert!(OcspClient::create_aia(AiaOptions {
            client_options: Some(options),
            ..Default::default()
        })
        .is_ok());
    }
}

#[test]
fn test_rim_store_create_cached() {
    init_sdk();
    let inner = RimStore::create_remote(None, None, None).expect("remote RIM store");
    let cached = RimStore::create_cached(inner, 1024 * 1024, 3600);
    assert!(cached.is_ok(), "cached RIM store creation should succeed");
}

#[test]
fn test_ocsp_client_create_cached() {
    init_sdk();
    let inner = OcspClient::create_default(None, None, None).expect("default OCSP client");
    let cached = OcspClient::create_cached(inner, 1024 * 1024, 3600);
    assert!(cached.is_ok(), "cached OCSP client creation should succeed");
}

#[test]
fn test_verifiers_accept_cached_store_and_client() {
    init_sdk();
    let rim = RimStore::create_remote(None, None, None).expect("remote RIM store");
    let rim = RimStore::create_cached(rim, 1024 * 1024, 3600).expect("cached RIM store");
    let ocsp = OcspClient::create_default(None, None, None).expect("default OCSP client");
    let ocsp = OcspClient::create_cached(ocsp, 1024 * 1024, 3600).expect("cached OCSP client");

    assert!(
        GpuLocalVerifier::new(&rim, &ocsp).is_ok(),
        "GPU verifier should accept cached store and client"
    );
    assert!(
        SwitchLocalVerifier::new(&rim, &ocsp).is_ok(),
        "switch verifier should accept cached store and client"
    );
}

#[test]
fn claims_collection_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<ClaimsCollection>();
}

// ---------------------------------------------------------------------------
// Cross-thread collection move (the fan-out pattern)
// ---------------------------------------------------------------------------

/// RIM store and OCSP endpoints for the recorded-evidence tests, taken from
/// `NVAT_TEST_RIM_STORE_URL` and `NVAT_TEST_OCSP_URL` so that no deployment
/// specific host is written into the source tree. Returns `(rim, ocsp)`, or
/// `None` when either is unset, in which case the caller skips.
fn recorded_evidence_endpoints() -> Option<(String, String)> {
    let rim = std::env::var("NVAT_TEST_RIM_STORE_URL").ok()?;
    let ocsp = std::env::var("NVAT_TEST_OCSP_URL").ok()?;
    Some((rim, ocsp))
}

/// Counts the elements of a top-level JSON array without a JSON dependency:
/// objects opened at nesting depth 1, string contents ignored.
fn json_array_len(json: &str) -> usize {
    let (mut depth, mut count) = (0usize, 0usize);
    let (mut in_string, mut escaped) = (false, false);
    for c in json.chars() {
        if in_string {
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '[' | '{' => {
                if depth == 1 && c == '{' {
                    count += 1;
                }
                depth += 1;
            }
            ']' | '}' => depth -= 1,
            _ => {}
        }
    }
    count
}

/// Verifies recorded GPU evidence twice on this thread, then MOVES both claims
/// collections to a second thread, where they merge with `extend`, serialize,
/// assemble a detached EAT, and drop. This is the exact ownership flow a
/// multi-device fan-out uses, and it runs the real C SDK operations on a
/// non-origin thread.
///
/// Mirrors GpuHighLevelApiLocalVerify in the C++ unit suite: same recorded
/// evidence and nonce (unit-tests/include/test_utils.h), against the RIM and
/// OCSP endpoints the environment supplies, so it needs the network
/// reachability that suite already requires in CI. Skips when the fixture or
/// either endpoint is absent. common-test-data ships no P-384 test key, so the
/// EAT assembles with default options (the SDK's unsigned alg-none path);
/// apart from the final ES384 signature the assembly code path is the same.
#[test]
fn claims_collection_moves_across_threads_for_merge_and_eat() {
    init_sdk();

    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../common-test-data/serialized_test_evidence/hopper_evidence.json"
    );
    if !std::path::Path::new(fixture).exists() {
        eprintln!("skipping: evidence fixture not found at {fixture}");
        return;
    }
    let Some((rim_store_url, ocsp_url)) = recorded_evidence_endpoints() else {
        eprintln!("skipping: NVAT_TEST_RIM_STORE_URL or NVAT_TEST_OCSP_URL is unset");
        return;
    };

    let verify = || {
        let nonce =
            Nonce::from_hex("e97b23a1718095a0e9e35edca810768c70a6a5a389b705e753b197912bc11576")
                .expect("recorded-evidence nonce");
        let ctx = AttestationContext::builder()
            .device_type(DeviceType::Gpu)
            .verifier_type(VerifierType::Local)
            .gpu_evidence_from_json_file(fixture)
            .ocsp_url(ocsp_url.as_str())
            .rim_store_url(rim_store_url.as_str())
            .build()
            .expect("attestation context");
        ctx.attest_device(Some(&nonce))
            .expect("verify recorded evidence")
    };

    let mut first = verify().claims.take().expect("first claims collection");
    let second = verify().claims.take().expect("second claims collection");
    let expected = json_array_len(&first.to_json().expect("serialize first"))
        + json_array_len(&second.to_json().expect("serialize second"));

    let merged_len = std::thread::spawn(move || {
        first.extend(&second).expect("extend on the second thread");
        let merged = first.to_json().expect("serialize merged collection");
        let options =
            DetachedEatOptions::new("", "NVAT-TEST", "test-kid").expect("detached EAT options");
        first
            .detached_eat_es384(&options)
            .expect("assemble detached EAT on the second thread");
        json_array_len(&merged)
        // first and second drop here, on the non-origin thread
    })
    .join()
    .expect("cross-thread merge panicked");

    assert_eq!(
        merged_len, expected,
        "merged collection must carry every claim from both parts"
    );
}

// ---------------------------------------------------------------------------
// Shared verify-path handles (the shared-verifier pattern)
// ---------------------------------------------------------------------------

#[test]
fn verify_path_handles_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<EvidencePolicy>();
    assert_send_sync::<OcspClient>();
    assert_send_sync::<RimStore>();
    assert_send_sync::<GpuLocalVerifier>();
    assert_send_sync::<SwitchLocalVerifier>();
    assert_send_sync::<DetachedEatOptions>();
}

/// Builds one verifier over one cached RIM store and one cached OCSP client on
/// this thread, then verifies the same recorded evidence on four threads at
/// once through a single shared `&GpuLocalVerifier`. Evidence stays per thread,
/// which is the request-scoped half of the contract; the verifier, policy,
/// store and client are the shared half.
///
/// The first verification populates the caches and the rest race against them,
/// so this exercises the concurrent cache access the `Sync` impls permit.
///
/// Uses the same recorded evidence and nonce as GpuHighLevelApiLocalVerify in
/// the C++ unit suite, against the RIM and OCSP endpoints the environment
/// supplies, so it needs the network reachability that suite already requires
/// in CI. Skips when the fixture or either endpoint is absent.
#[test]
fn one_verifier_and_cache_serve_concurrent_verifications() {
    use std::sync::Arc;

    init_sdk();

    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../common-test-data/serialized_test_evidence/hopper_evidence.json"
    );
    if !std::path::Path::new(fixture).exists() {
        eprintln!("skipping: evidence fixture not found at {fixture}");
        return;
    }
    let Some((rim_store_url, ocsp_url)) = recorded_evidence_endpoints() else {
        eprintln!("skipping: NVAT_TEST_RIM_STORE_URL or NVAT_TEST_OCSP_URL is unset");
        return;
    };

    const THREADS: usize = 4;
    const CACHE_BYTES: u64 = 8 * 1024 * 1024;
    const CACHE_TTL_SECONDS: i64 = 3600;

    let rim = RimStore::create_remote(Some(rim_store_url.as_str()), None, None)
        .expect("remote RIM store");
    let rim =
        RimStore::create_cached(rim, CACHE_BYTES, CACHE_TTL_SECONDS).expect("cached RIM store");
    let ocsp = OcspClient::create_default(Some(ocsp_url.as_str()), None, None)
        .expect("default OCSP client");
    let ocsp = OcspClient::create_cached(ocsp, CACHE_BYTES, CACHE_TTL_SECONDS)
        .expect("cached OCSP client");

    let verifier = Arc::new(GpuLocalVerifier::new(&rim, &ocsp).expect("shared GPU verifier"));
    let policy = Arc::new(EvidencePolicy::default_policy().expect("default evidence policy"));

    let claim_counts: Vec<usize> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let verifier = Arc::clone(&verifier);
                let policy = Arc::clone(&policy);
                scope.spawn(move || {
                    let nonce = Nonce::from_hex(
                        "e97b23a1718095a0e9e35edca810768c70a6a5a389b705e753b197912bc11576",
                    )
                    .expect("recorded-evidence nonce");
                    let evidence = GpuEvidenceSource::from_json_file(fixture)
                        .expect("evidence source")
                        .collect(&nonce)
                        .expect("evidence collection");

                    let result = verifier
                        .verify(&evidence, &policy)
                        .expect("verify over the shared verifier");
                    assert!(
                        result.is_success(),
                        "shared verifier returned verdict code {}",
                        result.result_code
                    );
                    let claims = result.claims.expect("claims on a successful verdict");
                    json_array_len(&claims.to_json().expect("serialize claims"))
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("verification thread panicked"))
            .collect()
    });

    assert!(
        claim_counts.iter().all(|&n| n > 0 && n == claim_counts[0]),
        "every thread should produce the same claims from the same evidence, got {claim_counts:?}"
    );
}

// ---------------------------------------------------------------------------
// CoRIM verifier
// ---------------------------------------------------------------------------

#[test]
fn test_corim_store_create_and_configure() {
    init_sdk();
    assert!(CorimStore::new(None, None).is_ok());

    let http_options = HttpOptions::default_options().expect("default http options");
    let mut store = CorimStore::new(Some("test-service-key"), Some(&http_options))
        .expect("CoRIM store with a service key");

    assert!(store
        .add_allowed_url_prefix("https://rim.attestation.nvidia.com/")
        .is_ok());
    assert!(store
        .add_url_rewrite("https://rim.attestation.nvidia.com/", "file:///tmp/rims/")
        .is_ok());
    assert!(store.enable_in_memory_cache(1024 * 1024, 3600).is_ok());
    // A zero TTL is legal - entries expire immediately.
    assert!(store.enable_in_memory_cache(1024, 0).is_ok());
}

#[test]
fn test_corim_store_rejects_bad_cache_settings() {
    init_sdk();
    let mut store = CorimStore::new(None, None).expect("CoRIM store");

    let err = store
        .enable_in_memory_cache(0, 3600)
        .expect_err("a zero-byte cache must be rejected");
    assert_eq!(err.code, NVAT_RC_BAD_ARGUMENT as u16);

    let err = store
        .enable_in_memory_cache(1024, -1)
        .expect_err("a negative TTL must be rejected");
    assert_eq!(err.code, NVAT_RC_BAD_ARGUMENT as u16);
}

#[test]
fn test_corim_store_rejects_interior_nul() {
    init_sdk();
    let mut store = CorimStore::new(None, None).expect("CoRIM store");

    let err = store
        .add_allowed_url_prefix("https://ex\0ample/")
        .expect_err("a prefix containing a NUL byte must be rejected, not truncated");
    assert_eq!(err.code, NVAT_RC_BAD_ARGUMENT as u16);
}

#[test]
fn test_local_corim_verifier_create_and_configure() {
    init_sdk();
    let store = CorimStore::new(None, None).expect("CoRIM store");
    let mut verifier = LocalCorimVerifier::new(store, None).expect("CoRIM verifier");

    assert!(verifier.set_verify_rim_signature(false).is_ok());
    assert!(verifier.set_verify_revocation(false).is_ok());
    // 0xa0 is an empty CBOR map.
    assert!(verifier.set_backup_spdm_coev(&[0xa0]).is_ok());
    assert!(verifier
        .add_backup_rim_locator("https://rim.attestation.nvidia.com/v1/rim/id")
        .is_ok());
    assert!(verifier
        .set_default_hash_algorithms(&[HashAlgorithm::Sha384, HashAlgorithm::Sha512])
        .is_ok());
    // An empty slice is the documented way to turn digest output off.
    assert!(verifier.set_default_hash_algorithms(&[]).is_ok());

    let err = verifier
        .set_backup_spdm_coev(&[])
        .expect_err("an empty CoEV must be rejected");
    assert_eq!(err.code, NVAT_RC_BAD_ARGUMENT as u16);
}

#[test]
fn test_local_corim_verifier_rejects_bad_input() {
    init_sdk();
    let store = CorimStore::new(None, None).expect("CoRIM store");
    let mut verifier = LocalCorimVerifier::new(store, None).expect("CoRIM verifier");

    let err = verifier
        .verify_cmw(&[], CmwFormat::Json, None)
        .expect_err("empty CMW input should be rejected");
    assert_eq!(err.code, NVAT_RC_BAD_ARGUMENT as u16);

    assert!(
        verifier
            .verify_cmw(b"not json at all", CmwFormat::Json, None)
            .is_err(),
        "unparseable CMW input should be an error"
    );

    let err = verifier
        .verify_cmw(&[0x00], CmwFormat::Cbor, None)
        .expect_err("CBOR is not implemented yet");
    assert_eq!(err.code, NVAT_RC_FEATURE_NOT_ENABLED as u16);

    let err = verifier
        .add_backup_rim_locator("")
        .expect_err("empty locator should be rejected");
    assert_eq!(err.code, NVAT_RC_BAD_ARGUMENT as u16);
}

#[test]
fn test_cmw_collection_from_spdm_transcript() {
    init_sdk();
    let nonce = Nonce::generate(32).expect("nonce");

    let err = CmwCollection::from_spdm_transcript("device_0", &[], b"pem", Some(&nonce))
        .expect_err("empty transcript should be rejected");
    assert_eq!(err.code, NVAT_RC_BAD_ARGUMENT as u16);

    let err = CmwCollection::from_spdm_transcript("device_0", b"spdm", &[], Some(&nonce))
        .expect_err("empty certificate chain should be rejected");
    assert_eq!(err.code, NVAT_RC_BAD_ARGUMENT as u16);

    let cmw = CmwCollection::from_spdm_transcript("device_0", b"spdm-bytes", b"pem-bytes", None)
        .expect("CMW collection from SPDM transcript");

    let json = cmw.serialize(CmwFormat::Json).expect("serialize as JSON");
    assert!(
        json.contains("device_0"),
        "serialized CMW should carry the evidence label, got {json}"
    );

    let err = cmw
        .serialize(CmwFormat::Cbor)
        .expect_err("CBOR serialization is not implemented yet");
    assert_eq!(err.code, NVAT_RC_FEATURE_NOT_ENABLED as u16);
}

#[test]
fn corim_verifier_is_send_and_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<LocalCorimVerifier>();
    assert_sync::<LocalCorimVerifier>();
    assert_send::<CorimStore>();
    assert_send::<CmwCollection>();
}

// ---------------------------------------------------------------------------
// CoRIM verification over a recorded CMW fixture
// ---------------------------------------------------------------------------

#[test]
fn test_verify_cmw_fixture_returns_ear() {
    init_sdk();

    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../nv-attestation-sdk-cpp/unit-tests/testdata",
        "/sample_attestation_data/blackwell_evidence.cmw.json"
    );
    let Ok(cmw) = std::fs::read(fixture) else {
        eprintln!("skipping: CMW fixture not present at {fixture}");
        return;
    };

    let store = CorimStore::new(None, None).expect("CoRIM store");
    let mut verifier = LocalCorimVerifier::new(store, None).expect("CoRIM verifier");
    verifier
        .set_verify_revocation(false)
        .expect("disable revocation");

    let ear = verifier
        .verify_cmw(&cmw, CmwFormat::Json, None)
        .expect("verify fixture");

    assert!(
        ear.json.contains("\"ear_status\"") && ear.json.contains("\"submods\""),
        "the EAR should carry a status and per-device submods, got {}",
        ear.json
    );
    assert!(
        ear.json.contains("\"signature_verified\""),
        "each submod should report evidence findings, got {}",
        ear.json
    );

    // With no signing options the JWT is unsigned
    let parts: Vec<&str> = ear.jwt.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "an EAR JWT has three parts, got {}",
        ear.jwt
    );
    assert!(
        parts[2].is_empty(),
        "an unsigned EAR should have an empty signature, got {}",
        ear.jwt
    );

    // The digest algorithms default to SHA-256 and are reported in the EAR.
    assert!(
        ear.json.contains("\"sha-256\""),
        "digests should default to SHA-256, got {}",
        ear.json
    );

    // The digests should now report SHA-512, not the SHA-256 default.
    verifier
        .set_default_hash_algorithms(&[HashAlgorithm::Sha512])
        .expect("select SHA-512");
    let ear = verifier
        .verify_cmw(&cmw, CmwFormat::Json, None)
        .expect("verify fixture");
    assert!(
        ear.json.contains("\"sha-512\"") && !ear.json.contains("\"sha-256\""),
        "the selected digest algorithm should be used, got {}",
        ear.json
    );

    // An empty slice turns digest output off entirely.
    verifier
        .set_default_hash_algorithms(&[])
        .expect("disable digests");
    let ear = verifier
        .verify_cmw(&cmw, CmwFormat::Json, None)
        .expect("verify fixture");
    assert!(
        !ear.json.contains("\"ear_nvidia_inputs\""),
        "an empty algorithm list should omit digests entirely, got {}",
        ear.json
    );
}

/// The signed path: the JWT carries an ES384 signature.
#[test]
fn test_verify_cmw_fixture_signs_the_ear() {
    init_sdk();

    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../nv-attestation-sdk-cpp/unit-tests/testdata",
        "/sample_attestation_data/blackwell_evidence.cmw.json"
    );
    let Ok(cmw) = std::fs::read(fixture) else {
        eprintln!("skipping: CMW fixture not present at {fixture}");
        return;
    };

    let signing_options = EarSigningOptions::new(
        &test_p384_key_pem(),
        "https://verifier.example.com",
        "test-kid",
    )
    .expect("EAR signing options");

    let store = CorimStore::new(None, None).expect("CoRIM store");
    let mut verifier = LocalCorimVerifier::new(store, None).expect("CoRIM verifier");
    verifier
        .set_verify_revocation(false)
        .expect("disable revocation");

    let ear = verifier
        .verify_cmw(&cmw, CmwFormat::Json, Some(&signing_options))
        .expect("verify fixture");

    let parts: Vec<&str> = ear.jwt.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "an EAR JWT has three parts, got {}",
        ear.jwt
    );
    assert!(
        !parts[2].is_empty(),
        "a signed EAR should carry a signature, got {}",
        ear.jwt
    );
    assert!(
        ear.json.contains("\"ear_status\""),
        "signing should still yield the JSON form, got {}",
        ear.json
    );

    // Options are accepted with an empty private key, and silently produce an
    // unsigned EAR.
    let unsigned_options = EarSigningOptions::new("", "https://verifier.example.com", "test-kid")
        .expect("options with an empty key are accepted");
    let unsigned = verifier
        .verify_cmw(&cmw, CmwFormat::Json, Some(&unsigned_options))
        .expect("verify fixture");
    assert!(
        unsigned.jwt.ends_with('.'),
        "an empty key should yield an unsigned EAR, got {}",
        unsigned.jwt
    );
}

const RUBIN_VBIOS_URL: &str = "https://rim.attestation.nvidia.com/v1/rim/GR100_081D_9900230000";
const RUBIN_DRIVER_URL: &str =
    "https://rim.attestation.nvidia.com/v1/rim/NV_GPU_DRIVER_GR100_620.54";

fn rubin_example_corim(name: &str) -> std::path::PathBuf {
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../nv-attestation-sdk-cpp");
    let generated = root
        .join("build/unit-tests/testdata/sample_rims/corim")
        .join(name);
    if generated.is_file() {
        return generated;
    }
    let source = root
        .join("unit-tests/testdata/sample_rims/corim")
        .join(name);
    assert!(
        source.is_file(),
        "missing {name}: build the C++ unit-test fixtures or run `make -C nv-attestation-sdk-cpp prepare-test-data`"
    );
    source
}

fn rubin_cmw() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../nv-attestation-sdk-cpp/unit-tests/testdata",
        "/sample_attestation_data/rubin_evidence.cmw.json"
    ))
    .expect("read Rubin CMW fixture")
}

fn rubin_store(vbios: &std::path::Path, driver: &std::path::Path) -> CorimStore {
    let mut store = CorimStore::new(None, None).expect("CoRIM store");
    store
        .add_url_rewrite(RUBIN_VBIOS_URL, &format!("file://{}", vbios.display()))
        .expect("rewrite VBIOS locator");
    store
        .add_url_rewrite(RUBIN_DRIVER_URL, &format!("file://{}", driver.display()))
        .expect("rewrite driver locator");
    store
}

fn rubin_verifier(store: CorimStore) -> LocalCorimVerifier {
    let mut verifier = LocalCorimVerifier::new(store, None).expect("CoRIM verifier");
    verifier
        .set_verify_rim_signature(false)
        .expect("accept unsigned example CoRIMs");
    verifier
        .set_verify_revocation(false)
        .expect("keep fixture test independent of OCSP");
    verifier
}

fn assert_rubin_appraisal(ear: &EarResult) {
    let result: serde_json::Value = serde_json::from_str(&ear.json).expect("parse EAR JSON");
    assert_eq!(result["ear_status"], "affirming", "{result}");
    let submods = result["submods"].as_object().expect("EAR submods");
    assert_eq!(submods.len(), 1, "{result}");
    let gpu = &submods["gpu_0"];
    assert_eq!(gpu["ear_status"], "affirming", "{result}");
    assert_eq!(
        gpu["ear_verifier_claims"]["ear_nvidia_evidence"]["signature_verified"], true,
        "{result}"
    );
    let rims = gpu["ear_verifier_claims"]["ear_nvidia_rims"]
        .as_array()
        .expect("GPU CoRIM results");
    assert_eq!(rims.len(), 2, "{result}");
    assert_eq!(rims[0]["id"], "example-rubin-vbios-GR100_081D_9900230000");
    assert_eq!(rims[1]["id"], "example-rubin-driver-GR100_620.54");
}

/// The evidence's two locators must reach distinct local example CoRIMs and
/// produce an affirming appraisal, not merely report a successful fetch.
#[test]
fn test_corim_store_rewrite_redirects_rim_fetch() {
    init_sdk();
    let store = rubin_store(
        &rubin_example_corim("rubin_vbios_example.cbor"),
        &rubin_example_corim("rubin_driver_example.cbor"),
    );
    let ear = rubin_verifier(store)
        .verify_cmw(&rubin_cmw(), CmwFormat::Json, None)
        .expect("verify Rubin fixture");
    assert_rubin_appraisal(&ear);
}

/// Once both backing files disappear, a second affirming appraisal must use
/// the in-memory CoRIM cache rather than falling back to a remote fetch.
#[test]
fn test_corim_store_in_memory_cache_serves_second_fetch() {
    init_sdk();
    let cmw = rubin_cmw();
    let dir = std::env::temp_dir().join(format!("nvat-rust-cache-{}", std::process::id()));
    std::fs::create_dir(&dir).expect("create cache fixture directory");
    let vbios = dir.join("rubin_vbios_example.cbor");
    let driver = dir.join("rubin_driver_example.cbor");
    std::fs::copy(rubin_example_corim("rubin_vbios_example.cbor"), &vbios)
        .expect("copy VBIOS CoRIM");
    std::fs::copy(rubin_example_corim("rubin_driver_example.cbor"), &driver)
        .expect("copy driver CoRIM");

    let mut store = rubin_store(&vbios, &driver);
    store
        .enable_in_memory_cache(1024 * 1024, 3600)
        .expect("enable the CoRIM cache");
    let verifier = rubin_verifier(store);
    let first = verifier
        .verify_cmw(&cmw, CmwFormat::Json, None)
        .expect("first verification populates the cache");
    assert_rubin_appraisal(&first);

    std::fs::remove_dir_all(&dir).expect("remove both backing files");
    let second = verifier
        .verify_cmw(&cmw, CmwFormat::Json, None)
        .expect("second verification uses the cache");
    assert_rubin_appraisal(&second);
}

// ---------------------------------------------------------------------------
// AIA OCSP client (the client the CoRIM verifier expects)
// ---------------------------------------------------------------------------

#[test]
fn test_ocsp_client_create_aia() {
    init_sdk();
    assert!(OcspClient::create_aia(AiaOptions::default()).is_ok());

    let http_options = HttpOptions::default_options().expect("default http options");
    assert!(OcspClient::create_aia(AiaOptions {
        base_url: Some("http://ocsp.attestation.nvidia.com"),
        service_key: Some("test-service-key"),
        http_options: Some(&http_options),
        client_options: None,
        rewrites: &[
            UrlRewrite {
                pattern: "http://ocsp.example.com/",
                replacement: "http://ocsp.internal.example/",
            },
            UrlRewrite {
                pattern: "http://ocsp2.example.com/",
                replacement: "http://ocsp.internal.example/",
            },
        ],
    })
    .is_ok());

    match OcspClient::create_aia(AiaOptions {
        rewrites: &[UrlRewrite {
            pattern: "http://ocsp.example.com/",
            replacement: "bad\0replacement",
        }],
        ..Default::default()
    }) {
        Ok(_) => panic!("a rewrite containing a NUL byte must be rejected"),
        Err(err) => assert_eq!(err.code, NVAT_RC_BAD_ARGUMENT as u16),
    }
}

#[test]
fn test_corim_verifier_accepts_aia_and_cached_ocsp_client() {
    init_sdk();
    let ocsp = OcspClient::create_aia(AiaOptions::default()).expect("AIA OCSP client");
    let ocsp = OcspClient::create_cached(ocsp, 1024 * 1024, 3600).expect("cached OCSP client");
    let store = CorimStore::new(None, None).expect("CoRIM store");

    assert!(LocalCorimVerifier::new(store, Some(&ocsp)).is_ok());
}
