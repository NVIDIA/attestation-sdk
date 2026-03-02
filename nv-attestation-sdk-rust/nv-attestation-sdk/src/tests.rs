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

// Global SDK client - initialized once and kept alive for all tests
static SDK_CLIENT: LazyLock<NvatSdk> = LazyLock::new(|| {
    // Initialize env_logger for tests (only once)
    let _ = env_logger::builder().is_test(true).try_init();

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
});

/// Initialize the SDK for tests. This is called once per test process.
fn init_sdk() {
    // Force initialization of the lazy static
    let _ = &*SDK_CLIENT;
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
fn test_sdk_options_default() {
    init_sdk();
    let opts = SdkOptions::default();
    // Should not panic - that's the test
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
fn test_attestation_context_default() {
    init_sdk();
    let ctx = AttestationContext::default();
    // Should not panic - that's the test
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
