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

//! Rust bindings for the NVIDIA Attestation SDK (NVAT).
//!
//! This crate provides safe Rust interfaces to the NVIDIA Attestation SDK,
//! enabling attestation and verification of NVIDIA GPU and other device evidence.
//!
//! # Example
//!
//! ```no_run
//! use nv_attestation_sdk::{NvatSdk, SdkOptions};
//!
//! let options = SdkOptions::default();
//! let client = NvatSdk::init(options)?;
//! # Ok::<(), nv_attestation_sdk::NvatError>(())
//! ```

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

// Re-export raw FFI bindings from the sys crate
#[doc(hidden)]
pub use nv_attestation_sdk_sys::*;

// Public modules
pub mod error;

/// Type definitions for NVAT SDK
pub mod types;

/// Attestation types for NVAT SDK operations (SDK, contexts, verifiers, policies)
pub mod attestation;

// Re-export commonly used types
pub use attestation::{
    AttestationContext, AttestationContextBuilder, AttestationResult, ClaimsCollection, DeviceType,
    EvidencePolicy, EvidencePolicyBuilder, GpuLocalVerifier, GpuNrasVerifier, NvatSdk, OcspClient,
    RimStore, SwitchLocalVerifier, SwitchNrasVerifier, VerifierType,
};
pub use error::{NvatError, Result};
pub use types::{
    GpuEvidenceCollection, GpuEvidenceSource, HttpOptions, HttpOptionsBuilder, Logger, Nonce,
    NvatString, SdkOptions, SwitchEvidenceCollection, SwitchEvidenceSource,
};

// Unit tests
#[cfg(test)]
mod tests;
