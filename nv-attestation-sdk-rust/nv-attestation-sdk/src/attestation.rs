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

use crate::error::{NvatError, Result};
use crate::types::{HttpOptions, Nonce, NvatString, SdkOptions};
use crate::*;
#[cfg(feature = "logging")]
use log::{debug, info};
use std::ffi::{CStr, CString};
use std::path::Path;
use std::ptr;

// Logging wrapper macros that compile to no-ops when logging feature is disabled
#[cfg(feature = "logging")]
macro_rules! log_info {
    ($($arg:tt)*) => { info!($($arg)*); };
}

#[cfg(not(feature = "logging"))]
macro_rules! log_info {
    ($($arg:tt)*) => {};
}

#[cfg(feature = "logging")]
macro_rules! log_debug {
    ($($arg:tt)*) => { debug!($($arg)*); };
}

#[cfg(not(feature = "logging"))]
macro_rules! log_debug {
    ($($arg:tt)*) => {};
}

/// NVIDIA Attestation SDK
///
/// This is the main entry point for using the NVAT SDK.
/// The SDK must be initialized before use.
///
/// # Thread Safety
///
/// The SDK initialization via [`NvatSdk::init`] or [`NvatSdk::init_default`]
/// should be called once per process from the main thread. After initialization,
/// attestation operations can be performed from multiple threads using separate
/// [`AttestationContext`] instances.
///
/// `NvatSdk` cannot be moved between threads. Create it on the main
/// thread and keep it alive for the duration of your application.
pub struct NvatSdk {
    // Zero-sized type - acts as a lifecycle marker for SDK initialization
}

impl NvatSdk {
    /// Initialize SDK. Wraps `nvat_sdk_init`.
    ///
    /// Call once per process from the main thread. SDK shuts down when dropped.
    pub fn init(opts: SdkOptions) -> Result<Self> {
        log_info!("Initializing NVAT SDK version {}", Self::version());
        unsafe {
            NvatError::check(nvat_sdk_init(opts.as_ptr()))?;
        }
        // Note: opts will be properly freed via Drop when it goes out of scope.
        // The C SDK copies the shared_ptr internally, so we must free the wrapper.
        log_info!("NVAT SDK initialized successfully");
        Ok(NvatSdk {})
    }

    /// Initialize SDK with default options. Convenience wrapper for `init`.
    pub fn init_default() -> Result<Self> {
        let opts = SdkOptions::new()?;
        Self::init(opts)
    }

    /// Get SDK version string.
    pub fn version() -> &'static str {
        unsafe {
            CStr::from_bytes_with_nul_unchecked(NVAT_VERSION_STRING)
                .to_str()
                .unwrap_or("unknown")
        }
    }
}

impl Drop for NvatSdk {
    fn drop(&mut self) {
        log_debug!("Shutting down NVAT SDK");
        unsafe {
            nvat_sdk_shutdown();
        }
        log_info!("NVAT SDK shutdown complete");
    }
}

/// Device type for attestation (GPU or NVSwitch).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// GPU device
    Gpu = NVAT_DEVICE_GPU as isize,
    /// NVSwitch device
    NvSwitch = NVAT_DEVICE_NVSWITCH as isize,
}

impl From<DeviceType> for nvat_devices_t {
    fn from(device: DeviceType) -> Self {
        device as u32
    }
}

/// Verifier type (local or remote).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierType {
    /// Local verification
    Local = NVAT_VERIFY_LOCAL as isize,
    /// Remote verification via NRAS
    Remote = NVAT_VERIFY_REMOTE as isize,
}

impl From<VerifierType> for nvat_verifier_type_t {
    fn from(verifier: VerifierType) -> Self {
        verifier as u8
    }
}

/// Wrapper around nvat_attestation_ctx_t
///
/// Attestation context for configuring and performing device attestation.
///
/// # Thread Safety
///
/// Each `AttestationContext` instance should be used by a single thread. For
/// concurrent attestation operations, create separate context instances in each
/// thread. The underlying SDK may support concurrent operations, but individual
/// context instances are not guaranteed to be thread-safe.
///
/// To perform attestation from multiple threads:
/// 1. Initialize the SDK once with [`NvatSdk::init`] on the main thread
/// 2. Create a separate [`AttestationContext`] in each worker thread
/// 3. Perform attestation operations independently in each thread
pub struct AttestationContext {
    inner: nvat_attestation_ctx_t,
}

impl AttestationContext {
    /// Create attestation context. Wraps `nvat_attestation_ctx_create`.
    ///
    /// For a more ergonomic API, consider using [`AttestationContextBuilder`]:
    /// ```no_run
    /// use nv_attestation_sdk::{AttestationContext, DeviceType, VerifierType};
    /// let ctx = AttestationContext::builder()
    ///     .device_type(DeviceType::Gpu)
    ///     .verifier_type(VerifierType::Remote)
    ///     .build()?;
    /// # Ok::<(), nv_attestation_sdk::NvatError>(())
    /// ```
    pub fn new() -> Result<Self> {
        let mut ctx = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_attestation_ctx_create(&mut ctx))?;
        }
        Ok(AttestationContext { inner: ctx })
    }

    /// Create a builder for configuring attestation context.
    ///
    /// This provides a more idiomatic Rust API compared to the setter methods.
    pub fn builder() -> AttestationContextBuilder {
        AttestationContextBuilder::default()
    }

    /// Set device type. Wraps `nvat_attestation_ctx_set_device_type`.
    pub fn set_device_type(&mut self, device_type: DeviceType) -> Result<()> {
        unsafe {
            NvatError::check(nvat_attestation_ctx_set_device_type(
                self.inner,
                device_type.into(),
            ))
        }
    }

    /// Set verifier type. Wraps `nvat_attestation_ctx_set_verifier_type`.
    pub fn set_verifier_type(&mut self, verifier_type: VerifierType) -> Result<()> {
        unsafe {
            NvatError::check(nvat_attestation_ctx_set_verifier_type(
                self.inner,
                verifier_type.into(),
            ))
        }
    }

    /// Set NRAS URL. Wraps `nvat_attestation_ctx_set_default_nras_url`.
    pub fn set_nras_url(&mut self, url: &str) -> Result<()> {
        let c_url = CString::new(url).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        unsafe {
            NvatError::check(nvat_attestation_ctx_set_default_nras_url(
                self.inner,
                c_url.as_ptr(),
            ))
        }
    }

    /// Set OCSP URL. Wraps `nvat_attestation_ctx_set_default_ocsp_url`.
    pub fn set_ocsp_url(&mut self, url: &str) -> Result<()> {
        let c_url = CString::new(url).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        unsafe {
            NvatError::check(nvat_attestation_ctx_set_default_ocsp_url(
                self.inner,
                c_url.as_ptr(),
            ))
        }
    }

    /// Set the RIM store URL
    pub fn set_rim_store_url(&mut self, url: &str) -> Result<()> {
        let c_url = CString::new(url).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        unsafe {
            NvatError::check(nvat_attestation_ctx_set_default_rim_store_url(
                self.inner,
                c_url.as_ptr(),
            ))
        }
    }

    /// Set the service key for authentication
    pub fn set_service_key(&mut self, key: &str) -> Result<()> {
        let c_key = CString::new(key).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        unsafe {
            NvatError::check(nvat_attestation_ctx_set_service_key(
                self.inner,
                c_key.as_ptr(),
            ))
        }
    }

    /// Set GPU evidence source from JSON file
    pub fn set_gpu_evidence_from_json_file(&mut self, file_path: &str) -> Result<()> {
        let c_path =
            CString::new(file_path).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        unsafe {
            NvatError::check(nvat_attestation_ctx_set_gpu_evidence_source_json_file(
                self.inner,
                c_path.as_ptr(),
            ))
        }
    }

    /// Set switch evidence source from JSON file
    pub fn set_switch_evidence_from_json_file(&mut self, file_path: &str) -> Result<()> {
        let c_path =
            CString::new(file_path).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        unsafe {
            NvatError::check(nvat_attestation_ctx_set_switch_evidence_source_json_file(
                self.inner,
                c_path.as_ptr(),
            ))
        }
    }

    /// Perform device attestation. Wraps `nvat_attestation_ctx_attest_device`.
    ///
    /// Auto-generates nonce if `None` is provided.
    pub fn attest_device(&self, nonce: Option<&Nonce>) -> Result<AttestationResult> {
        let nonce_ptr = nonce.map(|n| n.as_ptr()).unwrap_or(ptr::null_mut());

        if let Some(_n) = nonce {
            log_debug!(
                "Starting attestation with nonce (length: {} bytes)",
                _n.len()
            );
        } else {
            log_debug!("Starting attestation with auto-generated nonce");
        }

        let mut eat_ptr = ptr::null_mut();
        let mut claims_ptr = ptr::null_mut();

        unsafe {
            NvatError::check(nvat_attest_device(
                self.inner,
                nonce_ptr,
                &mut eat_ptr,
                &mut claims_ptr,
            ))?;
        }

        log_info!("Attestation completed successfully");

        Ok(AttestationResult {
            detached_eat: if eat_ptr.is_null() {
                None
            } else {
                Some(NvatString::from_raw(eat_ptr))
            },
            claims: if claims_ptr.is_null() {
                None
            } else {
                Some(ClaimsCollection::from_raw(claims_ptr))
            },
        })
    }
}

impl Default for AttestationContext {
    fn default() -> Self {
        Self::new().expect("Failed to create default attestation context")
    }
}

impl Drop for AttestationContext {
    fn drop(&mut self) {
        unsafe {
            nvat_attestation_ctx_free(&mut self.inner);
        }
    }
}

/// Builder for [`AttestationContext`] with a more idiomatic Rust API.
///
/// This builder pattern delays creating the C object until `build()` is called,
/// allowing for a more ergonomic configuration experience.
///
/// # Example
/// ```no_run
/// use nv_attestation_sdk::{AttestationContext, DeviceType, VerifierType};
///
/// let ctx = AttestationContext::builder()
///     .device_type(DeviceType::Gpu)
///     .verifier_type(VerifierType::Remote)
///     .nras_url("https://nras.attestation.nvidia.com")
///     .build()?;
/// # Ok::<(), nv_attestation_sdk::NvatError>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct AttestationContextBuilder {
    device_type: Option<DeviceType>,
    verifier_type: Option<VerifierType>,
    nras_url: Option<String>,
    ocsp_url: Option<String>,
    rim_store_url: Option<String>,
    service_key: Option<String>,
    gpu_evidence_json_file: Option<String>,
    switch_evidence_json_file: Option<String>,
}

impl AttestationContextBuilder {
    /// Set the device type.
    pub fn device_type(mut self, device_type: DeviceType) -> Self {
        self.device_type = Some(device_type);
        self
    }

    /// Set the verifier type.
    pub fn verifier_type(mut self, verifier_type: VerifierType) -> Self {
        self.verifier_type = Some(verifier_type);
        self
    }

    /// Set the NRAS URL.
    pub fn nras_url(mut self, url: impl Into<String>) -> Self {
        self.nras_url = Some(url.into());
        self
    }

    /// Set the OCSP URL.
    pub fn ocsp_url(mut self, url: impl Into<String>) -> Self {
        self.ocsp_url = Some(url.into());
        self
    }

    /// Set the RIM store URL.
    pub fn rim_store_url(mut self, url: impl Into<String>) -> Self {
        self.rim_store_url = Some(url.into());
        self
    }

    /// Set the service key for authentication.
    pub fn service_key(mut self, key: impl Into<String>) -> Self {
        self.service_key = Some(key.into());
        self
    }

    /// Set GPU evidence source from JSON file path.
    pub fn gpu_evidence_from_json_file(mut self, path: impl Into<String>) -> Self {
        self.gpu_evidence_json_file = Some(path.into());
        self
    }

    /// Set switch evidence source from JSON file path.
    pub fn switch_evidence_from_json_file(mut self, path: impl Into<String>) -> Self {
        self.switch_evidence_json_file = Some(path.into());
        self
    }

    /// Build the [`AttestationContext`] with the configured values.
    ///
    /// This creates the underlying C object and applies all configured settings.
    pub fn build(self) -> Result<AttestationContext> {
        let mut ctx = AttestationContext::new()?;

        if let Some(device_type) = self.device_type {
            ctx.set_device_type(device_type)?;
        }
        if let Some(verifier_type) = self.verifier_type {
            ctx.set_verifier_type(verifier_type)?;
        }
        if let Some(url) = self.nras_url {
            ctx.set_nras_url(&url)?;
        }
        if let Some(url) = self.ocsp_url {
            ctx.set_ocsp_url(&url)?;
        }
        if let Some(url) = self.rim_store_url {
            ctx.set_rim_store_url(&url)?;
        }
        if let Some(key) = self.service_key {
            ctx.set_service_key(&key)?;
        }
        if let Some(path) = self.gpu_evidence_json_file {
            ctx.set_gpu_evidence_from_json_file(&path)?;
        }
        if let Some(path) = self.switch_evidence_json_file {
            ctx.set_switch_evidence_from_json_file(&path)?;
        }

        Ok(ctx)
    }
}

/// Attestation result containing the detached EAT and claims
///
/// This structure holds the results of an attestation operation, including:
/// - The detached Entity Attestation Token (EAT) in JSON format
/// - A collection of claims about the attested device(s)
pub struct AttestationResult {
    /// The detached Entity Attestation Token (EAT)
    pub detached_eat: Option<NvatString>,
    /// Collection of claims about the attested device(s)
    pub claims: Option<ClaimsCollection>,
}

impl AttestationResult {
    /// Get the detached EAT as a JSON string
    pub fn eat_json(&self) -> Result<String> {
        self.detached_eat
            .as_ref()
            .ok_or_else(|| NvatError::new(NVAT_RC_INTERNAL_ERROR as u16))?
            .to_string()
    }

    /// Get the claims as a JSON string
    pub fn claims_json(&self) -> Result<String> {
        self.claims
            .as_ref()
            .ok_or_else(|| NvatError::new(NVAT_RC_INTERNAL_ERROR as u16))?
            .to_json()
    }
}

/// Safe wrapper around nvat_claims_collection_t
pub struct ClaimsCollection {
    inner: nvat_claims_collection_t,
}

impl ClaimsCollection {
    pub(crate) fn from_raw(ptr: nvat_claims_collection_t) -> Self {
        ClaimsCollection { inner: ptr }
    }

    /// Serialize the claims collection to JSON
    pub fn to_json(&self) -> Result<String> {
        let mut str_ptr = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_claims_collection_serialize_json(
                self.inner,
                &mut str_ptr,
            ))?;
        }
        let nvat_str = NvatString::from_raw(str_ptr);
        nvat_str.to_string()
    }
}

impl Drop for ClaimsCollection {
    fn drop(&mut self) {
        unsafe {
            nvat_claims_collection_free(&mut self.inner);
        }
    }
}

/// Safe wrapper around nvat_evidence_policy_t
pub struct EvidencePolicy {
    pub(crate) inner: nvat_evidence_policy_t,
}

impl EvidencePolicy {
    /// Create a default evidence policy.
    ///
    /// For a more ergonomic API, consider using [`EvidencePolicyBuilder`]:
    /// ```no_run
    /// use nv_attestation_sdk::EvidencePolicy;
    /// let policy = EvidencePolicy::builder()
    ///     .verify_rim_signature(true)
    ///     .verify_rim_cert_chain(true)
    ///     .build()?;
    /// # Ok::<(), nv_attestation_sdk::NvatError>(())
    /// ```
    pub fn default_policy() -> Result<Self> {
        let mut policy = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_evidence_policy_create_default(&mut policy))?;
        }
        Ok(EvidencePolicy { inner: policy })
    }

    /// Create a builder for configuring evidence policy.
    ///
    /// This provides a more idiomatic Rust API compared to the setter methods.
    pub fn builder() -> EvidencePolicyBuilder {
        EvidencePolicyBuilder::default()
    }

    /// Set whether to verify RIM signature
    pub fn set_verify_rim_signature(&mut self, verify: bool) {
        unsafe {
            nvat_evidence_policy_set_verify_rim_signature(self.inner, verify);
        }
    }

    /// Set whether to verify RIM certificate chain
    pub fn set_verify_rim_cert_chain(&mut self, verify: bool) {
        unsafe {
            nvat_evidence_policy_set_verify_rim_cert_chain(self.inner, verify);
        }
    }
}

impl Drop for EvidencePolicy {
    fn drop(&mut self) {
        unsafe {
            nvat_evidence_policy_free(&mut self.inner);
        }
    }
}

/// Builder for [`EvidencePolicy`] with a more idiomatic Rust API.
///
/// This builder pattern delays creating the C object until `build()` is called,
/// allowing for a more ergonomic configuration experience.
///
/// # Example
/// ```no_run
/// use nv_attestation_sdk::EvidencePolicy;
///
/// let policy = EvidencePolicy::builder()
///     .verify_rim_signature(true)
///     .verify_rim_cert_chain(true)
///     .build()?;
/// # Ok::<(), nv_attestation_sdk::NvatError>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct EvidencePolicyBuilder {
    verify_rim_signature: Option<bool>,
    verify_rim_cert_chain: Option<bool>,
}

impl EvidencePolicyBuilder {
    /// Set whether to verify RIM signature.
    pub fn verify_rim_signature(mut self, verify: bool) -> Self {
        self.verify_rim_signature = Some(verify);
        self
    }

    /// Set whether to verify RIM certificate chain.
    pub fn verify_rim_cert_chain(mut self, verify: bool) -> Self {
        self.verify_rim_cert_chain = Some(verify);
        self
    }

    /// Build the [`EvidencePolicy`] with the configured values.
    ///
    /// This creates the underlying C object and applies all configured settings.
    pub fn build(self) -> Result<EvidencePolicy> {
        let mut policy = EvidencePolicy::default_policy()?;

        if let Some(verify) = self.verify_rim_signature {
            policy.set_verify_rim_signature(verify);
        }
        if let Some(verify) = self.verify_rim_cert_chain {
            policy.set_verify_rim_cert_chain(verify);
        }

        Ok(policy)
    }
}

/// Safe wrapper around nvat_ocsp_client_t
pub struct OcspClient {
    pub(crate) inner: nvat_ocsp_client_t,
}

impl OcspClient {
    /// Create a default OCSP client
    pub fn create_default(
        base_url: Option<&str>,
        service_key: Option<&str>,
        http_options: Option<&HttpOptions>,
    ) -> Result<Self> {
        // Keep CStrings alive until after FFI call to avoid dangling pointers
        let url_cstring = base_url
            .map(CString::new)
            .transpose()
            .map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        let url_ptr = url_cstring
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(ptr::null());

        let key_cstring = service_key
            .map(CString::new)
            .transpose()
            .map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        let key_ptr = key_cstring
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(ptr::null());

        let opts_ptr = http_options.map(|o| o.as_ptr()).unwrap_or(ptr::null_mut());

        let mut client = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_ocsp_client_create_default(
                &mut client,
                url_ptr,
                key_ptr,
                opts_ptr,
            ))?;
        }
        Ok(OcspClient { inner: client })
    }
}

impl Drop for OcspClient {
    fn drop(&mut self) {
        unsafe {
            nvat_ocsp_client_free(&mut self.inner);
        }
    }
}

/// Safe wrapper around nvat_rim_store_t
pub struct RimStore {
    pub(crate) inner: nvat_rim_store_t,
}

impl RimStore {
    /// Create a remote RIM store
    pub fn create_remote(
        base_url: Option<&str>,
        service_key: Option<&str>,
        http_options: Option<&HttpOptions>,
    ) -> Result<Self> {
        // Keep CStrings alive until after FFI call to avoid dangling pointers
        let url_cstring = base_url
            .map(CString::new)
            .transpose()
            .map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        let url_ptr = url_cstring
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(ptr::null());

        let key_cstring = service_key
            .map(CString::new)
            .transpose()
            .map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        let key_ptr = key_cstring
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(ptr::null());

        let opts_ptr = http_options.map(|o| o.as_ptr()).unwrap_or(ptr::null_mut());

        let mut store = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_rim_store_create_remote(
                &mut store, url_ptr, key_ptr, opts_ptr,
            ))?;
        }
        Ok(RimStore { inner: store })
    }

    /// Create a filesystem-based RIM store
    pub fn create_filesystem(base_path: impl AsRef<Path>) -> Result<Self> {
        let path_str = base_path
            .as_ref()
            .to_str()
            .ok_or_else(|| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        let c_path =
            CString::new(path_str).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;

        let mut store = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_rim_store_create_filesystem(
                &mut store,
                c_path.as_ptr(),
            ))?;
        }
        Ok(RimStore { inner: store })
    }
}

impl Drop for RimStore {
    fn drop(&mut self) {
        unsafe {
            nvat_rim_store_free(&mut self.inner);
        }
    }
}

/// GPU Local Verifier - verifies GPU evidence locally
pub struct GpuLocalVerifier {
    inner: nvat_gpu_local_verifier_t,
}

impl GpuLocalVerifier {
    /// Create a local GPU verifier. Wraps `nvat_gpu_local_verifier_create`.
    ///
    /// # Arguments
    /// * `rim_store` - RIM store for fetching Reference Integrity Manifests
    /// * `ocsp_client` - OCSP client for certificate revocation checking
    ///
    /// # Example
    /// ```no_run
    /// use nv_attestation_sdk::{GpuLocalVerifier, RimStore, OcspClient, HttpOptions};
    ///
    /// let http_opts = HttpOptions::default_options()?;
    /// let rim_store = RimStore::create_remote(None, None, Some(&http_opts))?;
    /// let ocsp_client = OcspClient::create_default(None, None, Some(&http_opts))?;
    ///
    /// let verifier = GpuLocalVerifier::new(&rim_store, &ocsp_client)?;
    /// # Ok::<(), nv_attestation_sdk::NvatError>(())
    /// ```
    pub fn new(rim_store: &RimStore, ocsp_client: &OcspClient) -> Result<Self> {
        let mut verifier = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_gpu_local_verifier_create(
                &mut verifier,
                rim_store.inner,
                ocsp_client.inner,
                ptr::null_mut(), // Use default detached EAT options
            ))?;
        }
        Ok(GpuLocalVerifier { inner: verifier })
    }

    /// Verify GPU evidence against a policy. Wraps `nvat_verify_gpu_evidence`.
    ///
    /// # Arguments
    /// * `evidence` - Collection of GPU evidence to verify
    /// * `policy` - Evidence policy defining verification requirements
    ///
    /// # Returns
    /// An [`AttestationResult`] containing the detached EAT and claims
    pub fn verify(
        &self,
        evidence: &types::GpuEvidenceCollection,
        policy: &EvidencePolicy,
    ) -> Result<AttestationResult> {
        let mut eat_ptr = ptr::null_mut();
        let mut claims_ptr = ptr::null_mut();

        unsafe {
            // Upcast to base verifier type
            let base_verifier = nvat_gpu_local_verifier_upcast(self.inner);

            NvatError::check(nvat_verify_gpu_evidence(
                base_verifier,
                evidence.as_ptr(),
                evidence.len(),
                policy.inner,
                &mut eat_ptr,
                &mut claims_ptr,
            ))?;
        }

        Ok(AttestationResult {
            detached_eat: if eat_ptr.is_null() {
                None
            } else {
                Some(NvatString::from_raw(eat_ptr))
            },
            claims: if claims_ptr.is_null() {
                None
            } else {
                Some(ClaimsCollection::from_raw(claims_ptr))
            },
        })
    }
}

impl Drop for GpuLocalVerifier {
    fn drop(&mut self) {
        unsafe {
            // Upcast to base type before freeing
            let mut base_verifier = nvat_gpu_local_verifier_upcast(self.inner);
            nvat_gpu_verifier_free(&mut base_verifier);
        }
    }
}

/// GPU NRAS Verifier - verifies GPU evidence remotely via NVIDIA Remote Attestation Service
///
/// Remote verification offloads the verification process to NVIDIA's attestation
/// service, which handles certificate validation, RIM fetching, and evidence
/// appraisal in a secure environment.
///
/// Not `Send` or `Sync` - use separate instances per thread if needed.
pub struct GpuNrasVerifier {
    inner: nvat_gpu_nras_verifier_t,
}

impl GpuNrasVerifier {
    /// Create a remote GPU verifier using NRAS. Wraps `nvat_gpu_nras_verifier_create`.
    ///
    /// # Arguments
    /// * `base_url` - Optional NRAS base URL (uses default if None)
    /// * `service_key` - Optional service key for authentication
    /// * `http_options` - Optional HTTP configuration for network requests
    ///
    /// # Example
    /// ```no_run
    /// use nv_attestation_sdk::{GpuNrasVerifier, HttpOptions};
    ///
    /// let http_opts = HttpOptions::builder()
    ///     .max_retry_count(5)
    ///     .connection_timeout_ms(10000)
    ///     .build()?;
    ///
    /// let verifier = GpuNrasVerifier::new(None, None, Some(&http_opts))?;
    /// # Ok::<(), nv_attestation_sdk::NvatError>(())
    /// ```
    pub fn new(
        base_url: Option<&str>,
        service_key: Option<&str>,
        http_options: Option<&HttpOptions>,
    ) -> Result<Self> {
        // Keep CStrings alive until after FFI call to avoid dangling pointers
        let url_cstring = base_url
            .map(CString::new)
            .transpose()
            .map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        let url_ptr = url_cstring
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(ptr::null());

        let key_cstring = service_key
            .map(CString::new)
            .transpose()
            .map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        let key_ptr = key_cstring
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(ptr::null());

        let opts_ptr = http_options.map(|o| o.as_ptr()).unwrap_or(ptr::null_mut());

        let mut verifier = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_gpu_nras_verifier_create(
                &mut verifier,
                url_ptr,
                key_ptr,
                opts_ptr,
            ))?;
        }
        Ok(GpuNrasVerifier { inner: verifier })
    }

    /// Verify GPU evidence against a policy via NRAS. Wraps `nvat_verify_gpu_evidence`.
    ///
    /// # Arguments
    /// * `evidence` - Collection of GPU evidence to verify
    /// * `policy` - Evidence policy defining verification requirements
    ///
    /// # Returns
    /// An [`AttestationResult`] containing the detached EAT and claims
    pub fn verify(
        &self,
        evidence: &types::GpuEvidenceCollection,
        policy: &EvidencePolicy,
    ) -> Result<AttestationResult> {
        let mut eat_ptr = ptr::null_mut();
        let mut claims_ptr = ptr::null_mut();

        unsafe {
            // Upcast to base verifier type
            let base_verifier = nvat_gpu_nras_verifier_upcast(self.inner);

            NvatError::check(nvat_verify_gpu_evidence(
                base_verifier,
                evidence.as_ptr(),
                evidence.len(),
                policy.inner,
                &mut eat_ptr,
                &mut claims_ptr,
            ))?;
        }

        Ok(AttestationResult {
            detached_eat: if eat_ptr.is_null() {
                None
            } else {
                Some(NvatString::from_raw(eat_ptr))
            },
            claims: if claims_ptr.is_null() {
                None
            } else {
                Some(ClaimsCollection::from_raw(claims_ptr))
            },
        })
    }
}

impl Drop for GpuNrasVerifier {
    fn drop(&mut self) {
        unsafe {
            // Upcast to base type before freeing
            let mut base_verifier = nvat_gpu_nras_verifier_upcast(self.inner);
            nvat_gpu_verifier_free(&mut base_verifier);
        }
    }
}

/// Switch Local Verifier - verifies NVSwitch evidence locally
pub struct SwitchLocalVerifier {
    inner: nvat_switch_local_verifier_t,
}

impl SwitchLocalVerifier {
    /// Create a local NVSwitch verifier. Wraps `nvat_switch_local_verifier_create`.
    ///
    /// # Arguments
    /// * `rim_store` - RIM store for fetching Reference Integrity Manifests
    /// * `ocsp_client` - OCSP client for certificate revocation checking
    ///
    /// # Example
    /// ```no_run
    /// use nv_attestation_sdk::{SwitchLocalVerifier, RimStore, OcspClient, HttpOptions};
    ///
    /// let http_opts = HttpOptions::default_options()?;
    /// let rim_store = RimStore::create_remote(None, None, Some(&http_opts))?;
    /// let ocsp_client = OcspClient::create_default(None, None, Some(&http_opts))?;
    ///
    /// let verifier = SwitchLocalVerifier::new(&rim_store, &ocsp_client)?;
    /// # Ok::<(), nv_attestation_sdk::NvatError>(())
    /// ```
    pub fn new(rim_store: &RimStore, ocsp_client: &OcspClient) -> Result<Self> {
        let mut verifier = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_switch_local_verifier_create(
                &mut verifier,
                rim_store.inner,
                ocsp_client.inner,
                ptr::null_mut(), // Use default detached EAT options
            ))?;
        }
        Ok(SwitchLocalVerifier { inner: verifier })
    }

    /// Verify NVSwitch evidence against a policy. Wraps `nvat_verify_switch_evidence`.
    ///
    /// # Arguments
    /// * `evidence` - Collection of NVSwitch evidence to verify
    /// * `policy` - Evidence policy defining verification requirements
    ///
    /// # Returns
    /// An [`AttestationResult`] containing the detached EAT and claims
    pub fn verify(
        &self,
        evidence: &types::SwitchEvidenceCollection,
        policy: &EvidencePolicy,
    ) -> Result<AttestationResult> {
        let mut eat_ptr = ptr::null_mut();
        let mut claims_ptr = ptr::null_mut();

        unsafe {
            // Upcast to base verifier type
            let base_verifier = nvat_switch_local_verifier_upcast(self.inner);

            NvatError::check(nvat_verify_switch_evidence(
                base_verifier,
                evidence.as_ptr(),
                evidence.len(),
                policy.inner,
                &mut eat_ptr,
                &mut claims_ptr,
            ))?;
        }

        Ok(AttestationResult {
            detached_eat: if eat_ptr.is_null() {
                None
            } else {
                Some(NvatString::from_raw(eat_ptr))
            },
            claims: if claims_ptr.is_null() {
                None
            } else {
                Some(ClaimsCollection::from_raw(claims_ptr))
            },
        })
    }
}

impl Drop for SwitchLocalVerifier {
    fn drop(&mut self) {
        unsafe {
            // Upcast to base type before freeing
            let mut base_verifier = nvat_switch_local_verifier_upcast(self.inner);
            nvat_switch_verifier_free(&mut base_verifier);
        }
    }
}

/// Switch NRAS Verifier - verifies NVSwitch evidence remotely via NVIDIA Remote Attestation Service
///
/// Remote verification offloads the verification process to NVIDIA's attestation
/// service, which handles certificate validation, RIM fetching, and evidence
/// appraisal in a secure environment.
///
/// Not `Send` or `Sync` - use separate instances per thread if needed.
pub struct SwitchNrasVerifier {
    inner: nvat_switch_nras_verifier_t,
}

impl SwitchNrasVerifier {
    /// Create a remote NVSwitch verifier using NRAS. Wraps `nvat_switch_nras_verifier_create`.
    ///
    /// # Arguments
    /// * `base_url` - Optional NRAS base URL (uses default if None)
    /// * `service_key` - Optional service key for authentication
    /// * `http_options` - Optional HTTP configuration for network requests
    ///
    /// # Example
    /// ```no_run
    /// use nv_attestation_sdk::{SwitchNrasVerifier, HttpOptions};
    ///
    /// let http_opts = HttpOptions::builder()
    ///     .max_retry_count(5)
    ///     .connection_timeout_ms(10000)
    ///     .build()?;
    ///
    /// let verifier = SwitchNrasVerifier::new(None, None, Some(&http_opts))?;
    /// # Ok::<(), nv_attestation_sdk::NvatError>(())
    /// ```
    pub fn new(
        base_url: Option<&str>,
        service_key: Option<&str>,
        http_options: Option<&HttpOptions>,
    ) -> Result<Self> {
        // Keep CStrings alive until after FFI call to avoid dangling pointers
        let url_cstring = base_url
            .map(CString::new)
            .transpose()
            .map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        let url_ptr = url_cstring
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(ptr::null());

        let key_cstring = service_key
            .map(CString::new)
            .transpose()
            .map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        let key_ptr = key_cstring
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(ptr::null());

        let opts_ptr = http_options.map(|o| o.as_ptr()).unwrap_or(ptr::null_mut());

        let mut verifier = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_switch_nras_verifier_create(
                &mut verifier,
                url_ptr,
                key_ptr,
                opts_ptr,
            ))?;
        }
        Ok(SwitchNrasVerifier { inner: verifier })
    }

    /// Verify NVSwitch evidence against a policy via NRAS. Wraps `nvat_verify_switch_evidence`.
    ///
    /// # Arguments
    /// * `evidence` - Collection of NVSwitch evidence to verify
    /// * `policy` - Evidence policy defining verification requirements
    ///
    /// # Returns
    /// An [`AttestationResult`] containing the detached EAT and claims
    pub fn verify(
        &self,
        evidence: &types::SwitchEvidenceCollection,
        policy: &EvidencePolicy,
    ) -> Result<AttestationResult> {
        let mut eat_ptr = ptr::null_mut();
        let mut claims_ptr = ptr::null_mut();

        unsafe {
            // Upcast to base verifier type
            let base_verifier = nvat_switch_nras_verifier_upcast(self.inner);

            NvatError::check(nvat_verify_switch_evidence(
                base_verifier,
                evidence.as_ptr(),
                evidence.len(),
                policy.inner,
                &mut eat_ptr,
                &mut claims_ptr,
            ))?;
        }

        Ok(AttestationResult {
            detached_eat: if eat_ptr.is_null() {
                None
            } else {
                Some(NvatString::from_raw(eat_ptr))
            },
            claims: if claims_ptr.is_null() {
                None
            } else {
                Some(ClaimsCollection::from_raw(claims_ptr))
            },
        })
    }
}

impl Drop for SwitchNrasVerifier {
    fn drop(&mut self) {
        unsafe {
            // Upcast to base type before freeing
            let mut base_verifier = nvat_switch_nras_verifier_upcast(self.inner);
            nvat_switch_verifier_free(&mut base_verifier);
        }
    }
}
