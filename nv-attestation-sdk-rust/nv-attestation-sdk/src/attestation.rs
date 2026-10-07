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
use crate::types::{HttpOptions, JwtValidationOptions, Nonce, NvatString, SdkOptions};
use crate::util::{optional_cstring, required_cstring};
use crate::*;
#[cfg(feature = "logging")]
use log::{debug, info, warn};
use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::path::Path;
use std::ptr;
use std::rc::Rc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

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

#[cfg(feature = "logging")]
macro_rules! log_warn {
    ($($arg:tt)*) => { warn!($($arg)*); };
}

#[cfg(not(feature = "logging"))]
macro_rules! log_warn {
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
///
/// ```compile_fail
/// fn assert_send<T: Send>() {}
/// assert_send::<nv_attestation_sdk::NvatSdk>();
/// ```
pub struct NvatSdk {
    // Lifecycle marker for SDK initialization. Rc prevents Send/Sync because the
    // C SDK initialization/shutdown lifecycle is process-global and main-thread-only.
    _not_send_sync: PhantomData<Rc<()>>,
}

const SDK_STATE_UNINITIALIZED: u8 = 0;
const SDK_STATE_ACTIVE: u8 = 1;
const SDK_STATE_SHUTDOWN: u8 = 2;

static SDK_STATE: AtomicU8 = AtomicU8::new(SDK_STATE_UNINITIALIZED);

impl NvatSdk {
    /// Initialize SDK. Wraps `nvat_sdk_init`.
    ///
    /// Call once per process from the main thread. SDK shuts down when dropped.
    pub fn init(opts: SdkOptions) -> Result<Self> {
        // AcqRel mirrors a mutex-style acquire over the C SDK's process-global
        // state; pairs with the Release stores below.
        match SDK_STATE.compare_exchange(
            SDK_STATE_UNINITIALIZED,
            SDK_STATE_ACTIVE,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(SDK_STATE_ACTIVE) => {
                log_warn!(
                    "NVAT SDK already initialized; rejecting duplicate lifecycle guard. \
                     NvatSdk must be created once per process."
                );
                return Err(NvatError::new(NVAT_RC_INTERNAL_ERROR as u16));
            }
            Err(SDK_STATE_SHUTDOWN) => {
                log_warn!(
                    "NVAT SDK has already been shut down; rejecting reinitialization. \
                     The underlying C SDK supports one init/shutdown lifecycle per process."
                );
                return Err(NvatError::new(NVAT_RC_INTERNAL_ERROR as u16));
            }
            Err(_) => return Err(NvatError::new(NVAT_RC_INTERNAL_ERROR as u16)),
        }

        // Resets SDK_STATE on any early return (error, panic) before we commit
        // ownership to the returned NvatSdk.
        struct ActiveGuard {
            committed: bool,
        }
        impl Drop for ActiveGuard {
            fn drop(&mut self) {
                if !self.committed {
                    SDK_STATE.store(SDK_STATE_UNINITIALIZED, Ordering::Release);
                }
            }
        }
        let mut active_guard = ActiveGuard { committed: false };

        log_info!("Initializing NVAT SDK version {}", Self::version());
        unsafe {
            NvatError::check(nvat_sdk_init(opts.as_ptr()))?;
        }
        // Note: opts will be properly freed via Drop when it goes out of scope.
        // The C SDK copies the shared_ptr internally, so we must free the wrapper.
        active_guard.committed = true;
        Ok(NvatSdk {
            _not_send_sync: PhantomData,
        })
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
        // Move to a terminal state only after shutdown returns. A concurrent
        // init() must not observe a reusable state while shutdown is running.
        SDK_STATE.store(SDK_STATE_SHUTDOWN, Ordering::Release);
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
///
/// ```compile_fail
/// fn assert_send<T: Send>() {}
/// assert_send::<nv_attestation_sdk::AttestationContext>();
/// ```
pub struct AttestationContext {
    inner: nvat_attestation_ctx_t,
    // The C setter does not take ownership of the detached EAT options, and the
    // options must stay valid until attestation runs. Hold them here so they
    // outlive the context.
    detached_eat_options: Option<DetachedEatOptions>,
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
        Ok(AttestationContext {
            inner: ctx,
            detached_eat_options: None,
        })
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

    /// Set the options used to sign the detached EAT produced by attestation.
    /// Wraps `nvat_attestation_ctx_set_detached_eat_options`.
    ///
    /// Without this, the SDK signs the detached EAT with a default identity.
    /// The context keeps the options for its lifetime.
    pub fn set_detached_eat_options(&mut self, options: DetachedEatOptions) -> Result<()> {
        unsafe {
            NvatError::check(nvat_attestation_ctx_set_detached_eat_options(
                self.inner,
                options.as_ptr(),
            ))?;
        }
        self.detached_eat_options = Some(options);
        Ok(())
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

        let rc =
            unsafe { nvat_attest_device(self.inner, nonce_ptr, &mut eat_ptr, &mut claims_ptr) };

        let result = AttestationResult::from_ffi(rc, eat_ptr, claims_ptr)?;
        log_info!("Attestation request completed");

        Ok(result)
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
    detached_eat_options: Option<DetachedEatOptions>,
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

    /// Set the options used to sign the detached EAT produced by attestation.
    pub fn detached_eat_options(mut self, options: DetachedEatOptions) -> Self {
        self.detached_eat_options = Some(options);
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
        if let Some(options) = self.detached_eat_options {
            ctx.set_detached_eat_options(options)?;
        }

        Ok(ctx)
    }
}

/// Attestation result: the detached EAT, claims, and the overall verdict.
///
/// A negative verdict (`NVAT_RC_OVERALL_RESULT_FALSE`) or relying-party policy
/// mismatch (`NVAT_RC_RP_POLICY_MISMATCH`) is reported via `result_code` rather
/// than as an error, since the C SDK still produces a signed token and claims for
/// those codes. Use `is_success` to branch on the verdict.
pub struct AttestationResult {
    /// The detached Entity Attestation Token (EAT)
    pub detached_eat: Option<NvatString>,
    /// Collection of claims about the attested device(s)
    pub claims: Option<ClaimsCollection>,
    /// The raw result code carrying the overall verdict
    pub result_code: u16,
}

impl AttestationResult {
    /// Build a result from an FFI return code and the EAT/claims out-pointers.
    ///
    /// `OK`, `NVAT_RC_OVERALL_RESULT_FALSE`, and `NVAT_RC_RP_POLICY_MISMATCH` carry
    /// a result: the C SDK populates the token and claims for them, so the verdict
    /// is kept in `result_code` rather than raised as an error. Any other code is a
    /// genuine failure and returns `Err`.
    pub(crate) fn from_ffi(
        code: nvat_rc_t,
        eat_ptr: nvat_str_t,
        claims_ptr: nvat_claims_collection_t,
    ) -> Result<Self> {
        if code != NVAT_RC_OK as u16
            && code != NVAT_RC_OVERALL_RESULT_FALSE as u16
            && code != NVAT_RC_RP_POLICY_MISMATCH as u16
        {
            return Err(NvatError::new(code));
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
            result_code: code,
        })
    }

    /// `true` if the overall verdict passed (`NVAT_RC_OK`). A negative verdict is
    /// still `Ok` (so the signed token can be relayed); branch on this instead.
    pub fn is_success(&self) -> bool {
        self.result_code == NVAT_RC_OK as u16
    }

    /// Human-readable message for the result code.
    pub fn result_message(&self) -> String {
        NvatError::new(self.result_code).message()
    }

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
///
/// Owned collection of verified claims.
///
/// # Thread Safety
///
/// `ClaimsCollection` is `Send` but not `Sync`: a collection may move across
/// threads, but concurrent access to one collection from multiple threads is
/// not supported.
///
/// ```compile_fail
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<nv_attestation_sdk::ClaimsCollection>();
/// ```
pub struct ClaimsCollection {
    inner: nvat_claims_collection_t,
}

impl std::fmt::Debug for ClaimsCollection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaimsCollection").finish_non_exhaustive()
    }
}

impl ClaimsCollection {
    /// Assemble and sign the detached EAT from these claims with the given
    /// options. Wraps `nvat_get_detached_eat_es384`. Suits re-signing after a
    /// key rotation without rebuilding the verifier.
    pub fn detached_eat_es384(&self, options: &DetachedEatOptions) -> Result<String> {
        let mut out = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_get_detached_eat_es384(
                self.inner,
                options.as_ptr(),
                &mut out,
            ))?;
        }
        NvatString::from_raw(out).to_string()
    }

    /// Append every claim from `other` into this collection, leaving `other`
    /// unchanged. Wraps `nvat_claims_collection_extend`. Suits merging
    /// per-device claims verified separately before assembling one detached
    /// EAT for all of them.
    pub fn extend(&mut self, other: &ClaimsCollection) -> Result<()> {
        unsafe { NvatError::check(nvat_claims_collection_extend(self.inner, other.inner)) }
    }

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

// SAFETY: the native collection is a plain heap container
// (std::vector<std::shared_ptr<Claims>>) of immutable claim data with no
// thread-local state, and shared_ptr reference counts are atomic, so the
// handle may move to another thread (for example from a per-device
// verification thread to the thread that merges and signs). Not Sync:
// concurrent access from multiple threads is not part of the C API contract.
unsafe impl Send for ClaimsCollection {}

/// Safe wrapper around `nvat_detached_eat_options_t`.
///
/// The P-384 signing key, issuer, and key id used to sign a detached EAT
/// ([`AttestationContext::set_detached_eat_options`]) or a CoRIM EAR
/// ([`crate::LocalCorimVerifier::verify_cmw`], via the
/// [`crate::EarSigningOptions`] alias).
/// Cloning is cheap: clones share the same native options.
#[derive(Clone)]
pub struct DetachedEatOptions {
    inner: Arc<DetachedEatOptionsHandle>,
}

// Sole owner of the native handle, so clones of `DetachedEatOptions` share one
// allocation and free it exactly once. `Arc` rather than `Rc` because a
// verifier holds these options and may be shared across a thread pool, which
// puts the reference count itself on the concurrent path.
struct DetachedEatOptionsHandle(nvat_detached_eat_options_t);

// SAFETY: the native options object is three owned strings (private key PEM,
// issuer, key id) written once by `nvat_detached_eat_options_create` and only
// read afterwards, by the signing path. It owns no thread-local or shared
// mutable state, and the `Arc` frees it exactly once on the last drop.
unsafe impl Send for DetachedEatOptionsHandle {}
unsafe impl Sync for DetachedEatOptionsHandle {}

impl Drop for DetachedEatOptionsHandle {
    fn drop(&mut self) {
        unsafe {
            nvat_detached_eat_options_free(&mut self.0);
        }
    }
}

impl std::fmt::Debug for DetachedEatOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetachedEatOptions").finish_non_exhaustive()
    }
}

impl DetachedEatOptions {
    /// Create detached EAT signing options. Wraps `nvat_detached_eat_options_create`.
    ///
    /// `private_key_pem` must be a PEM-encoded ECDSA P-384 private key.
    pub fn new(private_key_pem: &str, issuer: &str, kid: &str) -> Result<Self> {
        let c_key = CString::new(private_key_pem)
            .map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        let c_issuer =
            CString::new(issuer).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        let c_kid = CString::new(kid).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        let mut options = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_detached_eat_options_create(
                &mut options,
                c_key.as_ptr(),
                c_issuer.as_ptr(),
                c_kid.as_ptr(),
            ))?;
        }
        Ok(DetachedEatOptions {
            inner: Arc::new(DetachedEatOptionsHandle(options)),
        })
    }

    pub(crate) fn as_ptr(&self) -> nvat_detached_eat_options_t {
        self.inner.0
    }
}

/// Safe wrapper around nvat_evidence_policy_t
///
/// # Thread Safety
///
/// `Send` and `Sync`. A policy is read-only configuration once built, so one
/// policy may be shared by reference across threads.
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
///
/// # Thread Safety
///
/// `Send` and `Sync`. A cached client built with [`OcspClient::create_cached`]
/// may be shared by reference across threads so that they share one response
/// cache; the cache serializes its own reads and writes.
pub struct OcspClient {
    pub(crate) inner: nvat_ocsp_client_t,
}

/// Hash algorithm used to construct OCSP CertIDs.
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OcspCertIdHashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
}

/// Construction options for an [`OcspClient`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct OcspClientOptions {
    /// Hash algorithm used to construct OCSP CertIDs.
    pub cert_id_hash_algorithm: OcspCertIdHashAlgorithm,
}

impl Default for OcspClientOptions {
    fn default() -> Self {
        Self {
            cert_id_hash_algorithm: OcspCertIdHashAlgorithm::Sha256,
        }
    }
}

/// Owns the temporary C options handle passed to an OCSP constructor.
struct OcspClientOptionsHandle(nvat_ocsp_client_options_t);

impl OcspClientOptionsHandle {
    fn new(options: OcspClientOptions) -> Result<Self> {
        let mut inner = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_ocsp_client_options_create_default(&mut inner))?;
        }
        let handle = Self(inner);
        let algorithm = match options.cert_id_hash_algorithm {
            OcspCertIdHashAlgorithm::Sha1 => {
                nvat_ocsp_cert_id_hash_algorithm_t_NVAT_OCSP_CERT_ID_HASH_SHA1
            }
            OcspCertIdHashAlgorithm::Sha256 => {
                nvat_ocsp_cert_id_hash_algorithm_t_NVAT_OCSP_CERT_ID_HASH_SHA256
            }
            OcspCertIdHashAlgorithm::Sha384 => {
                nvat_ocsp_cert_id_hash_algorithm_t_NVAT_OCSP_CERT_ID_HASH_SHA384
            }
        };
        unsafe {
            NvatError::check(nvat_ocsp_client_options_set_cert_id_hash_algorithm(
                handle.0, algorithm,
            ))?;
        }
        Ok(handle)
    }
}

impl Drop for OcspClientOptionsHandle {
    fn drop(&mut self) {
        unsafe {
            nvat_ocsp_client_options_free(&mut self.0);
        }
    }
}

/// A responder URL rewrite: the leading `pattern` is replaced with
/// `replacement`.
pub struct UrlRewrite<'a> {
    /// URL prefix to match.
    pub pattern: &'a str,
    /// Substituted for `pattern`.
    pub replacement: &'a str,
}

/// Options for [`OcspClient::create_aia`]. Every field falls back to the SDK
/// default.
#[derive(Default)]
pub struct AiaOptions<'a> {
    /// Responder URL used at construction.
    pub base_url: Option<&'a str>,
    /// Service key for authenticated calls.
    pub service_key: Option<&'a str>,
    /// HTTP options for the responder requests.
    pub http_options: Option<&'a HttpOptions>,
    /// OCSP client construction options. `None` uses SHA-256 defaults.
    pub client_options: Option<OcspClientOptions>,
    /// Applied to the responder URL; the first match wins.
    pub rewrites: &'a [UrlRewrite<'a>],
}

impl OcspClient {
    /// Create a default OCSP client
    pub fn create_default(
        base_url: Option<&str>,
        service_key: Option<&str>,
        http_options: Option<&HttpOptions>,
    ) -> Result<Self> {
        Self::create_default_impl(base_url, service_key, http_options, ptr::null_mut())
    }

    /// Create a default OCSP client with explicit construction options.
    pub fn create_default_with_options(
        base_url: Option<&str>,
        service_key: Option<&str>,
        http_options: Option<&HttpOptions>,
        options: OcspClientOptions,
    ) -> Result<Self> {
        let options_handle = OcspClientOptionsHandle::new(options)?;
        Self::create_default_impl(base_url, service_key, http_options, options_handle.0)
    }

    fn create_default_impl(
        base_url: Option<&str>,
        service_key: Option<&str>,
        http_options: Option<&HttpOptions>,
        options: nvat_ocsp_client_options_t,
    ) -> Result<Self> {
        // Keep CStrings alive until after FFI call to avoid dangling pointers
        let url_cstring = optional_cstring(base_url)?;
        let url_ptr = url_cstring
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(ptr::null());

        let key_cstring = optional_cstring(service_key)?;
        let key_ptr = key_cstring
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(ptr::null());

        let opts_ptr = http_options.map(|o| o.as_ptr()).unwrap_or(ptr::null_mut());

        let mut client = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_ocsp_client_create_default_with_options(
                &mut client,
                url_ptr,
                key_ptr,
                opts_ptr,
                options,
            ))?;
        }
        Ok(OcspClient { inner: client })
    }

    /// Create an OCSP client that resolves a responder per certificate.
    /// Wraps `nvat_ocsp_client_create_aia`.
    ///
    /// Each responder URL comes from the certificate's Authority Information
    /// Access extension; a certificate without one is skipped rather than
    /// queried against `base_url`.
    pub fn create_aia(options: AiaOptions<'_>) -> Result<Self> {
        let AiaOptions {
            base_url,
            service_key,
            http_options,
            client_options,
            rewrites,
        } = options;
        let options_handle = client_options
            .map(OcspClientOptionsHandle::new)
            .transpose()?;
        let options_ptr = options_handle
            .as_ref()
            .map(|handle| handle.0)
            .unwrap_or(ptr::null_mut());
        // Keep CStrings alive until after FFI call to avoid dangling pointers
        let url_cstring = optional_cstring(base_url)?;
        let url_ptr = url_cstring
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(ptr::null());

        let key_cstring = optional_cstring(service_key)?;
        let key_ptr = key_cstring
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(ptr::null());

        let opts_ptr = http_options.map(|o| o.as_ptr()).unwrap_or(ptr::null_mut());

        let pattern_cstrings = rewrites
            .iter()
            .map(|r| required_cstring(r.pattern))
            .collect::<Result<Vec<_>>>()?;
        let replacement_cstrings = rewrites
            .iter()
            .map(|r| required_cstring(r.replacement))
            .collect::<Result<Vec<_>>>()?;

        // These arrays hold pointers into the CStrings above, so both outlive the call.
        let pattern_ptrs: Vec<_> = pattern_cstrings.iter().map(|s| s.as_ptr()).collect();
        let replacement_ptrs: Vec<_> = replacement_cstrings.iter().map(|s| s.as_ptr()).collect();
        // With no rewrites, pass NULL rather than a dangling empty-Vec pointer.
        let (pattern_array, replacement_array) = if rewrites.is_empty() {
            (ptr::null(), ptr::null())
        } else {
            (pattern_ptrs.as_ptr(), replacement_ptrs.as_ptr())
        };

        let mut client = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_ocsp_client_create_aia(
                &mut client,
                url_ptr,
                key_ptr,
                opts_ptr,
                pattern_array,
                replacement_array,
                rewrites.len(),
                options_ptr,
            ))?;
        }
        Ok(OcspClient { inner: client })
    }

    /// Wrap an OCSP client with an in-memory response cache.
    /// Wraps `nvat_ocsp_client_create_cached`.
    ///
    /// Responses are cached per (subject, issuer) certificate pair for
    /// `min(ttl_seconds, response nextUpdate)`, bounded by `max_size_bytes`.
    /// The underlying C++ layer retains the inner client, so consuming the
    /// Rust handle here is safe.
    pub fn create_cached(inner: OcspClient, max_size_bytes: u64, ttl_seconds: i64) -> Result<Self> {
        let mut client = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_ocsp_client_create_cached(
                &mut client,
                inner.inner,
                max_size_bytes,
                ttl_seconds,
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
///
/// # Thread Safety
///
/// `Send` and `Sync`. A cached store built with [`RimStore::create_cached`] may
/// be shared by reference across threads so that they share one RIM cache; the
/// cache serializes its own reads and writes and hands out an independently
/// parsed document per hit.
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

    /// Wrap a RIM store with an in-memory cache.
    /// Wraps `nvat_rim_store_create_cached`.
    ///
    /// Fetched RIM documents are cached for `ttl_seconds`, bounded by
    /// `max_size_bytes`. The underlying C++ layer retains the inner store,
    /// so consuming the Rust handle here is safe.
    pub fn create_cached(inner: RimStore, max_size_bytes: u64, ttl_seconds: i64) -> Result<Self> {
        let mut store = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_rim_store_create_cached(
                &mut store,
                inner.inner,
                max_size_bytes,
                ttl_seconds,
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
///
/// # Thread Safety
///
/// `Send` and `Sync`. Verification does not mutate the verifier, so one
/// verifier may be shared by reference across threads, which is how a service
/// verifies concurrently over a single RIM and OCSP cache.
pub struct GpuLocalVerifier {
    inner: nvat_gpu_local_verifier_t,
    // Signing options passed at construction; held so the native options the
    // verifier references stay valid for its lifetime.
    _detached_eat_options: Option<DetachedEatOptions>,
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
        Ok(GpuLocalVerifier {
            inner: verifier,
            _detached_eat_options: None,
        })
    }

    /// Create a local GPU verifier whose detached EATs are signed with the
    /// given options instead of the default identity.
    /// Wraps `nvat_gpu_local_verifier_create`.
    pub fn new_with_signing(
        rim_store: &RimStore,
        ocsp_client: &OcspClient,
        options: DetachedEatOptions,
    ) -> Result<Self> {
        let mut verifier = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_gpu_local_verifier_create(
                &mut verifier,
                rim_store.inner,
                ocsp_client.inner,
                options.as_ptr(),
            ))?;
        }
        Ok(GpuLocalVerifier {
            inner: verifier,
            _detached_eat_options: Some(options),
        })
    }

    /// Verify GPU evidence against a policy. Wraps `nvat_verify_gpu_evidence`.
    ///
    /// # Arguments
    /// * `evidence` - Collection of GPU evidence to verify
    /// * `policy` - Evidence policy defining verification requirements
    ///
    /// # Returns
    /// An [`AttestationResult`] with the detached EAT, claims, and verdict. A
    /// negative verdict is returned as `Ok`; inspect `result_code`/`is_success`.
    pub fn verify(
        &self,
        evidence: &types::GpuEvidenceCollection,
        policy: &EvidencePolicy,
    ) -> Result<AttestationResult> {
        let mut eat_ptr = ptr::null_mut();
        let mut claims_ptr = ptr::null_mut();

        let rc = unsafe {
            // Upcast to base verifier type
            let base_verifier = nvat_gpu_local_verifier_upcast(self.inner);

            nvat_verify_gpu_evidence(
                base_verifier,
                evidence.as_ptr(),
                evidence.len(),
                policy.inner,
                &mut eat_ptr,
                &mut claims_ptr,
            )
        };

        AttestationResult::from_ffi(rc, eat_ptr, claims_ptr)
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
    /// An [`AttestationResult`] with the detached EAT, claims, and verdict. A
    /// negative verdict is returned as `Ok`; inspect `result_code`/`is_success`.
    pub fn verify(
        &self,
        evidence: &types::GpuEvidenceCollection,
        policy: &EvidencePolicy,
    ) -> Result<AttestationResult> {
        let mut eat_ptr = ptr::null_mut();
        let mut claims_ptr = ptr::null_mut();

        let rc = unsafe {
            // Upcast to base verifier type
            let base_verifier = nvat_gpu_nras_verifier_upcast(self.inner);

            nvat_verify_gpu_evidence(
                base_verifier,
                evidence.as_ptr(),
                evidence.len(),
                policy.inner,
                &mut eat_ptr,
                &mut claims_ptr,
            )
        };

        AttestationResult::from_ffi(rc, eat_ptr, claims_ptr)
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
///
/// # Thread Safety
///
/// `Send` and `Sync`. Verification does not mutate the verifier, so one
/// verifier may be shared by reference across threads, which is how a service
/// verifies concurrently over a single RIM and OCSP cache.
pub struct SwitchLocalVerifier {
    inner: nvat_switch_local_verifier_t,
    // Signing options passed at construction; held so the native options the
    // verifier references stay valid for its lifetime.
    _detached_eat_options: Option<DetachedEatOptions>,
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
        Ok(SwitchLocalVerifier {
            inner: verifier,
            _detached_eat_options: None,
        })
    }

    /// Create a local NVSwitch verifier whose detached EATs are signed with
    /// the given options instead of the default identity.
    /// Wraps `nvat_switch_local_verifier_create`.
    pub fn new_with_signing(
        rim_store: &RimStore,
        ocsp_client: &OcspClient,
        options: DetachedEatOptions,
    ) -> Result<Self> {
        let mut verifier = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_switch_local_verifier_create(
                &mut verifier,
                rim_store.inner,
                ocsp_client.inner,
                options.as_ptr(),
            ))?;
        }
        Ok(SwitchLocalVerifier {
            inner: verifier,
            _detached_eat_options: Some(options),
        })
    }

    /// Verify NVSwitch evidence against a policy. Wraps `nvat_verify_switch_evidence`.
    ///
    /// # Arguments
    /// * `evidence` - Collection of NVSwitch evidence to verify
    /// * `policy` - Evidence policy defining verification requirements
    ///
    /// # Returns
    /// An [`AttestationResult`] with the detached EAT, claims, and verdict. A
    /// negative verdict is returned as `Ok`; inspect `result_code`/`is_success`.
    pub fn verify(
        &self,
        evidence: &types::SwitchEvidenceCollection,
        policy: &EvidencePolicy,
    ) -> Result<AttestationResult> {
        let mut eat_ptr = ptr::null_mut();
        let mut claims_ptr = ptr::null_mut();

        let rc = unsafe {
            // Upcast to base verifier type
            let base_verifier = nvat_switch_local_verifier_upcast(self.inner);

            nvat_verify_switch_evidence(
                base_verifier,
                evidence.as_ptr(),
                evidence.len(),
                policy.inner,
                &mut eat_ptr,
                &mut claims_ptr,
            )
        };

        AttestationResult::from_ffi(rc, eat_ptr, claims_ptr)
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
    /// An [`AttestationResult`] with the detached EAT, claims, and verdict. A
    /// negative verdict is returned as `Ok`; inspect `result_code`/`is_success`.
    pub fn verify(
        &self,
        evidence: &types::SwitchEvidenceCollection,
        policy: &EvidencePolicy,
    ) -> Result<AttestationResult> {
        let mut eat_ptr = ptr::null_mut();
        let mut claims_ptr = ptr::null_mut();

        let rc = unsafe {
            // Upcast to base verifier type
            let base_verifier = nvat_switch_nras_verifier_upcast(self.inner);

            nvat_verify_switch_evidence(
                base_verifier,
                evidence.as_ptr(),
                evidence.len(),
                policy.inner,
                &mut eat_ptr,
                &mut claims_ptr,
            )
        };

        AttestationResult::from_ffi(rc, eat_ptr, claims_ptr)
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

/// Result of a successful NRAS attestation result verification.
///
/// Returned for a token whose signature, issuer, and structure verified — i.e.
/// both `NVAT_RC_OK` and `NVAT_RC_OVERALL_RESULT_FALSE`. Inspect
/// `overall_result_passed` to distinguish them.
#[derive(Debug)]
pub struct VerifiedAttestationResult {
    /// The verified, decoded claims.
    pub claims: ClaimsCollection,
    /// `true` when the token's overall attestation result is true (`NVAT_RC_OK`);
    /// `false` when the token verified but its overall result is false
    /// (`NVAT_RC_OVERALL_RESULT_FALSE`).
    pub overall_result_passed: bool,
}

/// Verify a detached EAT issued by NRAS against the JWKS published at
/// `nras_base_url`/.well-known/jwks.json and return the verified claims.
///
/// Returns `Ok(VerifiedAttestationResult)` for both `NVAT_RC_OK` and
/// `NVAT_RC_OVERALL_RESULT_FALSE` (signature verified; claims present in both).
/// Returns `Err` for genuine failures (invalid token, bad argument, HTTP/JWKS
/// errors) — those have no claims.
///
/// This is a convenience wrapper around [`verify_attestation_result_with_options`] with
/// no expected nonce and no custom HTTP/TLS options.
pub fn verify_attestation_result(
    eat: &str,
    nras_base_url: &str,
) -> Result<VerifiedAttestationResult> {
    verify_attestation_result_with_options(eat, nras_base_url, None, None, None, None)
}

/// Like [`verify_attestation_result`] but with an optional service key, an
/// optional expected nonce, HTTP/TLS options, and JWT time-claim settings.
///
/// `service_key` is sent with the JWKS fetch. The public NRAS JWKS endpoint does
/// not require one, so `None` (send no credential) is the common case; supply
/// `Some(key)` for deployments that authenticate the JWKS fetch.
///
/// When `expected_nonce` is `Some`, the token's overall `eat_nonce` must equal
/// it or verification fails with `NVAT_RC_NONCE_MISMATCH`. `None` skips the
/// nonce comparison (the token must still contain a nonce).
///
/// `jwt_validation_options` configures the leeway applied to the JWT `exp`,
/// `nbf`, and `iat` claims. `None` uses the 60-second default.
pub fn verify_attestation_result_with_options(
    eat: &str,
    nras_base_url: &str,
    service_key: Option<&str>,
    expected_nonce: Option<&Nonce>,
    http_options: Option<&HttpOptions>,
    jwt_validation_options: Option<&JwtValidationOptions>,
) -> Result<VerifiedAttestationResult> {
    let eat_c = CString::new(eat).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
    let url_c =
        CString::new(nras_base_url).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
    let service_key_c = service_key
        .map(|k| CString::new(k).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16)))
        .transpose()?;
    let service_key_ptr = service_key_c
        .as_ref()
        .map(|k| k.as_ptr())
        .unwrap_or(ptr::null());
    let nonce_ptr = expected_nonce
        .map(|n| n.as_ptr())
        .unwrap_or(ptr::null_mut());
    let http_ptr = http_options.map(|o| o.as_ptr()).unwrap_or(ptr::null_mut());
    let jwt_options_ptr = jwt_validation_options
        .map(|o| o.as_ptr())
        .unwrap_or(ptr::null_mut());
    let mut claims_ptr = ptr::null_mut();
    let rc = unsafe {
        nvat_verify_attestation_result(
            eat_c.as_ptr(),
            url_c.as_ptr(),
            service_key_ptr,
            nonce_ptr,
            http_ptr,
            jwt_options_ptr,
            &mut claims_ptr,
        )
    };

    let ok = rc == NVAT_RC_OK as u16;
    let overall_false = rc == NVAT_RC_OVERALL_RESULT_FALSE as u16;
    if ok || overall_false {
        if claims_ptr.is_null() {
            return Err(NvatError::new(NVAT_RC_INTERNAL_ERROR as u16));
        }
        return Ok(VerifiedAttestationResult {
            claims: ClaimsCollection::from_raw(claims_ptr),
            overall_result_passed: ok,
        });
    }
    // Genuine failure: claims normally not set, but wrap-to-free if non-null to avoid any leak.
    if !claims_ptr.is_null() {
        let _ = ClaimsCollection::from_raw(claims_ptr);
    }
    Err(NvatError::new(rc))
}

/// Authenticate a signed EAR against the verifier's published JWKS and return
/// its authenticated JSON payload.
///
/// This is a convenience wrapper around [`verify_ear_with_options`] with no
/// expected nonce and default HTTP/TLS and JWT-validation options.
pub fn verify_ear(ear_jwt: &str, verifier_base_url: &str) -> Result<String> {
    verify_ear_with_options(ear_jwt, verifier_base_url, None, None, None, None)
}

/// Authenticate a signed EAR against the verifier's published JWKS and return
/// its authenticated JSON payload.
///
/// Fetches `<verifier_base_url>/.well-known/jwks.json`, then verifies the EAR
/// signature, issuer, key ID, and present JWT time claims. When
/// `expected_nonce` is `Some`, the EAR's `eat_nonce` must match it. `None`
/// skips nonce comparison. `jwt_validation_options` configures the leeway for
/// present `exp`, `nbf`, and `iat` claims; `None` uses the 60-second default.
///
/// `service_key` is sent only when the JWKS host is HTTPS `nvidia.com` or one
/// of its subdomains. This function authenticates a JWT but does not validate
/// the EAR schema or make an appraisal decision; use
/// [`RelyingPartyPolicy::apply_to_ear_json`] for policy evaluation.
pub fn verify_ear_with_options(
    ear_jwt: &str,
    verifier_base_url: &str,
    service_key: Option<&str>,
    expected_nonce: Option<&Nonce>,
    http_options: Option<&HttpOptions>,
    jwt_validation_options: Option<&JwtValidationOptions>,
) -> Result<String> {
    let ear_c = CString::new(ear_jwt).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
    let url_c =
        CString::new(verifier_base_url).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
    let service_key_c = service_key
        .map(|key| CString::new(key).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16)))
        .transpose()?;
    let service_key_ptr = service_key_c
        .as_ref()
        .map(|key| key.as_ptr())
        .unwrap_or(ptr::null());
    let nonce_ptr = expected_nonce
        .map(|nonce| nonce.as_ptr())
        .unwrap_or(ptr::null_mut());
    let http_ptr = http_options
        .map(|options| options.as_ptr())
        .unwrap_or(ptr::null_mut());
    let jwt_options_ptr = jwt_validation_options
        .map(|options| options.as_ptr())
        .unwrap_or(ptr::null_mut());
    let mut ear_json_ptr = ptr::null_mut();
    let rc = unsafe {
        nvat_verify_ear(
            ear_c.as_ptr(),
            url_c.as_ptr(),
            service_key_ptr,
            nonce_ptr,
            http_ptr,
            jwt_options_ptr,
            &mut ear_json_ptr,
        )
    };
    if rc != NVAT_RC_OK as u16 {
        if !ear_json_ptr.is_null() {
            let _ = NvatString::from_raw(ear_json_ptr);
        }
        return Err(NvatError::new(rc));
    }
    if ear_json_ptr.is_null() {
        return Err(NvatError::new(NVAT_RC_INTERNAL_ERROR as u16));
    }
    NvatString::from_raw(ear_json_ptr).to_string()
}

/// Safe wrapper around `nvat_relying_party_policy_t`.
///
/// Holds a compiled Rego policy for evaluating verified attestation claims.
/// Automatically freed on drop.
pub struct RelyingPartyPolicy {
    inner: nvat_relying_party_policy_t,
}

impl RelyingPartyPolicy {
    /// Compile a Rego policy from a string. Wraps
    /// `nvat_relying_party_policy_create_rego_from_str`.
    pub fn from_rego(rego: &str) -> Result<Self> {
        let c = CString::new(rego).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        let mut inner = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_relying_party_policy_create_rego_from_str(
                &mut inner,
                c.as_ptr(),
            ))?;
        }
        Ok(RelyingPartyPolicy { inner })
    }

    /// Evaluate the policy against a claims collection.
    ///
    /// Returns `Ok(())` when the policy match succeeds; returns `Err` with the
    /// policy-mismatch code otherwise.
    pub fn apply(&self, claims: &ClaimsCollection) -> Result<()> {
        unsafe { NvatError::check(nvat_apply_relying_party_policy(self.inner, claims.inner)) }
    }

    /// Evaluate the policy against an EAR JSON object.
    ///
    /// The EAR must already be authenticated when it came from an untrusted
    /// source. This evaluates the policy only; it does not verify a JWT,
    /// change `ear_status`, or modify the EAR.
    pub fn apply_to_ear_json(&self, ear_json: &str) -> Result<()> {
        let c_ear_json =
            CString::new(ear_json).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        unsafe {
            NvatError::check(nvat_apply_relying_party_policy_to_ear(
                self.inner,
                c_ear_json.as_ptr(),
            ))
        }
    }
}

impl Drop for RelyingPartyPolicy {
    fn drop(&mut self) {
        unsafe {
            nvat_relying_party_policy_free(&mut self.inner);
        }
    }
}

// ---------------------------------------------------------------------------
// Shared verify-path handles
// ---------------------------------------------------------------------------
//
// SAFETY, for every impl below. These five handles carry the state a service
// wants to build once and share, rather than duplicate per worker. Sharing is
// sound because verification neither mutates them nor reaches any thread-local
// or process-global state that is not already serialized:
//
// - Verification does not mutate the verifier. `LocalGpuVerifier` and
//   `LocalSwitchVerifier` assign their RIM store, OCSP client and detached-EAT
//   options in `create` and never again; `verify_evidence` is non-const only
//   because the `IGpuVerifier`/`ISwitchVerifier` interface declares it so, and
//   it delegates straight to a const method.
// - `EvidencePolicy` is read-only configuration after it is built.
// - The cached RIM store and cached OCSP client take an internal
//   `std::lock_guard` on every get and put, so concurrent lookups are
//   serialized by the cache itself.
// - The RIM cache stores the raw XML string, not a parsed tree, and builds a
//   fresh `RimDocument` on every hit, so no libxml document is ever shared.
// - The HTTP client holds immutable configuration, does its request through a
//   const method, and creates its own curl easy handle per call.
//
// Deliberately not extended to SDK lifecycle, evidence collection, or
// `AttestationContext`: those retain their existing single-thread contract.
unsafe impl Send for EvidencePolicy {}
unsafe impl Sync for EvidencePolicy {}
unsafe impl Send for OcspClient {}
unsafe impl Sync for OcspClient {}
unsafe impl Send for RimStore {}
unsafe impl Sync for RimStore {}
unsafe impl Send for GpuLocalVerifier {}
unsafe impl Sync for GpuLocalVerifier {}
unsafe impl Send for SwitchLocalVerifier {}
unsafe impl Sync for SwitchLocalVerifier {}
