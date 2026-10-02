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

//! CoRIM verification.
//!
//! Findings are collected - the caller derives the verdict from the returned
//! EAR. See `examples/corim_local_attestation.rs`.

use crate::attestation::{DetachedEatOptions, OcspClient};
use crate::error::{NvatError, Result};
use crate::types::{GpuEvidenceCollection, HttpOptions, Nonce, NvatString};
use crate::util::{optional_cstring, required_cstring};
use crate::*;

use std::fmt;
use std::mem::ManuallyDrop;
use std::ptr;

/// Serialization format of a CMW collection. Maps to `nvat_cmw_format_t`.
///
/// [`CmwFormat::Cbor`] is reserved and fails with `NVAT_RC_FEATURE_NOT_ENABLED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmwFormat {
    /// JSON encoding
    Json,
    /// CBOR encoding, not yet implemented
    Cbor,
}

impl From<CmwFormat> for nvat_cmw_format_t {
    fn from(format: CmwFormat) -> Self {
        match format {
            CmwFormat::Json => nvat_cmw_format_t_NVAT_CMW_FORMAT_JSON,
            CmwFormat::Cbor => nvat_cmw_format_t_NVAT_CMW_FORMAT_CBOR,
        }
    }
}

/// Hash algorithm for `ear_nvidia_inputs.digests`.
/// Maps to `nvat_hash_algorithm_t`, using IANA Named Information registry ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256, the default.
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
}

impl From<HashAlgorithm> for nvat_hash_algorithm_t {
    fn from(alg: HashAlgorithm) -> Self {
        match alg {
            HashAlgorithm::Sha256 => nvat_hash_algorithm_t_NVAT_HASH_ALGORITHM_SHA256,
            HashAlgorithm::Sha384 => nvat_hash_algorithm_t_NVAT_HASH_ALGORITHM_SHA384,
            HashAlgorithm::Sha512 => nvat_hash_algorithm_t_NVAT_HASH_ALGORITHM_SHA512,
        }
    }
}

/// Options for signing the EAR a CoRIM verification produces.
pub type EarSigningOptions = DetachedEatOptions;

/// The EAR (Entity Attestation Result) produced by a CoRIM verification.
///
/// Two forms of one appraisal: `jwt` to hand a relying party, `json` to read
/// claims locally without decoding it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EarResult {
    /// The EAR as a JWT. Unsigned unless [`EarSigningOptions`] are supplied.
    pub jwt: String,
    /// The same EAR as unsigned JSON.
    pub json: String,
}

/// Wrapper around `nvat_cmw_collection_t`: the evidence input to a CoRIM
/// verification. `Send` but not `Sync`.
pub struct CmwCollection {
    inner: nvat_cmw_collection_t,
}

impl CmwCollection {
    /// Build a CMW collection from collected GPU evidence.
    /// Wraps `nvat_cmw_collection_create_from_gpu_evidence`.
    ///
    /// Each item becomes a child labelled `gpu_<i>`, zero-based.
    pub fn from_gpu_evidence(evidence: &GpuEvidenceCollection, nonce: &Nonce) -> Result<Self> {
        if evidence.is_empty() {
            return Err(NvatError::new(NVAT_RC_BAD_ARGUMENT as u16));
        }

        let mut cmw = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_cmw_collection_create_from_gpu_evidence(
                &mut cmw,
                evidence.as_ptr(),
                evidence.len(),
                nonce.as_ptr(),
            ))?;
        }
        Ok(CmwCollection { inner: cmw })
    }

    /// Build a CMW collection from a raw SPDM transcript and PEM chain.
    /// Wraps `nvat_cmw_collection_create_from_spdm_transcript`.
    ///
    /// `nonce` is checked against the one signed into the transcript; `None`
    /// skips that check. Empty slices are rejected.
    pub fn from_spdm_transcript(
        label: &str,
        transcript: &[u8],
        cert_pem: &[u8],
        nonce: Option<&Nonce>,
    ) -> Result<Self> {
        if transcript.is_empty() || cert_pem.is_empty() {
            return Err(NvatError::new(NVAT_RC_BAD_ARGUMENT as u16));
        }
        let c_label = required_cstring(label)?;
        let nonce_ptr = nonce.map(|n| n.as_ptr()).unwrap_or(ptr::null_mut());

        let mut cmw = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_cmw_collection_create_from_spdm_transcript(
                &mut cmw,
                c_label.as_ptr(),
                transcript.as_ptr(),
                transcript.len(),
                cert_pem.as_ptr(),
                cert_pem.len(),
                nonce_ptr,
            ))?;
        }
        Ok(CmwCollection { inner: cmw })
    }

    /// Serialize the collection. Wraps `nvat_cmw_collection_serialize`.
    pub fn serialize(&self, format: CmwFormat) -> Result<String> {
        let mut str_ptr = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_cmw_collection_serialize(
                self.inner,
                format.into(),
                &mut str_ptr,
            ))?;
        }
        NvatString::from_raw(str_ptr).to_string()
    }
}

impl Drop for CmwCollection {
    fn drop(&mut self) {
        unsafe {
            nvat_cmw_collection_free(&mut self.inner);
        }
    }
}

/// Wrapper around `nvat_corim_store_t`: fetches CoRIMs from the rim-locator
/// URLs in the evidence, which default to NVIDIA's RIM service.
///
/// Consumed by [`LocalCorimVerifier::new`], so configure it first. `Send` but
/// not `Sync`.
pub struct CorimStore {
    inner: nvat_corim_store_t,
}

impl CorimStore {
    /// Create a CoRIM store. Wraps `nvat_corim_store_create`.
    pub fn new(service_key: Option<&str>, http_options: Option<&HttpOptions>) -> Result<Self> {
        // Keep the CString alive until after the FFI call.
        let key_cstring = optional_cstring(service_key)?;
        let key_ptr = key_cstring
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(ptr::null());
        let opts_ptr = http_options.map(|o| o.as_ptr()).unwrap_or(ptr::null_mut());

        let mut store = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_corim_store_create(&mut store, key_ptr, opts_ptr))?;
        }
        Ok(CorimStore { inner: store })
    }

    /// Replace a matching rim-locator URL prefix, first match wins.
    /// Wraps `nvat_corim_store_add_url_rewrite`.
    pub fn add_url_rewrite(&mut self, pattern: &str, replacement: &str) -> Result<()> {
        let c_pattern = required_cstring(pattern)?;
        let c_replacement = required_cstring(replacement)?;
        unsafe {
            NvatError::check(nvat_corim_store_add_url_rewrite(
                self.inner,
                c_pattern.as_ptr(),
                c_replacement.as_ptr(),
            ))
        }
    }

    /// Allow another `https://` URL prefix.
    /// Wraps `nvat_corim_store_add_allowed_url_prefix`.
    pub fn add_allowed_url_prefix(&mut self, prefix: &str) -> Result<()> {
        let c_prefix = required_cstring(prefix)?;
        unsafe {
            NvatError::check(nvat_corim_store_add_allowed_url_prefix(
                self.inner,
                c_prefix.as_ptr(),
            ))
        }
    }

    /// Enable in-memory LRU+TTL caching of fetched CoRIMs.
    /// Wraps `nvat_corim_store_enable_in_memory_cache`.
    ///
    /// The cache key is the effective URL, after rewrites, so subsequent fetches
    /// of the same CoRIM skip the network or filesystem entirely. Call this
    /// before [`LocalCorimVerifier::new`] takes ownership of the store.
    pub fn enable_in_memory_cache(&mut self, max_size_bytes: u64, ttl_seconds: i64) -> Result<()> {
        unsafe {
            NvatError::check(nvat_corim_store_enable_in_memory_cache(
                self.inner,
                max_size_bytes,
                ttl_seconds,
            ))
        }
    }

    /// Release the handle without freeing it, for the ownership transfer in
    /// [`LocalCorimVerifier::new`].
    fn into_raw(self) -> nvat_corim_store_t {
        ManuallyDrop::new(self).inner
    }
}

impl Drop for CorimStore {
    fn drop(&mut self) {
        unsafe {
            nvat_corim_store_free(&mut self.inner);
        }
    }
}

/// Wrapper around `nvat_local_corim_verifier_t`: appraises CMW evidence against
/// CoRIM reference values in-process.
///
/// `Send` and `Sync`, so a service can share one across threads.
pub struct LocalCorimVerifier {
    inner: nvat_local_corim_verifier_t,
}

impl LocalCorimVerifier {
    /// Create a local CoRIM verifier. Wraps `nvat_local_corim_verifier_create`.
    ///
    /// `corim_store` is consumed. Build `ocsp_client` with
    /// [`OcspClient::create_aia`](crate::OcspClient::create_aia), which this
    /// verifier expects; `None` disables revocation checking outright.
    pub fn new(corim_store: CorimStore, ocsp_client: Option<&OcspClient>) -> Result<Self> {
        let ocsp_ptr = ocsp_client.map(|c| c.inner).unwrap_or(ptr::null_mut());

        // On success the C API frees the store handle and NULLs it out; on
        // failure the handle survives and must be freed.
        let mut store_ptr = corim_store.into_raw();
        let mut verifier = ptr::null_mut();
        let rc =
            unsafe { nvat_local_corim_verifier_create(&mut verifier, &mut store_ptr, ocsp_ptr) };
        if let Err(err) = NvatError::check(rc) {
            if !store_ptr.is_null() {
                unsafe { nvat_corim_store_free(&mut store_ptr) };
            }
            return Err(err);
        }
        Ok(LocalCorimVerifier { inner: verifier })
    }

    /// Toggle CoRIM signature verification, on by default.
    /// Wraps `nvat_local_corim_verifier_set_verify_rim_signature`.
    ///
    /// Disabling also accepts unsigned CoRIMs - development only.
    pub fn set_verify_rim_signature(&mut self, enabled: bool) -> Result<()> {
        unsafe {
            NvatError::check(nvat_local_corim_verifier_set_verify_rim_signature(
                self.inner, enabled,
            ))
        }
    }

    /// Toggle OCSP revocation checking, on by default.
    /// Wraps `nvat_local_corim_verifier_set_verify_revocation`.
    pub fn set_verify_revocation(&mut self, enabled: bool) -> Result<()> {
        unsafe {
            NvatError::check(nvat_local_corim_verifier_set_verify_revocation(
                self.inner, enabled,
            ))
        }
    }

    /// Set a fallback ConciseEvidence blob, used when the SPDM evidence yields
    /// no claims. Wraps `nvat_local_corim_verifier_set_backup_spdm_coev`.
    pub fn set_backup_spdm_coev(&mut self, coev: &[u8]) -> Result<()> {
        if coev.is_empty() {
            return Err(NvatError::new(NVAT_RC_BAD_ARGUMENT as u16));
        }
        unsafe {
            NvatError::check(nvat_local_corim_verifier_set_backup_spdm_coev(
                self.inner,
                coev.as_ptr(),
                coev.len(),
            ))
        }
    }

    /// Append a fallback RIM locator URI, used when the evidence carries none.
    /// Wraps `nvat_local_corim_verifier_add_backup_rim_locator`.
    pub fn add_backup_rim_locator(&mut self, uri: &str) -> Result<()> {
        let c_uri = required_cstring(uri)?;
        unsafe {
            NvatError::check(nvat_local_corim_verifier_add_backup_rim_locator(
                self.inner,
                c_uri.as_ptr(),
            ))
        }
    }

    /// Set the hash algorithms used for `ear_nvidia_inputs.digests`.
    /// Wraps `nvat_local_corim_verifier_set_default_hash_algorithms`.
    ///
    /// Defaults to `[HashAlgorithm::Sha256]`; an empty slice disables digests.
    /// Evidence carrying `ars.digest-algos` overrides whatever is set here.
    pub fn set_default_hash_algorithms(&mut self, algs: &[HashAlgorithm]) -> Result<()> {
        let c_algs: Vec<nvat_hash_algorithm_t> = algs.iter().copied().map(Into::into).collect();
        unsafe {
            NvatError::check(nvat_local_corim_verifier_set_default_hash_algorithms(
                self.inner,
                c_algs.as_ptr(),
                c_algs.len(),
            ))
        }
    }

    /// Verify serialized CMW bytes, returning the appraisal as an EAR.
    /// Wraps `nvat_local_corim_verifier_verify_cmw`.
    ///
    /// Findings are collected: `Ok` means the input was processable; the
    /// verdict is `ear_status` in the returned [`EarResult`].
    ///
    /// `signing_options` signs the JWT. `None`, or options with an empty key,
    /// leaves it unsigned.
    pub fn verify_cmw(
        &self,
        cmw_data: &[u8],
        format: CmwFormat,
        signing_options: Option<&EarSigningOptions>,
    ) -> Result<EarResult> {
        if cmw_data.is_empty() {
            return Err(NvatError::new(NVAT_RC_BAD_ARGUMENT as u16));
        }
        let options_ptr = signing_options
            .map(|o| o.as_ptr())
            .unwrap_or(ptr::null_mut());

        let mut jwt_ptr = ptr::null_mut();
        let mut json_ptr = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_local_corim_verifier_verify_cmw(
                self.inner,
                cmw_data.as_ptr(),
                cmw_data.len(),
                format.into(),
                options_ptr,
                &mut jwt_ptr,
                &mut json_ptr,
            ))?;
        }
        let jwt = NvatString::from_raw(jwt_ptr);
        let json = NvatString::from_raw(json_ptr);
        Ok(EarResult {
            jwt: jwt.to_string()?,
            json: json.to_string()?,
        })
    }

    /// Serialize `cmw` and verify it. Convenience over
    /// [`CmwCollection::serialize`] plus [`verify_cmw`](Self::verify_cmw).
    pub fn verify_cmw_collection(
        &self,
        cmw: &CmwCollection,
        format: CmwFormat,
        signing_options: Option<&EarSigningOptions>,
    ) -> Result<EarResult> {
        let serialized = cmw.serialize(format)?;
        self.verify_cmw(serialized.as_bytes(), format, signing_options)
    }
}

impl Drop for LocalCorimVerifier {
    fn drop(&mut self) {
        unsafe {
            nvat_local_corim_verifier_free(&mut self.inner);
        }
    }
}

// Handles are opaque, so Debug prints the type name only.
impl fmt::Debug for CmwCollection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CmwCollection").finish_non_exhaustive()
    }
}

impl fmt::Debug for CorimStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CorimStore").finish_non_exhaustive()
    }
}

impl fmt::Debug for LocalCorimVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalCorimVerifier").finish_non_exhaustive()
    }
}

// SAFETY: the C objects are not thread-affine, and verification only reads the
// verifier's configuration. The one thing a shared verify writes is the CoRIM
// store's optional cache, which locks itself on every get and put.
unsafe impl Send for CmwCollection {}
unsafe impl Send for CorimStore {}
unsafe impl Send for LocalCorimVerifier {}
unsafe impl Sync for LocalCorimVerifier {}
