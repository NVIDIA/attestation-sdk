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
use crate::*;
use std::ffi::CString;
use std::ptr;

/// Safe wrapper around nvat_str_t
///
/// Provides a safe interface to strings allocated by the NVAT C SDK.
/// The underlying C string is automatically freed when dropped.
/// Not `Send` or `Sync` - do not share across threads.
pub struct NvatString {
    inner: nvat_str_t,
}

impl NvatString {
    pub(crate) fn from_raw(ptr: nvat_str_t) -> Self {
        NvatString { inner: ptr }
    }

    /// Get the length of the string
    pub fn len(&self) -> Result<usize> {
        let mut length: usize = 0;
        unsafe {
            NvatError::check(nvat_str_length(self.inner, &mut length))?;
        }
        Ok(length)
    }

    /// Check if the string is empty
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Get the string data as a slice
    pub fn as_bytes(&self) -> Result<&[u8]> {
        let mut data_ptr: *mut std::os::raw::c_char = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_str_get_data(self.inner, &mut data_ptr))?;
            let length = self.len()?;
            Ok(std::slice::from_raw_parts(data_ptr as *const u8, length))
        }
    }

    /// Get the string as a UTF-8 string (if valid)
    pub fn to_string(&self) -> Result<String> {
        let bytes = self.as_bytes()?;
        String::from_utf8(bytes.to_vec()).map_err(|_| NvatError::new(NVAT_RC_INTERNAL_ERROR as u16))
    }

    /// Get the string as a lossy UTF-8 string
    pub fn to_string_lossy(&self) -> Result<String> {
        let bytes = self.as_bytes()?;
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }
}

impl Drop for NvatString {
    fn drop(&mut self) {
        unsafe {
            nvat_str_free(&mut self.inner);
        }
    }
}

impl TryFrom<NvatString> for String {
    type Error = NvatError;

    fn try_from(nvat_string: NvatString) -> Result<Self> {
        nvat_string.to_string()
    }
}

impl TryFrom<&NvatString> for String {
    type Error = NvatError;

    fn try_from(nvat_string: &NvatString) -> Result<Self> {
        nvat_string.to_string()
    }
}

/// Wrapper around `nvat_nonce_t`.
///
/// Not `Send`/`Sync` - use `to_hex_string`/`from_hex` to transfer across threads.
pub struct Nonce {
    inner: nvat_nonce_t,
}

impl Nonce {
    /// Generate a random nonce. Wraps `nvat_nonce_create`.
    pub fn generate(length: usize) -> Result<Self> {
        let mut nonce = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_nonce_create(&mut nonce, length))?;
        }
        Ok(Nonce { inner: nonce })
    }

    /// Create nonce from hex string. Wraps `nvat_nonce_from_hex`.
    pub fn from_hex(hex_string: &str) -> Result<Self> {
        let c_string =
            CString::new(hex_string).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        let mut nonce = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_nonce_from_hex(&mut nonce, c_string.as_ptr()))?;
        }
        Ok(Nonce { inner: nonce })
    }

    /// Get the nonce length in bytes. Wraps `nvat_nonce_get_length`.
    pub fn len(&self) -> usize {
        unsafe { nvat_nonce_get_length(self.inner) }
    }

    /// Check if the nonce is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Encode the nonce as a hex string. Wraps `nvat_nonce_to_hex`.
    pub fn to_hex_string(&self) -> Result<String> {
        let mut str_ptr = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_nonce_to_hex_string(self.inner, &mut str_ptr))?;
        }
        let nvat_str = NvatString::from_raw(str_ptr);
        nvat_str.to_string()
    }

    pub(crate) fn as_ptr(&self) -> nvat_nonce_t {
        self.inner
    }
}

impl Drop for Nonce {
    fn drop(&mut self) {
        unsafe {
            nvat_nonce_free(&mut self.inner);
        }
    }
}

/// Safe wrapper around nvat_sdk_opts_t
/// Wrapper around `nvat_sdk_opts_t`. Ownership transferred to SDK on `init`.
pub struct SdkOptions {
    inner: nvat_sdk_opts_t,
}

impl SdkOptions {
    /// Create SDK options with defaults. Wraps `nvat_sdk_opts_create`.
    pub fn new() -> Result<Self> {
        let mut opts = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_sdk_opts_create(&mut opts))?;
        }
        Ok(SdkOptions { inner: opts })
    }

    /// Set logger for the SDK. Wraps `nvat_sdk_opts_set_logger`.
    ///
    /// The C SDK copies the logger's shared_ptr internally, so the wrapper is freed.
    pub fn set_logger(&mut self, logger: Logger) {
        unsafe {
            nvat_sdk_opts_set_logger(self.inner, logger.inner);
        }
        // Note: logger will be properly freed via Drop when it goes out of scope.
        // The C SDK copies the shared_ptr internally, so we must free the wrapper.
    }

    pub(crate) fn as_ptr(&self) -> nvat_sdk_opts_t {
        self.inner
    }
}

impl Default for SdkOptions {
    fn default() -> Self {
        Self::new().expect("Failed to create default SDK options")
    }
}

impl Drop for SdkOptions {
    fn drop(&mut self) {
        unsafe {
            nvat_sdk_opts_free(&mut self.inner);
        }
    }
}

/// Safe wrapper around nvat_logger_t
///
/// Logger for the NVAT C SDK. Integrates C SDK logging with Rust's `log` crate.
/// Automatically freed unless ownership is transferred via [`SdkOptions::set_logger`].
pub struct Logger {
    inner: nvat_logger_t,
}

impl Logger {
    /// Create a logger that integrates with Rust's `log` crate.
    ///
    /// This creates a logger that forwards all C SDK log messages to the Rust `log` crate,
    /// which can then be handled by any logger backend like `env_logger`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nv_attestation_sdk::{Logger, SdkOptions, NvatSdk};
    ///
    /// // Initialize env_logger to handle Rust log messages
    /// env_logger::init();
    ///
    /// // Create a logger that forwards C SDK logs to env_logger
    /// let logger = Logger::new().expect("Failed to create logger");
    ///
    /// let mut opts = SdkOptions::default();
    /// opts.set_logger(logger);
    ///
    /// let client = NvatSdk::init(opts)?;
    /// # Ok::<(), nv_attestation_sdk::NvatError>(())
    /// ```
    ///
    /// Wraps `nvat_logger_callback_create`.
    #[cfg(feature = "logging")]
    pub fn new() -> Result<Self> {
        let mut logger = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_logger_callback_create(
                &mut logger,
                Some(rust_log_callback),
                Some(rust_should_log_callback),
                Some(rust_flush_callback),
                ptr::null_mut(),
            ))?;
        }
        Ok(Logger { inner: logger })
    }
}

impl Drop for Logger {
    fn drop(&mut self) {
        unsafe {
            nvat_logger_free(&mut self.inner);
        }
    }
}

/// Wrapper around `nvat_http_options_t`. Automatically freed on drop.
///
/// This struct uses a builder pattern for a more idiomatic Rust API.
/// Use [`HttpOptionsBuilder`] to construct instances.
pub struct HttpOptions {
    inner: nvat_http_options_t,
}

impl HttpOptions {
    /// Create HTTP options with defaults. Wraps `nvat_http_options_create_default`.
    ///
    /// For a more ergonomic API, consider using [`HttpOptionsBuilder`]:
    /// ```no_run
    /// use nv_attestation_sdk::HttpOptions;
    /// let opts = HttpOptions::builder()
    ///     .max_retry_count(5)
    ///     .connection_timeout_ms(10000)
    ///     .build()?;
    /// # Ok::<(), nv_attestation_sdk::NvatError>(())
    /// ```
    pub fn default_options() -> Result<Self> {
        let mut opts = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_http_options_create_default(&mut opts))?;
        }
        Ok(HttpOptions { inner: opts })
    }

    /// Create a builder for configuring HTTP options.
    ///
    /// This provides a more idiomatic Rust API compared to the setter methods.
    pub fn builder() -> HttpOptionsBuilder {
        HttpOptionsBuilder::default()
    }

    /// Set maximum retry count. Wraps `nvat_http_options_set_max_retry_count`.
    pub fn set_max_retry_count(&mut self, count: i64) {
        unsafe {
            nvat_http_options_set_max_retry_count(self.inner, count);
        }
    }

    /// Set the base backoff time in milliseconds
    pub fn set_base_backoff_ms(&mut self, ms: i64) {
        unsafe {
            nvat_http_options_set_base_backoff_ms(self.inner, ms);
        }
    }

    /// Set the maximum backoff time in milliseconds
    pub fn set_max_backoff_ms(&mut self, ms: i64) {
        unsafe {
            nvat_http_options_set_max_backoff_ms(self.inner, ms);
        }
    }

    /// Set the connection timeout in milliseconds
    pub fn set_connection_timeout_ms(&mut self, ms: i64) {
        unsafe {
            nvat_http_options_set_connection_timeout_ms(self.inner, ms);
        }
    }

    /// Set the request timeout in milliseconds
    pub fn set_request_timeout_ms(&mut self, ms: i64) {
        unsafe {
            nvat_http_options_set_request_timeout_ms(self.inner, ms);
        }
    }

    pub(crate) fn as_ptr(&self) -> nvat_http_options_t {
        self.inner
    }
}

impl Drop for HttpOptions {
    fn drop(&mut self) {
        unsafe {
            nvat_http_options_free(&mut self.inner);
        }
    }
}

/// Builder for [`HttpOptions`] with a more idiomatic Rust API.
///
/// This builder pattern delays creating the C object until `build()` is called,
/// allowing for a more ergonomic configuration experience.
///
/// # Example
/// ```no_run
/// use nv_attestation_sdk::HttpOptions;
///
/// let opts = HttpOptions::builder()
///     .max_retry_count(5)
///     .base_backoff_ms(100)
///     .max_backoff_ms(5000)
///     .connection_timeout_ms(10000)
///     .request_timeout_ms(30000)
///     .build()?;
/// # Ok::<(), nv_attestation_sdk::NvatError>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct HttpOptionsBuilder {
    max_retry_count: Option<i64>,
    base_backoff_ms: Option<i64>,
    max_backoff_ms: Option<i64>,
    connection_timeout_ms: Option<i64>,
    request_timeout_ms: Option<i64>,
}

impl HttpOptionsBuilder {
    /// Set maximum retry count.
    pub fn max_retry_count(mut self, count: i64) -> Self {
        self.max_retry_count = Some(count);
        self
    }

    /// Set the base backoff time in milliseconds.
    pub fn base_backoff_ms(mut self, ms: i64) -> Self {
        self.base_backoff_ms = Some(ms);
        self
    }

    /// Set the maximum backoff time in milliseconds.
    pub fn max_backoff_ms(mut self, ms: i64) -> Self {
        self.max_backoff_ms = Some(ms);
        self
    }

    /// Set the connection timeout in milliseconds.
    pub fn connection_timeout_ms(mut self, ms: i64) -> Self {
        self.connection_timeout_ms = Some(ms);
        self
    }

    /// Set the request timeout in milliseconds.
    pub fn request_timeout_ms(mut self, ms: i64) -> Self {
        self.request_timeout_ms = Some(ms);
        self
    }

    /// Build the [`HttpOptions`] with the configured values.
    ///
    /// This creates the underlying C object and applies all configured settings.
    pub fn build(self) -> Result<HttpOptions> {
        let mut opts = HttpOptions::default_options()?;

        if let Some(count) = self.max_retry_count {
            opts.set_max_retry_count(count);
        }
        if let Some(ms) = self.base_backoff_ms {
            opts.set_base_backoff_ms(ms);
        }
        if let Some(ms) = self.max_backoff_ms {
            opts.set_max_backoff_ms(ms);
        }
        if let Some(ms) = self.connection_timeout_ms {
            opts.set_connection_timeout_ms(ms);
        }
        if let Some(ms) = self.request_timeout_ms {
            opts.set_request_timeout_ms(ms);
        }

        Ok(opts)
    }
}

// Callback functions for integrating C SDK logging with Rust's log crate
#[cfg(feature = "logging")]
mod log_callbacks {
    use super::*;
    use std::ffi::CStr;

    /// Convert C log level to Rust log level
    fn nvat_level_to_log_level(level: nvat_log_level_t) -> log::Level {
        match level {
            nv_attestation_sdk_sys::nvat_log_level_t_NVAT_LOG_LEVEL_TRACE => log::Level::Trace,
            nv_attestation_sdk_sys::nvat_log_level_t_NVAT_LOG_LEVEL_DEBUG => log::Level::Debug,
            nv_attestation_sdk_sys::nvat_log_level_t_NVAT_LOG_LEVEL_INFO => log::Level::Info,
            nv_attestation_sdk_sys::nvat_log_level_t_NVAT_LOG_LEVEL_WARN => log::Level::Warn,
            nv_attestation_sdk_sys::nvat_log_level_t_NVAT_LOG_LEVEL_ERROR => log::Level::Error,
            _ => log::Level::Info, // Default to Info for unknown levels (including OFF)
        }
    }

    /// Callback to check if logging is enabled for a given level
    ///
    /// This is called by the C SDK before formatting log messages to avoid
    /// unnecessary string formatting when logging is disabled.
    pub(super) unsafe extern "C" fn rust_should_log_callback(
        level: nvat_log_level_t,
        _filename: *const std::os::raw::c_char,
        _function: *const std::os::raw::c_char,
        _line: std::os::raw::c_int,
        _user_data: *mut std::os::raw::c_void,
    ) -> bool {
        // Convert C log level to Rust log level and check if enabled
        let rust_level = nvat_level_to_log_level(level);
        log::log_enabled!(rust_level)
    }

    /// Callback to write log messages to the Rust log system
    ///
    /// This forwards C SDK log messages to the Rust `log` crate, which can then
    /// be handled by any backend like `env_logger`, `tracing`, etc.
    pub(super) unsafe extern "C" fn rust_log_callback(
        level: nvat_log_level_t,
        message: *const std::os::raw::c_char,
        filename: *const std::os::raw::c_char,
        function: *const std::os::raw::c_char,
        line: std::os::raw::c_int,
        _user_data: *mut std::os::raw::c_void,
    ) {
        if message.is_null() {
            return;
        }

        // SAFETY: The C SDK guarantees that message is a valid null-terminated string
        let msg = unsafe {
            match CStr::from_ptr(message).to_str() {
                Ok(s) => s,
                Err(_) => return, // Skip invalid UTF-8
            }
        };

        let rust_level = nvat_level_to_log_level(level);

        // Extract source location information if available
        let file = if !filename.is_null() {
            unsafe { CStr::from_ptr(filename).to_str().ok() }
        } else {
            None
        };

        let func = if !function.is_null() {
            unsafe { CStr::from_ptr(function).to_str().ok() }
        } else {
            None
        };

        // Format the log message with source location
        let location = match (file, func) {
            (Some(f), Some(fn_name)) => format!("{}:{} in {}", f, line, fn_name),
            (Some(f), None) => format!("{}:{}", f, line),
            (None, Some(fn_name)) => format!("in {}", fn_name),
            (None, None) => String::new(),
        };

        // Log the message through the Rust log system
        if location.is_empty() {
            log::log!(rust_level, "{}", msg);
        } else {
            log::log!(rust_level, "{} - {}", location, msg);
        }
    }

    /// Callback to flush buffered log messages
    ///
    /// Called by the C SDK at critical points to ensure logs are persisted.
    pub(super) unsafe extern "C" fn rust_flush_callback(_user_data: *mut std::os::raw::c_void) {
        // env_logger and most Rust loggers flush automatically
        // This is a no-op, but we could add explicit flushing if needed
        log::logger().flush();
    }
}

#[cfg(feature = "logging")]
use log_callbacks::{rust_flush_callback, rust_log_callback, rust_should_log_callback};

/// Wrapper around `nvat_gpu_evidence_source_t`.
///
/// Evidence sources can collect GPU attestation evidence via NVML, Corelib,
/// or load pre-collected evidence from JSON.
///
/// Not `Send` or `Sync` - use separate instances per thread.
pub struct GpuEvidenceSource {
    inner: nvat_gpu_evidence_source_t,
}

impl GpuEvidenceSource {
    /// Create a GPU evidence source that collects evidence from all GPUs
    /// accessible via NVML. Wraps `nvat_gpu_evidence_source_nvml_create`.
    pub fn from_nvml() -> Result<Self> {
        let mut source = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_gpu_evidence_source_nvml_create(&mut source))?;
        }
        Ok(GpuEvidenceSource { inner: source })
    }

    /// Create a GPU evidence source that collects evidence from all GPUs
    /// accessible via Corelib SPDM C API. Wraps `nvat_gpu_evidence_source_corelib_create`.
    ///
    /// # Arguments
    /// * `gpu_architecture` - GPU architecture string (currently only "blackwell" is supported)
    pub fn from_corelib(gpu_architecture: &str) -> Result<Self> {
        let c_arch = CString::new(gpu_architecture)
            .map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        let mut source = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_gpu_evidence_source_corelib_create(
                &mut source,
                c_arch.as_ptr(),
            ))?;
        }
        Ok(GpuEvidenceSource { inner: source })
    }

    /// Create a GPU evidence source from a JSON file. Wraps `nvat_gpu_evidence_source_from_json_file`.
    ///
    /// The file must contain evidence in the schema expected by the C SDK.
    pub fn from_json_file(file_path: &str) -> Result<Self> {
        let c_path =
            CString::new(file_path).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        let mut source = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_gpu_evidence_source_from_json_file(
                &mut source,
                c_path.as_ptr(),
            ))?;
        }
        Ok(GpuEvidenceSource { inner: source })
    }

    /// Create a GPU evidence source from a JSON string. Wraps `nvat_gpu_evidence_source_from_json_string`.
    ///
    /// The string must contain evidence in the schema expected by the C SDK.
    pub fn from_json_string(json_string: &str) -> Result<Self> {
        let c_json =
            CString::new(json_string).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        let mut source = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_gpu_evidence_source_from_json_string(
                &mut source,
                c_json.as_ptr(),
            ))?;
        }
        Ok(GpuEvidenceSource { inner: source })
    }

    /// Collect GPU evidence from this source. Wraps `nvat_gpu_evidence_collect`.
    ///
    /// # Arguments
    /// * `nonce` - The nonce to include in the evidence collection
    ///
    /// # Returns
    /// A collection of GPU evidence items
    pub fn collect(&self, nonce: &Nonce) -> Result<GpuEvidenceCollection> {
        let mut array = ptr::null_mut();
        let mut count = 0;

        unsafe {
            NvatError::check(nvat_gpu_evidence_collect(
                self.inner,
                nonce.as_ptr(),
                &mut array,
                &mut count,
            ))?;
        }

        Ok(GpuEvidenceCollection::from_raw(array, count))
    }
}

impl Drop for GpuEvidenceSource {
    fn drop(&mut self) {
        unsafe {
            nvat_gpu_evidence_source_free(&mut self.inner);
        }
    }
}

/// Collection of GPU evidence items.
///
/// Represents evidence collected from one or more GPUs. The evidence
/// is opaque but can be serialized to JSON for inspection or storage.
///
/// Not `Send` or `Sync` - serialize to JSON to transfer across threads.
pub struct GpuEvidenceCollection {
    array: *mut nvat_gpu_evidence_t,
    count: usize,
}

impl GpuEvidenceCollection {
    pub(crate) fn from_raw(array: *mut nvat_gpu_evidence_t, count: usize) -> Self {
        GpuEvidenceCollection { array, count }
    }

    /// Get the raw pointer for FFI calls
    pub(crate) fn as_ptr(&self) -> *const nvat_gpu_evidence_t {
        self.array
    }

    /// Get the number of GPU evidence items in this collection
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if the collection is empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Serialize the GPU evidence collection to JSON. Wraps `nvat_gpu_evidence_serialize_json`.
    pub fn to_json(&self) -> Result<String> {
        let mut str_ptr = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_gpu_evidence_serialize_json(
                self.array,
                self.count,
                &mut str_ptr,
            ))?;
        }
        let nvat_str = NvatString::from_raw(str_ptr);
        nvat_str.to_string()
    }
}

impl Drop for GpuEvidenceCollection {
    fn drop(&mut self) {
        unsafe {
            nvat_gpu_evidence_array_free(&mut self.array, self.count);
        }
    }
}

/// Wrapper around `nvat_switch_evidence_source_t`.
///
/// Evidence sources can collect NVSwitch attestation evidence via NSCQ,
/// or load pre-collected evidence from JSON.
///
/// Not `Send` or `Sync` - use separate instances per thread.
pub struct SwitchEvidenceSource {
    inner: nvat_switch_evidence_source_t,
}

impl SwitchEvidenceSource {
    /// Create an NVSwitch evidence source that collects evidence from all NVSwitches
    /// accessible via NSCQ. Wraps `nvat_switch_evidence_source_nscq_create`.
    pub fn from_nscq() -> Result<Self> {
        let mut source = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_switch_evidence_source_nscq_create(&mut source))?;
        }
        Ok(SwitchEvidenceSource { inner: source })
    }

    /// Create an NVSwitch evidence source from a JSON file. Wraps `nvat_switch_evidence_source_from_json_file`.
    ///
    /// The file must contain evidence in the schema expected by the C SDK.
    pub fn from_json_file(file_path: &str) -> Result<Self> {
        let c_path =
            CString::new(file_path).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        let mut source = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_switch_evidence_source_from_json_file(
                &mut source,
                c_path.as_ptr(),
            ))?;
        }
        Ok(SwitchEvidenceSource { inner: source })
    }

    /// Create an NVSwitch evidence source from a JSON string. Wraps `nvat_switch_evidence_source_from_json_string`.
    ///
    /// The string must contain evidence in the schema expected by the C SDK.
    pub fn from_json_string(json_string: &str) -> Result<Self> {
        let c_json =
            CString::new(json_string).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))?;
        let mut source = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_switch_evidence_source_from_json_string(
                &mut source,
                c_json.as_ptr(),
            ))?;
        }
        Ok(SwitchEvidenceSource { inner: source })
    }

    /// Collect NVSwitch evidence from this source. Wraps `nvat_switch_evidence_collect`.
    ///
    /// # Arguments
    /// * `nonce` - The nonce to include in the evidence collection
    ///
    /// # Returns
    /// A collection of NVSwitch evidence items
    pub fn collect(&self, nonce: &Nonce) -> Result<SwitchEvidenceCollection> {
        let mut array = ptr::null_mut();
        let mut count = 0;

        unsafe {
            NvatError::check(nvat_switch_evidence_collect(
                self.inner,
                nonce.as_ptr(),
                &mut array,
                &mut count,
            ))?;
        }

        Ok(SwitchEvidenceCollection::from_raw(array, count))
    }
}

impl Drop for SwitchEvidenceSource {
    fn drop(&mut self) {
        unsafe {
            nvat_switch_evidence_source_free(&mut self.inner);
        }
    }
}

/// Collection of NVSwitch evidence items.
///
/// Represents evidence collected from one or more NVSwitches. The evidence
/// is opaque but can be serialized to JSON for inspection or storage.
///
/// Not `Send` or `Sync` - serialize to JSON to transfer across threads.
pub struct SwitchEvidenceCollection {
    array: *mut nvat_switch_evidence_t,
    count: usize,
}

impl SwitchEvidenceCollection {
    pub(crate) fn from_raw(array: *mut nvat_switch_evidence_t, count: usize) -> Self {
        SwitchEvidenceCollection { array, count }
    }

    /// Get the raw pointer for FFI calls
    pub(crate) fn as_ptr(&self) -> *const nvat_switch_evidence_t {
        self.array
    }

    /// Get the number of NVSwitch evidence items in this collection
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if the collection is empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Serialize the NVSwitch evidence collection to JSON. Wraps `nvat_switch_evidence_serialize_json`.
    pub fn to_json(&self) -> Result<String> {
        let mut str_ptr = ptr::null_mut();
        unsafe {
            NvatError::check(nvat_switch_evidence_serialize_json(
                self.array,
                self.count,
                &mut str_ptr,
            ))?;
        }
        let nvat_str = NvatString::from_raw(str_ptr);
        nvat_str.to_string()
    }
}

impl Drop for SwitchEvidenceCollection {
    fn drop(&mut self) {
        unsafe {
            nvat_switch_evidence_array_free(&mut self.array, self.count);
        }
    }
}
