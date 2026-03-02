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

//! Error types for NVAT SDK operations
//!
//! This module provides error handling types that wrap C SDK error codes
//! with safe Rust error handling patterns.

use crate::nvat_rc_t;
use std::ffi::CStr;
use std::fmt;

/// Result type for NVAT operations
///
/// A type alias for `Result<T, NvatError>`, used throughout the crate
/// for operations that can fail.
pub type Result<T> = std::result::Result<T, NvatError>;

/// Error type for NVAT SDK operations
///
/// Wraps error codes from the underlying C SDK with human-readable
/// error messages. Implements `std::error::Error` for compatibility
/// with Rust error handling patterns.
///
/// # Examples
///
/// ```no_run
/// use nv_attestation_sdk::{NvatSdk, NvatError};
///
/// match NvatSdk::init_default() {
///     Ok(client) => println!("Success!"),
///     Err(e) => eprintln!("Error {}: {}", e.code, e.message()),
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvatError {
    /// The error code from the C SDK
    pub code: u16,
}

impl NvatError {
    /// Create a new error from an error code
    ///
    /// # Arguments
    ///
    /// * `code` - Error code from the C SDK
    pub fn new(code: nvat_rc_t) -> Self {
        NvatError { code }
    }

    /// Check an error code and convert to Result
    ///
    /// Returns `Ok(())` if the code indicates success, otherwise returns
    /// an `Err` with the error wrapped in `NvatError`.
    ///
    /// # Arguments
    ///
    /// * `code` - Return code from a C SDK function
    pub fn check(code: nvat_rc_t) -> Result<()> {
        if code == crate::NVAT_RC_OK as u16 {
            Ok(())
        } else {
            Err(NvatError::new(code))
        }
    }

    /// Get a human-readable error message for this error code
    ///
    /// Queries the C SDK for the error message associated with this code.
    pub fn message(&self) -> String {
        unsafe {
            let msg = crate::nvat_rc_to_string(self.code);
            if msg.is_null() {
                format!("Unknown error code: {}", self.code)
            } else {
                CStr::from_ptr(msg).to_string_lossy().into_owned()
            }
        }
    }
}

impl fmt::Display for NvatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NVAT Error {}: {}", self.code, self.message())
    }
}

impl std::error::Error for NvatError {}

impl From<u16> for NvatError {
    fn from(code: u16) -> Self {
        NvatError { code }
    }
}

impl From<NvatError> for u16 {
    fn from(error: NvatError) -> Self {
        error.code
    }
}
