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

//! Shared helpers.

use crate::error::{NvatError, Result};
use crate::NVAT_RC_BAD_ARGUMENT;

use std::any::Any;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// Convert to a C string, mapping interior NULs to `NVAT_RC_BAD_ARGUMENT`.
pub(crate) fn required_cstring(value: &str) -> Result<CString> {
    CString::new(value).map_err(|_| NvatError::new(NVAT_RC_BAD_ARGUMENT as u16))
}

/// Convert an optional argument, where `None` becomes a NULL pointer.
pub(crate) fn optional_cstring(value: Option<&str>) -> Result<Option<CString>> {
    value.map(required_cstring).transpose()
}

/// Convert a C string, where NULL or invalid UTF-8 becomes `None`.
///
/// # Safety
/// `ptr` must be null or a valid null-terminated string that outlives `'a`.
pub(crate) unsafe fn optional_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

/// Message carried by a caught panic payload.
pub(crate) fn panic_message(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload")
}
