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

//! Observer hooks for SDK-internal HTTP calls and cache lookups.

use std::any::Any;
use std::os::raw::{c_char, c_long, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Duration;

use crate::util::{optional_str, panic_message};

/// One outbound HTTP attempt made by the SDK. Each retry is its own attempt.
#[derive(Debug, Clone, Copy)]
pub struct HttpCall<'a> {
    /// The service called: `rim`, `ocsp`, `jwks`, `nras` or `unknown`.
    pub service: &'a str,
    /// The HTTP method, e.g. `GET`.
    pub method: &'a str,
    /// The request URL.
    pub url: &'a str,
    /// The HTTP status, or `None` if no response was received.
    pub status: Option<u16>,
    /// Why no response was received: `timeout`, `connect` or `other`.
    pub error: Option<&'a str>,
    /// Time taken by the attempt.
    pub duration: Duration,
    /// Size of the request body in bytes.
    pub request_size: usize,
    /// Size of the response body received in bytes.
    pub response_size: usize,
}

/// Receives SDK-internal events.
///
/// Callbacks run synchronously on the thread making the SDK call, so they
/// should be cheap. A panic inside a callback is swallowed.
pub trait Observer: Send + Sync + 'static {
    /// Called after each outbound HTTP attempt.
    fn on_http_call(&self, _call: &HttpCall<'_>) {}

    /// Called after each cache lookup. `cache` is `rim` or `ocsp`.
    fn on_cache_lookup(&self, _cache: &str, _hit: bool) {}
}

pub(crate) unsafe extern "C" fn http_call_trampoline<O: Observer>(
    service: *const c_char,
    method: *const c_char,
    url: *const c_char,
    status: c_long,
    error: *const c_char,
    duration_ms: c_long,
    request_size: usize,
    response_size: usize,
    user_data: *mut c_void,
) {
    // Unwinding into C is undefined behavior, so a panicking observer drops the event.
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: user_data is the `O` leaked by `SdkOptions::set_observer`,
        // and the C SDK passes valid null-terminated strings or null.
        let observer = unsafe { &*(user_data as *const O) };
        let call = HttpCall {
            service: unsafe { optional_str(service) }.unwrap_or("unknown"),
            method: unsafe { optional_str(method) }.unwrap_or("unknown"),
            url: unsafe { optional_str(url) }.unwrap_or("unknown"),
            status: u16::try_from(status).ok().filter(|status| *status != 0),
            error: unsafe { optional_str(error) },
            duration: Duration::from_millis(u64::try_from(duration_ms).unwrap_or(0)),
            request_size,
            response_size,
        };
        observer.on_http_call(&call);
    }));
    if let Err(payload) = result {
        report_panic("on_http_call", payload);
    }
}

pub(crate) unsafe extern "C" fn cache_lookup_trampoline<O: Observer>(
    cache: *const c_char,
    hit: bool,
    user_data: *mut c_void,
) {
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: user_data is the `O` leaked by `SdkOptions::set_observer`,
        // and the C SDK passes a valid null-terminated string or null.
        let observer = unsafe { &*(user_data as *const O) };
        observer.on_cache_lookup(unsafe { optional_str(cache) }.unwrap_or("unknown"), hit);
    }));
    if let Err(payload) = result {
        report_panic("on_cache_lookup", payload);
    }
}

/// Log a panic caught from an observer callback so it is not lost.
fn report_panic(callback: &str, payload: Box<dyn Any + Send>) {
    let message = panic_message(payload.as_ref());
    // The logger can panic too, and that must not unwind into C either.
    let _ = catch_unwind(AssertUnwindSafe(|| {
        #[cfg(feature = "logging")]
        log::error!("Observer::{callback} panicked, event dropped: {message}");
        #[cfg(not(feature = "logging"))]
        {
            use std::io::Write;
            let _ = writeln!(
                std::io::stderr(),
                "nv-attestation-sdk: Observer::{callback} panicked, event dropped: {message}"
            );
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    // (service, method, url, status, error, request_size, response_size)
    type RecordedCall = (
        String,
        String,
        String,
        Option<u16>,
        Option<String>,
        usize,
        usize,
    );

    #[derive(Default)]
    struct Recorder {
        http: Mutex<Vec<RecordedCall>>,
        cache: Mutex<Vec<(String, bool)>>,
    }

    impl Observer for Recorder {
        fn on_http_call(&self, call: &HttpCall<'_>) {
            self.http.lock().unwrap().push((
                call.service.to_owned(),
                call.method.to_owned(),
                call.url.to_owned(),
                call.status,
                call.error.map(str::to_owned),
                call.request_size,
                call.response_size,
            ));
        }

        fn on_cache_lookup(&self, cache: &str, hit: bool) {
            self.cache.lock().unwrap().push((cache.to_owned(), hit));
        }
    }

    #[derive(Default)]
    struct Panicking {
        calls: AtomicUsize,
    }

    impl Observer for Panicking {
        fn on_http_call(&self, _call: &HttpCall<'_>) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            panic!("observer panic");
        }

        fn on_cache_lookup(&self, _cache: &str, _hit: bool) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            panic!("observer panic");
        }
    }

    fn user_data<O>(observer: &O) -> *mut c_void {
        observer as *const O as *mut c_void
    }

    #[test]
    fn http_call_with_response_has_status_and_no_error() {
        let recorder = Recorder::default();
        let (service, method) = (CString::new("rim").unwrap(), CString::new("GET").unwrap());
        let url = CString::new("https://rim.attestation.nvidia.com/v1/rim/abc").unwrap();
        unsafe {
            http_call_trampoline::<Recorder>(
                service.as_ptr(),
                method.as_ptr(),
                url.as_ptr(),
                200,
                std::ptr::null(),
                250,
                0,
                1024,
                user_data(&recorder),
            );
        }
        assert_eq!(
            *recorder.http.lock().unwrap(),
            vec![(
                "rim".into(),
                "GET".into(),
                "https://rim.attestation.nvidia.com/v1/rim/abc".into(),
                Some(200),
                None,
                0,
                1024
            )]
        );
    }

    #[test]
    fn http_call_without_response_has_error_and_no_status() {
        let recorder = Recorder::default();
        let service = CString::new("ocsp").unwrap();
        let method = CString::new("POST").unwrap();
        let url = CString::new("https://ocsp.ndis.nvidia.com").unwrap();
        let error = CString::new("timeout").unwrap();
        unsafe {
            http_call_trampoline::<Recorder>(
                service.as_ptr(),
                method.as_ptr(),
                url.as_ptr(),
                0,
                error.as_ptr(),
                5000,
                100,
                0,
                user_data(&recorder),
            );
        }
        assert_eq!(
            *recorder.http.lock().unwrap(),
            vec![(
                "ocsp".into(),
                "POST".into(),
                "https://ocsp.ndis.nvidia.com".into(),
                None,
                Some("timeout".into()),
                100,
                0
            )]
        );
    }

    #[test]
    fn cache_lookup_is_forwarded() {
        let recorder = Recorder::default();
        let cache = CString::new("rim").unwrap();
        unsafe {
            cache_lookup_trampoline::<Recorder>(cache.as_ptr(), true, user_data(&recorder));
        }
        assert_eq!(*recorder.cache.lock().unwrap(), vec![("rim".into(), true)]);
    }

    #[test]
    fn panicking_observer_is_contained_and_keeps_receiving_events() {
        let observer = Panicking::default();
        let name = CString::new("rim").unwrap();
        for _ in 0..2 {
            unsafe {
                http_call_trampoline::<Panicking>(
                    name.as_ptr(),
                    name.as_ptr(),
                    name.as_ptr(),
                    200,
                    std::ptr::null(),
                    0,
                    0,
                    0,
                    user_data(&observer),
                );
                cache_lookup_trampoline::<Panicking>(name.as_ptr(), true, user_data(&observer));
            }
        }
        // Every call reached the observer and panicked, and later calls still ran.
        assert_eq!(observer.calls.load(Ordering::SeqCst), 4);
    }
}
