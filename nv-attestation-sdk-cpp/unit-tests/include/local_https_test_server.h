/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * All rights reserved. SPDX-License-Identifier: Apache-2.0
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

#pragma once

#include <string>

#include <sys/types.h>

// Spawns the shared testdata/tls_test/https_server.py as a child process
// with a self-signed cert, for integration tests that need a real HTTPS
// endpoint. One instance per gtest fixture (e.g. a `static` member set up in
// SetUpTestSuite / torn down in TearDownTestSuite) so each fixture's server
// lifetime doesn't interfere with another's.
class LocalHttpsTestServer {
  public:
    // Starts the server with certificates prepared by the unit-test fixture
    // target, waiting up to 10s for readiness. Returns true on success.
    // When jwks_file is non-empty the server receives it as a 4th argument and
    // serves it at /.well-known/jwks.json; the default empty string preserves
    // the existing 3-argument behaviour for all current callers.
    bool start(const std::string &jwks_file = "",
               const std::string &capture_headers_file = "",
               const std::string &jwks_redirect_url = "");
    void stop();

    std::string url() const;
    std::string cert_path(const std::string &filename) const;
    const std::string &cert_dir() const { return m_cert_dir; }

  private:
    static int find_free_port();

    pid_t m_pid = -1;
    int m_port = 0;
    std::string m_cert_dir = "testdata/tls_test";
};
