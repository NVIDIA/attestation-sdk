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

#include "local_https_test_server.h"

#include <cstdio>
#include <cstdlib>
#include <iostream>

#include <csignal>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

int LocalHttpsTestServer::find_free_port() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    socklen_t len = sizeof(addr);
    getsockname(sock, (struct sockaddr*)&addr, &len);
    int port = ntohs(addr.sin_port);
    close(sock);
    return port;
}

bool LocalHttpsTestServer::start(const std::string &jwks_file,
                                 const std::string &capture_headers_file,
                                 const std::string &jwks_redirect_url) {
    const std::string cert = m_cert_dir + "/tls_server_cert.pem";
    const std::string key = m_cert_dir + "/tls_server_key.pem";
    if (access(cert.c_str(), R_OK) != 0 || access(key.c_str(), R_OK) != 0) {
        std::cerr << "Prepared TLS test certificates are not readable"
                  << std::endl;
        return false;
    }

    m_port = find_free_port();
    if (m_port < 0) {
        std::cerr << "Failed to find free port" << std::endl;
        return false;
    }

    // Create pipe so we can read server stdout for READY signal
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        std::cerr << "pipe() failed" << std::endl;
        return false;
    }

    m_pid = fork();
    if (m_pid < 0) {
        std::cerr << "fork() failed" << std::endl;
        close(pipefd[0]);
        close(pipefd[1]);
        return false;
    }

    if (m_pid == 0) {
        // Child: redirect stdout to pipe, exec python server
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        std::string port_str = std::to_string(m_port);
        std::string script = m_cert_dir + "/https_server.py";

        execlp("python3", "python3", script.c_str(),
               port_str.c_str(), cert.c_str(), key.c_str(),
               jwks_file.c_str(), capture_headers_file.c_str(),
               jwks_redirect_url.c_str(), nullptr);
        // If exec fails
        _exit(1);
    }

    // Parent: read pipe until READY
    close(pipefd[1]);
    FILE* pipe_stream = fdopen(pipefd[0], "r");
    if (!pipe_stream) {
        std::cerr << "fdopen() failed" << std::endl;
        kill(m_pid, SIGTERM);
        waitpid(m_pid, nullptr, 0);
        return false;
    }

    char buf[256];
    bool ready = false;
    // Wait up to 10 seconds for server to be ready
    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(pipefd[0], &fds);
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    if (select(pipefd[0] + 1, &fds, nullptr, nullptr, &tv) > 0) {
        if (fgets(buf, sizeof(buf), pipe_stream)) {
            std::string line(buf);
            if (line.find("READY") != std::string::npos) {
                ready = true;
            }
        }
    }
    fclose(pipe_stream);

    if (!ready) {
        std::cerr << "HTTPS server did not become ready" << std::endl;
        kill(m_pid, SIGTERM);
        waitpid(m_pid, nullptr, 0);
        m_pid = -1;
        return false;
    }

    return true;
}

void LocalHttpsTestServer::stop() {
    if (m_pid > 0) {
        kill(m_pid, SIGTERM);
        waitpid(m_pid, nullptr, 0);
        m_pid = -1;
    }
}

std::string LocalHttpsTestServer::url() const {
    return "https://127.0.0.1:" + std::to_string(m_port) + "/";
}

std::string LocalHttpsTestServer::cert_path(const std::string &filename) const {
    return m_cert_dir + "/" + filename;
}
