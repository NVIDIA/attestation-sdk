#!/usr/bin/env python3
"""Minimal HTTPS server for TLS integration tests."""

import base64
import hashlib
import http.server
import json
import ssl
import sys

# Fixture bytes served by the RIM-fetcher content-type routes below.
RIM_SERVICE_RAW_BYTES = b"CORIM-BYTES-FROM-SERVICE"
CORIM_CBOR_BYTES = b"CORIM-BYTES-CBOR"
CORIM_COSE_BYTES = b"CORIM-BYTES-COSE"
UNEXPECTED_CONTENT_TYPE_BYTES = b"UNEXPECTED-BYTES"

# Fixture bytes for the fetch_with_coev() RIM-service envelope routes.
RIM_SERVICE_WITH_COEV_CORIM_BYTES = bytes([0x01, 0x02, 0x03])
RIM_SERVICE_WITH_COEV_COEV_BYTES = bytes([0xAA, 0xBB])
RIM_SERVICE_NO_COEV_CORIM_BYTES = bytes([0x01])

# Optional JWKS controls used by local integration tests.
JWKS_FILE = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] else None
CAPTURE_HEADERS_FILE = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] else None
JWKS_REDIRECT_URL = sys.argv[6] if len(sys.argv) > 6 and sys.argv[6] else None


class Handler(http.server.BaseHTTPRequestHandler):
    # HTTP/1.1 with Content-Length avoids OpenSSL 3.x "unexpected eof" errors
    # that occur when HTTP/1.0 closes the connection without TLS close_notify.
    protocol_version = "HTTP/1.1"

    def _send_json(self, data):
        self._send_bytes(json.dumps(data).encode(), "application/json")

    def _send_bytes(self, body, content_type):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            if CAPTURE_HEADERS_FILE is not None:
                try:
                    with open(CAPTURE_HEADERS_FILE, "w", encoding="utf-8") as f:
                        json.dump({k: v for k, v in self.headers.items()}, f)
                except OSError:
                    self.send_response(500)
                    self.send_header("Content-Length", "0")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    return
            if JWKS_REDIRECT_URL is not None:
                self.send_response(302)
                self.send_header("Location", JWKS_REDIRECT_URL)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            if JWKS_FILE is None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            try:
                with open(JWKS_FILE, "rb") as f:
                    body = f.read()
            except OSError:
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/echo-headers":
            headers_dict = {k: v for k, v in self.headers.items()}
            self._send_json({"headers": headers_dict})
            return
        if self.path == "/ratelimited":
            self.send_response(429)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return
        if self.path == "/rim-service":
            self._send_json({
                "id": "test-rim-id",
                "rim": base64.b64encode(RIM_SERVICE_RAW_BYTES).decode(),
                "request_id": "test-request-id",
                "sha256": "unused",
                "rim_format": "corim",
            })
            return
        if self.path == "/corim-cbor":
            self._send_bytes(CORIM_CBOR_BYTES, "application/rim+cbor")
            return
        if self.path == "/corim-cose":
            self._send_bytes(CORIM_COSE_BYTES, "application/rim+cose")
            return
        if self.path == "/unexpected-content-type":
            self._send_bytes(UNEXPECTED_CONTENT_TYPE_BYTES, "text/plain")
            return
        if self.path == "/rim-service-with-coev":
            self._send_json({
                "id": "test-rim-id-with-coev",
                "rim": base64.b64encode(RIM_SERVICE_WITH_COEV_CORIM_BYTES).decode(),
                "request_id": "test-request-id",
                "sha256": "unused",
                "coev": base64.b64encode(RIM_SERVICE_WITH_COEV_COEV_BYTES).decode(),
                "coev_sha256": "unused",
            })
            return
        if self.path == "/rim-service-with-invalid-coev-base64":
            self._send_json({
                "id": "test-rim-id-invalid-coev-base64",
                "rim": base64.b64encode(RIM_SERVICE_WITH_COEV_CORIM_BYTES).decode(),
                "request_id": "test-request-id",
                "sha256": "unused",
                "coev": "abc",
                "coev_sha256": "unused",
            })
            return
        if self.path == "/rim-service-no-coev":
            self._send_json({
                "id": "test-rim-id-no-coev",
                "rim": base64.b64encode(RIM_SERVICE_NO_COEV_CORIM_BYTES).decode(),
                "request_id": "test-request-id",
                "sha256": "unused",
                # coev is absent but coev_sha256 is still set, to exercise
                # that a stale hash isn't returned alongside coev_present=false.
                "coev_sha256": "stale-hash-should-be-cleared",
            })
            return
        if self.path == "/rim-service-with-real-coev":
            # Real CoRIM+CoEV fixtures for the RIM-fetch-loop integration tests.
            try:
                with open("testdata/sample_rims/corim/nonroot_only.cbor", "rb") as f:
                    rim_bytes = f.read()
                with open("testdata/sample_rims/coev/minimal.cbor", "rb") as f:
                    coev_bytes = f.read()
            except OSError:
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            self._send_json({
                "id": "test-rim-id-with-real-coev",
                "rim": base64.b64encode(rim_bytes).decode(),
                "request_id": "test-request-id",
                "sha256": "unused",
                "coev": base64.b64encode(coev_bytes).decode(),
                "coev_sha256": hashlib.sha256(coev_bytes).hexdigest(),
            })
            return
        if self.path == "/rim-service-with-blackwell-fsp-coev":
            try:
                with open("testdata/sample_rims/corim/blackwell_fsp_real.cbor", "rb") as f:
                    rim_bytes = f.read()
                with open("testdata/sample_rims/coev/blackwell_fsp_real.cbor", "rb") as f:
                    coev_bytes = f.read()
            except OSError:
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            self._send_json({
                "id": "test-rim-id-blackwell-fsp",
                "rim": base64.b64encode(rim_bytes).decode(),
                "request_id": "test-request-id",
                "sha256": "unused",
                "coev": base64.b64encode(coev_bytes).decode(),
                "coev_sha256": hashlib.sha256(coev_bytes).hexdigest(),
            })
            return
        if self.path == "/rim-service-with-blackwell-fsp-coev-with-profile":
            try:
                with open("testdata/sample_rims/corim/blackwell_fsp_real.cbor", "rb") as f:
                    rim_bytes = f.read()
                with open("testdata/sample_rims/coev/blackwell_fsp_with_profile.cbor", "rb") as f:
                    coev_bytes = f.read()
            except OSError:
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            self._send_json({
                "id": "test-rim-id-blackwell-fsp-with-profile",
                "rim": base64.b64encode(rim_bytes).decode(),
                "request_id": "test-request-id",
                "sha256": "unused",
                "coev": base64.b64encode(coev_bytes).decode(),
                "coev_sha256": hashlib.sha256(coev_bytes).hexdigest(),
            })
            return
        if self.path == "/rim-service-with-blackwell-fsp-signed-coev":
            try:
                with open("testdata/sample_rims/corim/blackwell_fsp_real.cbor", "rb") as f:
                    rim_bytes = f.read()
                with open("testdata/sample_rims/coev_signed/blackwell_fsp_real.cbor", "rb") as f:
                    coev_bytes = f.read()
            except OSError:
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            self._send_json({
                "id": "test-rim-id-blackwell-fsp-signed-coev",
                "rim": base64.b64encode(rim_bytes).decode(),
                "request_id": "test-request-id",
                "sha256": "unused",
                "coev": base64.b64encode(coev_bytes).decode(),
                "coev_sha256": hashlib.sha256(coev_bytes).hexdigest(),
            })
            return
        if self.path == "/rim-service-with-blackwell-fsp-signed-coev-bad-sig":
            try:
                with open("testdata/sample_rims/corim/blackwell_fsp_real.cbor", "rb") as f:
                    rim_bytes = f.read()
                with open("testdata/sample_rims/coev_signed/blackwell_fsp_real_bad_sig.cbor", "rb") as f:
                    coev_bytes = f.read()
            except OSError:
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            self._send_json({
                "id": "test-rim-id-blackwell-fsp-signed-coev-bad-sig",
                "rim": base64.b64encode(rim_bytes).decode(),
                "request_id": "test-request-id",
                "sha256": "unused",
                "coev": base64.b64encode(coev_bytes).decode(),
                "coev_sha256": hashlib.sha256(coev_bytes).hexdigest(),
            })
            return
        if self.path == "/rim-service-blackwell-fsp-garbage-corim":
            self._send_json({
                "id": "test-rim-id-blackwell-fsp-garbage-corim",
                "rim": base64.b64encode(b"not a valid CoRIM").decode(),
                "request_id": "test-request-id",
                "sha256": "unused",
            })
            return
        if self.path == "/rim-service-blackwell-fsp-garbage-spdmtoc-coev":
            try:
                with open("testdata/sample_rims/corim/blackwell_fsp_real.cbor", "rb") as f:
                    rim_bytes = f.read()
            except OSError:
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            # SpdmToc CBOR tag prefix (#6.570 = 0xD9, 0x02, 0x3A) followed by
            # bytes that don't decode as a valid tagged-spdm-toc.
            coev_bytes = bytes([0xD9, 0x02, 0x3A, 0xFF, 0xFF])
            self._send_json({
                "id": "test-rim-id-blackwell-fsp-garbage-spdmtoc-coev",
                "rim": base64.b64encode(rim_bytes).decode(),
                "request_id": "test-request-id",
                "sha256": "unused",
                "coev": base64.b64encode(coev_bytes).decode(),
                "coev_sha256": hashlib.sha256(coev_bytes).hexdigest(),
            })
            return
        if self.path == "/rim-service-blackwell-fsp-garbage-concise-evidence-coev":
            try:
                with open("testdata/sample_rims/corim/blackwell_fsp_real.cbor", "rb") as f:
                    rim_bytes = f.read()
            except OSError:
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            # Not the SpdmToc tag prefix, and not valid tagged-concise-evidence
            # CBOR either.
            coev_bytes = bytes([0xFF, 0xFF, 0xFF, 0xFF])
            self._send_json({
                "id": "test-rim-id-blackwell-fsp-garbage-concise-evidence-coev",
                "rim": base64.b64encode(rim_bytes).decode(),
                "request_id": "test-request-id",
                "sha256": "unused",
                "coev": base64.b64encode(coev_bytes).decode(),
                "coev_sha256": hashlib.sha256(coev_bytes).hexdigest(),
            })
            return
        if self.path == "/rim-service-blackwell-fsp-no-coev":
            try:
                with open("testdata/sample_rims/corim/blackwell_fsp_real.cbor", "rb") as f:
                    rim_bytes = f.read()
            except OSError:
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            self._send_json({
                "id": "test-rim-id-blackwell-fsp-no-coev",
                "rim": base64.b64encode(rim_bytes).decode(),
                "request_id": "test-request-id",
                "sha256": "unused",
            })
            return
        if self.path == "/rim-service-real-rim-no-coev":
            try:
                with open("testdata/sample_rims/corim/nonroot_only.cbor", "rb") as f:
                    rim_bytes = f.read()
            except OSError:
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            self._send_json({
                "id": "test-rim-id-real-rim-no-coev",
                "rim": base64.b64encode(rim_bytes).decode(),
                "request_id": "test-request-id",
                "sha256": "unused",
            })
            return
        self._send_json({"method": "GET", "path": self.path, "status": "ok"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode() if length > 0 else ""
        self._send_json({"method": "POST", "path": self.path, "body": body, "status": "ok"})

    def log_message(self, format, *args):
        pass  # suppress request logging


def main():
    port = int(sys.argv[1])
    certfile = sys.argv[2]
    keyfile = sys.argv[3]

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)

    server = http.server.HTTPServer(("127.0.0.1", port), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    print(f"READY {port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
