#!/bin/bash

set -e

# Idempotent: skip if certs already exist
if [ -f "tls_ca_cert.pem" ] && [ -f "tls_server_cert.pem" ]; then
    echo "TLS test certificates already exist. Skipping generation."
    exit 0
fi

echo "Generating TLS test certificates..."

DAYS_VALID=3650

# --- CA certificate ---
openssl genpkey -algorithm RSA -out tls_ca_key.pem -pkeyopt rsa_keygen_bits:2048 2>/dev/null

cat > tls_ca.cnf <<EOF
[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = critical,CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
EOF

openssl req -x509 -new -nodes -key tls_ca_key.pem \
    -sha256 -days ${DAYS_VALID} -out tls_ca_cert.pem \
    -subj "/CN=TLS Test CA" \
    -extensions v3_ca -config tls_ca.cnf

# --- Server certificate (signed by CA, with SAN for localhost) ---
openssl genpkey -algorithm RSA -out tls_server_key.pem -pkeyopt rsa_keygen_bits:2048 2>/dev/null

cat > tls_server.cnf <<EOF
[ req ]
default_bits = 2048
prompt = no
distinguished_name = dn
req_extensions = v3_req

[ dn ]
CN = localhost

[ v3_req ]
subjectAltName = DNS:localhost,IP:127.0.0.1
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF

openssl req -new -key tls_server_key.pem -out tls_server.csr -config tls_server.cnf

cat > tls_server_ext.cnf <<EOF
subjectAltName = DNS:localhost,IP:127.0.0.1
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF

openssl x509 -req -in tls_server.csr \
    -CA tls_ca_cert.pem -CAkey tls_ca_key.pem -CAcreateserial \
    -out tls_server_cert.pem -days ${DAYS_VALID} -sha256 \
    -extfile tls_server_ext.cnf

# --- Wrong CA (for negative tests) ---
openssl genpkey -algorithm RSA -out tls_wrong_ca_key.pem -pkeyopt rsa_keygen_bits:2048 2>/dev/null

openssl req -x509 -new -nodes -key tls_wrong_ca_key.pem \
    -sha256 -days ${DAYS_VALID} -out tls_wrong_ca_cert.pem \
    -subj "/CN=Wrong CA" \
    -extensions v3_ca -config tls_ca.cnf

# --- Create OpenSSL rehash symlinks for CAPATH testing ---
# Use c_rehash as fallback since 'openssl rehash' may return non-zero on some platforms
c_rehash . 2>/dev/null || openssl rehash . 2>/dev/null || true

# Cleanup temp files
rm -f tls_ca.cnf tls_server.cnf tls_server_ext.cnf tls_server.csr tls_ca_cert.srl

echo "TLS test certificates generated successfully."
