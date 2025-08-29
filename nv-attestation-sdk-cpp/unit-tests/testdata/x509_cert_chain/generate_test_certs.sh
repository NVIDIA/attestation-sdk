#!/bin/bash

set -e

# Check if certificates already exist (more than just this script in directory)
file_count=$(ls -1 | wc -l)
if [ "$file_count" -gt 1 ]; then
    echo "Certificates already exist. Skipping generation."
    exit 0
fi

echo "Generating test certificates..."

FWID_OID="2.23.133.5.4.1"
# Generate 48 bytes of sequential FWID data (01 02 03 ... 30 in hex)
FWID_HEX_VALUE=$(printf "%02x" {1..48} | sed 's/../&:/g' | sed 's/:$//')
CERT_DIR="."
DAYS_VALID=3650 # 10 years

# Certificate and key file names
# do not use .pem extension, gitlab wont allow it
ROOT_CERT="${CERT_DIR}/root_cert"
ROOT_KEY="${CERT_DIR}/root_key"
LEAF_KEY="${CERT_DIR}/leaf_key"
LEAF_CERT_WITHOUT_FWID="${CERT_DIR}/leaf_cert_without_fwid"
LEAF_CERT_WITH_FWID="${CERT_DIR}/leaf_cert_with_fwid"

# Temporary file names (will be cleaned up)
ROOT_CA_CNF="${CERT_DIR}/root_ca.cnf"
LEAF_NO_FWID_CSR="${CERT_DIR}/leaf_csr_no_fwid.pem"
LEAF_NO_FWID_CSR_CNF="${CERT_DIR}/leaf_no_fwid_csr.cnf"
LEAF_NO_FWID_SIGN_CNF="${CERT_DIR}/leaf_no_fwid_sign.cnf"
LEAF_WITH_FWID_CSR="${CERT_DIR}/leaf_csr_with_fwid.pem"
LEAF_WITH_FWID_CSR_CNF="${CERT_DIR}/leaf_with_fwid_csr.cnf"
LEAF_WITH_FWID_SIGN_CNF="${CERT_DIR}/leaf_with_fwid_sign.cnf"

# Clean up existing certificate files
rm -f "${ROOT_CERT}" "${ROOT_KEY}" "${LEAF_KEY}" "${LEAF_CERT_WITHOUT_FWID}" "${LEAF_CERT_WITH_FWID}"

echo "Generating Root CA key..."
openssl genpkey -algorithm RSA -out "${ROOT_KEY}" -pkeyopt rsa_keygen_bits:2048

echo "Creating Root CA configuration..."
cat > "${ROOT_CA_CNF}" <<EOF
[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always # For a self-signed root, AKID refers to itself
basicConstraints = critical,CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
EOF

echo "Generating Root CA certificate..."
openssl req -x509 -new -nodes -key "${ROOT_KEY}" \
    -sha256 -days ${DAYS_VALID} -out "${ROOT_CERT}" \
    -subj "/CN=TestRootCA" \
    -extensions v3_ca -config "${ROOT_CA_CNF}"

echo "Generating Leaf key..."
openssl genpkey -algorithm RSA -out "${LEAF_KEY}" -pkeyopt rsa_keygen_bits:2048

# Create OpenSSL config for leaf cert CSR without FWID
cat > "${LEAF_NO_FWID_CSR_CNF}" <<EOF
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = TestLeafNoFwid

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectKeyIdentifier = hash
EOF

# Create OpenSSL config for signing leaf cert without FWID
cat > "${LEAF_NO_FWID_SIGN_CNF}" <<EOF
[ v3_leaf ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

echo "Generating Leaf certificate without FWID..."
openssl req -new -key "${LEAF_KEY}" -out "${LEAF_NO_FWID_CSR}" -subj "/CN=TestLeafNoFwid" -config "${LEAF_NO_FWID_CSR_CNF}"
openssl x509 -req -in "${LEAF_NO_FWID_CSR}" -CA "${ROOT_CERT}" -CAkey "${ROOT_KEY}" -CAcreateserial \
    -out "${LEAF_CERT_WITHOUT_FWID}" -days ${DAYS_VALID} -sha256 -extfile "${LEAF_NO_FWID_SIGN_CNF}" -extensions v3_leaf

# Create OpenSSL config for leaf cert CSR with FWID
cat > "${LEAF_WITH_FWID_CSR_CNF}" <<EOF
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req_fwid
prompt = no

[ req_distinguished_name ]
CN = TestLeafWithFwid

[ v3_req_fwid ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectKeyIdentifier = hash
${FWID_OID}=DER:${FWID_HEX_VALUE}
EOF

# Create OpenSSL config for signing leaf cert with FWID
cat > "${LEAF_WITH_FWID_SIGN_CNF}" <<EOF
[ v3_leaf_fwid ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
${FWID_OID}=DER:${FWID_HEX_VALUE}
EOF

echo "Generating Leaf certificate with FWID..."
openssl req -new -key "${LEAF_KEY}" -out "${LEAF_WITH_FWID_CSR}" -subj "/CN=TestLeafWithFwid" -config "${LEAF_WITH_FWID_CSR_CNF}"
openssl x509 -req -in "${LEAF_WITH_FWID_CSR}" -CA "${ROOT_CERT}" -CAkey "${ROOT_KEY}" -CAcreateserial \
    -out "${LEAF_CERT_WITH_FWID}" -days ${DAYS_VALID} -sha256 -extfile "${LEAF_WITH_FWID_SIGN_CNF}" -extensions v3_leaf_fwid

# Clean up CSRs and config files
rm "${LEAF_NO_FWID_CSR}" "${LEAF_NO_FWID_CSR_CNF}" "${LEAF_NO_FWID_SIGN_CNF}"
rm "${LEAF_WITH_FWID_CSR}" "${LEAF_WITH_FWID_CSR_CNF}" "${LEAF_WITH_FWID_SIGN_CNF}"
rm "${ROOT_CA_CNF}" # remove root CA config

echo "Certificates generated in ${CERT_DIR}"
echo "Root CA: ${ROOT_CERT}"
echo "Leaf without FWID: ${LEAF_CERT_WITHOUT_FWID}"
echo "Leaf with FWID: ${LEAF_CERT_WITH_FWID}"
echo "Leaf Key (not directly used by test after generation): ${LEAF_KEY}"
echo "Root Key (not directly used by test after generation): ${ROOT_KEY}" 