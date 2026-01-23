#!/bin/bash

set -e

# Check if certificates already exist (more than just this script in directory)
file_count=$(ls -1 | wc -l)
if [ "$file_count" -gt 1 ]; then
    echo "Certificates already exist. Skipping generation."
    exit 0
fi

echo "Generating test certificates..."

CERT_DIR="."
DAYS_VALID=3650 # 10 years

# Certificate and key file names
# do not use .pem extension, gitlab wont allow it
ROOT_CERT="${CERT_DIR}/root_cert"
ROOT_KEY="${CERT_DIR}/root_key"
LEAF_KEY="${CERT_DIR}/leaf_key"
LEAF_CERT_WITHOUT_FWID="${CERT_DIR}/leaf_cert_without_fwid"
LEAF_CERT_WITH_FWID="${CERT_DIR}/leaf_cert_with_fwid"
LEAF_CERT_EXPIRED="${CERT_DIR}/leaf_cert_expired"
LEAF_CERT_WRONG_SIGNATURE="${CERT_DIR}/leaf_cert_wrong_signature"
WRONG_ROOT_KEY="${CERT_DIR}/wrong_root_key"
WRONG_ROOT_CERT="${CERT_DIR}/wrong_root_cert"
SIGNATURE_FILE="${CERT_DIR}/valid_signature.sig"
DATA_FILE="${CERT_DIR}/signed_data.txt"

generate_root_cert() {
    echo "Generating Root CA key..."
    openssl genpkey -algorithm RSA -out "${ROOT_KEY}" -pkeyopt rsa_keygen_bits:2048

    echo "Creating Root CA configuration..."
    ROOT_CA_CNF="${CERT_DIR}/root_ca.cnf"
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

    rm "${ROOT_CA_CNF}"
}

generate_leaf_cert_without_fwid() {
    echo "Generating Leaf certificate without FWID..."
    
    LEAF_NO_FWID_CSR="${CERT_DIR}/leaf_csr_no_fwid.pem"
    LEAF_NO_FWID_CSR_CNF="${CERT_DIR}/leaf_no_fwid_csr.cnf"
    LEAF_NO_FWID_SIGN_CNF="${CERT_DIR}/leaf_no_fwid_sign.cnf"
    
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

    openssl req -new -key "${LEAF_KEY}" -out "${LEAF_NO_FWID_CSR}" -subj "/CN=TestLeafNoFwid" -config "${LEAF_NO_FWID_CSR_CNF}"
    openssl x509 -req -in "${LEAF_NO_FWID_CSR}" -CA "${ROOT_CERT}" -CAkey "${ROOT_KEY}" -CAcreateserial \
        -out "${LEAF_CERT_WITHOUT_FWID}" -days ${DAYS_VALID} -sha256 -extfile "${LEAF_NO_FWID_SIGN_CNF}" -extensions v3_leaf
    
    # Clean up temporary files
    rm "${LEAF_NO_FWID_CSR}" "${LEAF_NO_FWID_CSR_CNF}" "${LEAF_NO_FWID_SIGN_CNF}"
}

generate_leaf_cert_with_fwid() {
    echo "Generating Leaf certificate with FWID..."
    
    FWID_OID="2.23.133.5.4.1"
    # Generate 48 bytes of sequential FWID data (01 02 03 ... 30 in hex)
    FWID_HEX_VALUE=$(printf "%02x" {1..48} | sed 's/../&:/g' | sed 's/:$//')
    
    LEAF_WITH_FWID_CSR="${CERT_DIR}/leaf_csr_with_fwid.pem"
    LEAF_WITH_FWID_CSR_CNF="${CERT_DIR}/leaf_with_fwid_csr.cnf"
    LEAF_WITH_FWID_SIGN_CNF="${CERT_DIR}/leaf_with_fwid_sign.cnf"
    
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

    openssl req -new -key "${LEAF_KEY}" -out "${LEAF_WITH_FWID_CSR}" -subj "/CN=TestLeafWithFwid" -config "${LEAF_WITH_FWID_CSR_CNF}"
    openssl x509 -req -in "${LEAF_WITH_FWID_CSR}" -CA "${ROOT_CERT}" -CAkey "${ROOT_KEY}" -CAcreateserial \
        -out "${LEAF_CERT_WITH_FWID}" -days ${DAYS_VALID} -sha256 -extfile "${LEAF_WITH_FWID_SIGN_CNF}" -extensions v3_leaf_fwid
    
    # Clean up temporary files
    rm "${LEAF_WITH_FWID_CSR}" "${LEAF_WITH_FWID_CSR_CNF}" "${LEAF_WITH_FWID_SIGN_CNF}"
}

generate_leaf_cert_expired() {
    echo "Generating expired leaf certificate..."
    
    EXPIRED_CSR="${CERT_DIR}/leaf_expired_csr.pem"
    EXPIRED_CSR_CNF="${CERT_DIR}/leaf_expired_csr.cnf"
    EXPIRED_SIGN_CNF="${CERT_DIR}/leaf_expired_sign.cnf"
    
    # Create OpenSSL config for leaf cert CSR
    cat > "${EXPIRED_CSR_CNF}" <<EOF
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = TestLeafExpired

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectKeyIdentifier = hash
EOF

    # Create OpenSSL config for signing leaf cert
    cat > "${EXPIRED_SIGN_CNF}" <<EOF
[ v3_leaf ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

    openssl req -new -key "${LEAF_KEY}" -out "${EXPIRED_CSR}" -subj "/CN=TestLeafExpired" -config "${EXPIRED_CSR_CNF}"
    openssl x509 -req -in "${EXPIRED_CSR}" -CA "${ROOT_CERT}" -CAkey "${ROOT_KEY}" -CAcreateserial \
        -out "${LEAF_CERT_EXPIRED}" -days -1 -sha256 -extfile "${EXPIRED_SIGN_CNF}" -extensions v3_leaf
    
    # Clean up temporary files
    rm "${EXPIRED_CSR}" "${EXPIRED_CSR_CNF}" "${EXPIRED_SIGN_CNF}"
}

generate_leaf_cert_wrong_signature() {
    echo "Generating wrong root CA for invalid signature test..."
    
    WRONG_ROOT_CA_CNF="${CERT_DIR}/wrong_root_ca.cnf"

    cat > "${WRONG_ROOT_CA_CNF}" <<EOF
[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = critical,CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
EOF

    openssl genpkey -algorithm RSA -out "${WRONG_ROOT_KEY}" -pkeyopt rsa_keygen_bits:2048
    openssl req -x509 -new -nodes -key "${WRONG_ROOT_KEY}" \
        -sha256 -days ${DAYS_VALID} -out "${WRONG_ROOT_CERT}" \
        -subj "/CN=WrongRootCA" \
        -extensions v3_ca -config "${WRONG_ROOT_CA_CNF}"

    echo "Generating leaf certificate signed by wrong CA..."
    WRONG_SIG_CSR="${CERT_DIR}/leaf_wrong_sig_csr.pem"
    WRONG_SIG_CSR_CNF="${CERT_DIR}/leaf_wrong_sig_csr.cnf"
    WRONG_SIG_SIGN_CNF="${CERT_DIR}/leaf_wrong_sig_sign.cnf"

    cat > "${WRONG_SIG_CSR_CNF}" <<EOF
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = TestLeafWrongSignature

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectKeyIdentifier = hash
EOF

    cat > "${WRONG_SIG_SIGN_CNF}" <<EOF
[ v3_leaf ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

    openssl req -new -key "${LEAF_KEY}" -out "${WRONG_SIG_CSR}" -subj "/CN=TestLeafWrongSignature" -config "${WRONG_SIG_CSR_CNF}"
    # Sign with the wrong CA instead of the correct root CA
    openssl x509 -req -in "${WRONG_SIG_CSR}" -CA "${WRONG_ROOT_CERT}" -CAkey "${WRONG_ROOT_KEY}" -CAcreateserial \
        -out "${LEAF_CERT_WRONG_SIGNATURE}" -days ${DAYS_VALID} -sha256 -extfile "${WRONG_SIG_SIGN_CNF}" -extensions v3_leaf

    # Clean up temporary files and wrong root key (not needed after this function)
    rm "${WRONG_SIG_CSR}" "${WRONG_SIG_CSR_CNF}" "${WRONG_SIG_SIGN_CNF}" "${WRONG_ROOT_CA_CNF}" "${WRONG_ROOT_KEY}"
}

generate_es384_keypair() {
    echo "Generating ES384 (secp384r1) keypair for tests..."
    
    EC_PRIV="${CERT_DIR}/ec_p384_private.pem"
    EC_PUB="${CERT_DIR}/ec_p384_public.pem"
    
    if [ ! -f "${EC_PRIV}" ] || [ ! -f "${EC_PUB}" ]; then
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out "${EC_PRIV}"
        openssl pkey -in "${EC_PRIV}" -pubout -out "${EC_PUB}"
    fi
}

create_valid_signature() {
    echo "Creating valid signature with leaf certificate with FWID..."
    
    # Create the data file
    echo -n "hello world" > "${DATA_FILE}"
    
    # Sign the data with the leaf key
    openssl dgst -sha256 -sign "${LEAF_KEY}" -out "${SIGNATURE_FILE}" "${DATA_FILE}"
    
    echo "Signature created: ${SIGNATURE_FILE}"
    echo "Signed data: ${DATA_FILE}"
}

# Clean up existing certificate files
rm -f "${ROOT_CERT}" "${ROOT_KEY}" "${LEAF_KEY}" "${LEAF_CERT_WITHOUT_FWID}" "${LEAF_CERT_WITH_FWID}" "${LEAF_CERT_EXPIRED}" "${LEAF_CERT_WRONG_SIGNATURE}" "${WRONG_ROOT_KEY}" "${WRONG_ROOT_CERT}" "${CERT_DIR}/valid_signature.sig" "${CERT_DIR}/signed_data.txt"

# Generate root certificate
generate_root_cert

echo "Generating Leaf key..."
openssl genpkey -algorithm RSA -out "${LEAF_KEY}" -pkeyopt rsa_keygen_bits:2048

# Generate all leaf certificates using functions
generate_leaf_cert_without_fwid
generate_leaf_cert_with_fwid
generate_leaf_cert_expired

# Remove root key (no longer needed after leaf cert generation)
rm -f "${ROOT_KEY}"

generate_leaf_cert_wrong_signature

# Generate ES384 keypair
generate_es384_keypair

# Create valid signature
create_valid_signature

# Remove leaf key (no longer needed after signature creation)
rm -f "${LEAF_KEY}"

# Define EC key paths for summary output
EC_PRIV="${CERT_DIR}/ec_p384_private.pem"
EC_PUB="${CERT_DIR}/ec_p384_public.pem"

echo "Certificates generated in ${CERT_DIR}"
echo "Root CA: ${ROOT_CERT}"
echo "Leaf without FWID: ${LEAF_CERT_WITHOUT_FWID}"
echo "Leaf with FWID: ${LEAF_CERT_WITH_FWID}"
echo "Leaf Expired: ${LEAF_CERT_EXPIRED}"
echo "Leaf Wrong Signature: ${LEAF_CERT_WRONG_SIGNATURE}"
echo "Wrong Root CA: ${WRONG_ROOT_CERT}"
echo "ES384 Private Key: ${EC_PRIV}"
echo "ES384 Public Key: ${EC_PUB}"
echo "Valid Signature: ${CERT_DIR}/valid_signature.sig"
echo "Signed Data: ${CERT_DIR}/signed_data.txt"