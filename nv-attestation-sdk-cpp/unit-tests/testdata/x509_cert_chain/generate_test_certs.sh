#!/bin/bash

set -e

# Skip only if every expected output is present. Naming a specific set
# (rather than counting files) so adding new artifacts to the script forces
# regeneration on machines that already had the older subset.
EXPECTED_OUTPUTS=(
    root_cert
    leaf_cert_without_fwid leaf_cert_with_fwid leaf_cert_expired leaf_cert_wrong_signature
    wrong_root_cert
    ec_p384_private.pem ec_p384_public.pem
    valid_signature.sig signed_data.txt
    cose_signing_root.crt cose_signing_root_key.pem
    cose_signing_leaf.crt cose_signing_leaf_key.pem
    eat_jwks_leaf_key.pem eat_jwks_leaf
    eat_jwks_ca_key.pem eat_jwks_ca eat_jwks_chain_leaf_key.pem eat_jwks_chain_leaf
    eat_jwks_root eat_jwks_int eat_jwks_int_leaf_key.pem eat_jwks_int_leaf
    leaf_cert_fsp_cn leaf_cert_gsp_cn
)
all_present=1
for f in "${EXPECTED_OUTPUTS[@]}"; do
    [[ -f "$f" ]] || { all_present=0; break; }
done
if [[ "$all_present" == "1" ]]; then
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
COSE_SIGNING_ROOT_KEY="${CERT_DIR}/cose_signing_root_key.pem"
COSE_SIGNING_ROOT_CERT="${CERT_DIR}/cose_signing_root.crt"
COSE_SIGNING_LEAF_KEY="${CERT_DIR}/cose_signing_leaf_key.pem"
COSE_SIGNING_LEAF_CERT="${CERT_DIR}/cose_signing_leaf.crt"
EAT_JWKS_KEY="${CERT_DIR}/eat_jwks_leaf_key.pem"
EAT_JWKS_CERT="${CERT_DIR}/eat_jwks_leaf"

generate_root_cert() {
    echo "Generating Root CA key..."
    openssl genpkey -algorithm RSA -out "${ROOT_KEY}" -pkeyopt rsa_keygen_bits:2048

    echo "Creating Root CA configuration..."
    ROOT_CA_CNF="${CERT_DIR}/root_ca.cnf"
    cat > "${ROOT_CA_CNF}" <<EOF
[ req ]
distinguished_name = req_dn
[ req_dn ]
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
[ req ]
distinguished_name = req_dn
[ req_dn ]
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
    
    if [[ ! -f "${EC_PRIV}" || ! -f "${EC_PUB}" ]]; then
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out "${EC_PRIV}"
        openssl pkey -in "${EC_PRIV}" -pubout -out "${EC_PUB}"
    fi
}

generate_eat_jwks_leaf() {
    echo "Generating EC P-384 EAT/JWKS signing cert + key..."
    # Self-signed EC P-384 leaf used to sign test EATs (ES384) and to populate a
    # test JWKS (its DER goes in the x5c entry the SDK reads).
    openssl ecparam -name secp384r1 -genkey -noout -out "${EAT_JWKS_KEY}"
    openssl req -new -x509 -key "${EAT_JWKS_KEY}" -out "${EAT_JWKS_CERT}" -days ${DAYS_VALID} \
        -subj "/CN=nvat-test-eat-signer"
}

generate_eat_jwks_chain_certs() {
    echo "Generating EC P-384 EAT/JWKS CA cert + chain leaf cert..."
    local CA_KEY="${CERT_DIR}/eat_jwks_ca_key.pem"
    local CA_CERT="${CERT_DIR}/eat_jwks_ca"
    local CHAIN_LEAF_KEY="${CERT_DIR}/eat_jwks_chain_leaf_key.pem"
    local CHAIN_LEAF_CERT="${CERT_DIR}/eat_jwks_chain_leaf"
    local CA_CNF="${CERT_DIR}/eat_jwks_ca.cnf"
    local CHAIN_LEAF_CSR="${CERT_DIR}/eat_jwks_chain_leaf.csr"
    local CHAIN_LEAF_CSR_CNF="${CERT_DIR}/eat_jwks_chain_leaf_csr.cnf"
    local CHAIN_LEAF_SIGN_CNF="${CERT_DIR}/eat_jwks_chain_leaf_sign.cnf"

    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out "${CA_KEY}"

    cat > "${CA_CNF}" <<EOF
[ req ]
distinguished_name = req_dn
[ req_dn ]
[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = critical,CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
EOF

    openssl req -x509 -new -nodes -key "${CA_KEY}" \
        -sha384 -days ${DAYS_VALID} -out "${CA_CERT}" \
        -subj "/CN=nvat-test-eat-jwks-ca" \
        -extensions v3_ca -config "${CA_CNF}"

    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out "${CHAIN_LEAF_KEY}"

    cat > "${CHAIN_LEAF_CSR_CNF}" <<EOF
[ req ]
distinguished_name = dn
req_extensions = v3_req
prompt = no

[ dn ]
CN = nvat-test-eat-chain-leaf

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
subjectKeyIdentifier = hash
EOF

    cat > "${CHAIN_LEAF_SIGN_CNF}" <<EOF
[ v3_leaf ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

    openssl req -new -key "${CHAIN_LEAF_KEY}" -out "${CHAIN_LEAF_CSR}" \
        -subj "/CN=nvat-test-eat-chain-leaf" -config "${CHAIN_LEAF_CSR_CNF}"
    openssl x509 -req -in "${CHAIN_LEAF_CSR}" \
        -CA "${CA_CERT}" -CAkey "${CA_KEY}" -CAcreateserial \
        -out "${CHAIN_LEAF_CERT}" -days ${DAYS_VALID} -sha384 \
        -extfile "${CHAIN_LEAF_SIGN_CNF}" -extensions v3_leaf

    rm -f "${CA_CNF}" "${CHAIN_LEAF_CSR}" "${CHAIN_LEAF_CSR_CNF}" \
          "${CHAIN_LEAF_SIGN_CNF}" "${CERT_DIR}/eat_jwks_ca.srl"
}

generate_cose_signing_chain() {
    echo "Generating ES384 COSE_Sign1 CoRIM signing chain..."

    COSE_ROOT_CNF="${CERT_DIR}/cose_signing_root.cnf"
    COSE_LEAF_CSR="${CERT_DIR}/cose_signing_leaf.csr"
    COSE_LEAF_CSR_CNF="${CERT_DIR}/cose_signing_leaf_csr.cnf"
    COSE_LEAF_SIGN_CNF="${CERT_DIR}/cose_signing_leaf_sign.cnf"

    cat > "${COSE_ROOT_CNF}" <<EOF
[ req ]
distinguished_name = req_dn
[ req_dn ]
[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = critical,CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
EOF

    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out "${COSE_SIGNING_ROOT_KEY}"
    openssl req -x509 -new -nodes -key "${COSE_SIGNING_ROOT_KEY}" \
        -sha384 -days ${DAYS_VALID} -out "${COSE_SIGNING_ROOT_CERT}" \
        -subj "/CN=TestCoRIMSigningRootCA" \
        -extensions v3_ca -config "${COSE_ROOT_CNF}"

    cat > "${COSE_LEAF_CSR_CNF}" <<EOF
[ req ]
distinguished_name = dn
req_extensions = v3_req
prompt = no

[ dn ]
CN = TestCoRIMSigningLeaf

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
subjectKeyIdentifier = hash
EOF

    cat > "${COSE_LEAF_SIGN_CNF}" <<EOF
[ v3_leaf ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out "${COSE_SIGNING_LEAF_KEY}"
    openssl req -new -key "${COSE_SIGNING_LEAF_KEY}" -out "${COSE_LEAF_CSR}" \
        -subj "/CN=TestCoRIMSigningLeaf" -config "${COSE_LEAF_CSR_CNF}"
    openssl x509 -req -in "${COSE_LEAF_CSR}" \
        -CA "${COSE_SIGNING_ROOT_CERT}" -CAkey "${COSE_SIGNING_ROOT_KEY}" -CAcreateserial \
        -out "${COSE_SIGNING_LEAF_CERT}" -days ${DAYS_VALID} -sha384 \
        -extfile "${COSE_LEAF_SIGN_CNF}" -extensions v3_leaf

    rm -f "${COSE_ROOT_CNF}" "${COSE_LEAF_CSR}" "${COSE_LEAF_CSR_CNF}" \
          "${COSE_LEAF_SIGN_CNF}" "${CERT_DIR}/cose_signing_root.srl"
}

generate_fsp_gsp_responder_leaf_certs() {
    echo "Generating synthetic FSP/GSP responder-CN leaf certs..."
    local FSP_KEY="${CERT_DIR}/leaf_key_fsp_cn"
    local GSP_KEY="${CERT_DIR}/leaf_key_gsp_cn"

    openssl genpkey -algorithm RSA -out "${FSP_KEY}" -pkeyopt rsa_keygen_bits:2048
    openssl req -x509 -new -nodes -key "${FSP_KEY}" -sha256 -days ${DAYS_VALID} \
        -out "${CERT_DIR}/leaf_cert_fsp_cn" -subj "/CN=NVIDIA GB100 FSP Responder"

    openssl genpkey -algorithm RSA -out "${GSP_KEY}" -pkeyopt rsa_keygen_bits:2048
    openssl req -x509 -new -nodes -key "${GSP_KEY}" -sha256 -days ${DAYS_VALID} \
        -out "${CERT_DIR}/leaf_cert_gsp_cn" -subj "/CN=NVIDIA GB100 GSP Responder"

    rm -f "${FSP_KEY}" "${GSP_KEY}"
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

generate_eat_jwks_int_chain_certs() {
    echo "Generating EC P-384 3-level EAT/JWKS chain (root -> intermediate -> leaf)..."
    local ROOT_KEY="${CERT_DIR}/eat_jwks_root_key.pem"
    local ROOT_CERT="${CERT_DIR}/eat_jwks_root"
    local INT_KEY="${CERT_DIR}/eat_jwks_int_key.pem"
    local INT_CERT="${CERT_DIR}/eat_jwks_int"
    local INT_LEAF_KEY="${CERT_DIR}/eat_jwks_int_leaf_key.pem"
    local INT_LEAF_CERT="${CERT_DIR}/eat_jwks_int_leaf"
    local ROOT_CNF="${CERT_DIR}/eat_jwks_root.cnf"
    local INT_CNF="${CERT_DIR}/eat_jwks_int.cnf"
    local INT_CSR="${CERT_DIR}/eat_jwks_int.csr"
    local INT_SIGN_CNF="${CERT_DIR}/eat_jwks_int_sign.cnf"
    local INT_LEAF_CSR="${CERT_DIR}/eat_jwks_int_leaf.csr"
    local INT_LEAF_CSR_CNF="${CERT_DIR}/eat_jwks_int_leaf_csr.cnf"
    local INT_LEAF_SIGN_CNF="${CERT_DIR}/eat_jwks_int_leaf_sign.cnf"

    # Root CA (self-signed)
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out "${ROOT_KEY}"
    cat > "${ROOT_CNF}" <<EOF
[ req ]
distinguished_name = req_dn
[ req_dn ]
[ v3_root_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = critical,CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
EOF
    openssl req -x509 -new -nodes -key "${ROOT_KEY}" \
        -sha384 -days ${DAYS_VALID} -out "${ROOT_CERT}" \
        -subj "/CN=nvat-test-eat-jwks-root" \
        -extensions v3_root_ca -config "${ROOT_CNF}"

    # Intermediate CA (signed by root, CA:TRUE)
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out "${INT_KEY}"
    cat > "${INT_CNF}" <<EOF
[ req ]
distinguished_name = dn
req_extensions = v3_req
prompt = no

[ dn ]
CN = nvat-test-eat-jwks-int

[ v3_req ]
basicConstraints = critical,CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF
    cat > "${INT_SIGN_CNF}" <<EOF
[ v3_int_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
    openssl req -new -key "${INT_KEY}" -out "${INT_CSR}" \
        -subj "/CN=nvat-test-eat-jwks-int" -config "${INT_CNF}"
    openssl x509 -req -in "${INT_CSR}" \
        -CA "${ROOT_CERT}" -CAkey "${ROOT_KEY}" -CAcreateserial \
        -out "${INT_CERT}" -days ${DAYS_VALID} -sha384 \
        -extfile "${INT_SIGN_CNF}" -extensions v3_int_ca

    # Remove root key (no longer needed after intermediate signing)
    rm -f "${ROOT_KEY}" "${ROOT_CNF}" "${INT_CSR}" "${INT_SIGN_CNF}" \
          "${CERT_DIR}/eat_jwks_root.srl"

    # Leaf (signed by intermediate)
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out "${INT_LEAF_KEY}"
    cat > "${INT_LEAF_CSR_CNF}" <<EOF
[ req ]
distinguished_name = dn
req_extensions = v3_req
prompt = no

[ dn ]
CN = nvat-test-eat-jwks-int-leaf

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
subjectKeyIdentifier = hash
EOF
    cat > "${INT_LEAF_SIGN_CNF}" <<EOF
[ v3_leaf ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
    openssl req -new -key "${INT_LEAF_KEY}" -out "${INT_LEAF_CSR}" \
        -subj "/CN=nvat-test-eat-jwks-int-leaf" -config "${INT_LEAF_CSR_CNF}"
    openssl x509 -req -in "${INT_LEAF_CSR}" \
        -CA "${INT_CERT}" -CAkey "${INT_KEY}" -CAcreateserial \
        -out "${INT_LEAF_CERT}" -days ${DAYS_VALID} -sha384 \
        -extfile "${INT_LEAF_SIGN_CNF}" -extensions v3_leaf

    rm -f "${INT_CNF}" "${INT_LEAF_CSR}" "${INT_LEAF_CSR_CNF}" \
          "${INT_LEAF_SIGN_CNF}" "${CERT_DIR}/eat_jwks_int.srl"
}

# Clean up existing certificate files
rm -f "${ROOT_CERT}" "${ROOT_KEY}" "${LEAF_KEY}" "${LEAF_CERT_WITHOUT_FWID}" "${LEAF_CERT_WITH_FWID}" "${LEAF_CERT_EXPIRED}" "${LEAF_CERT_WRONG_SIGNATURE}" "${WRONG_ROOT_KEY}" "${WRONG_ROOT_CERT}" "${CERT_DIR}/valid_signature.sig" "${CERT_DIR}/signed_data.txt" "${COSE_SIGNING_ROOT_KEY}" "${COSE_SIGNING_ROOT_CERT}" "${COSE_SIGNING_LEAF_KEY}" "${COSE_SIGNING_LEAF_CERT}" "${EAT_JWKS_KEY}" "${EAT_JWKS_CERT}" "${CERT_DIR}/eat_jwks_ca_key.pem" "${CERT_DIR}/eat_jwks_ca" "${CERT_DIR}/eat_jwks_chain_leaf_key.pem" "${CERT_DIR}/eat_jwks_chain_leaf" "${CERT_DIR}/eat_jwks_root" "${CERT_DIR}/eat_jwks_root_key.pem" "${CERT_DIR}/eat_jwks_int" "${CERT_DIR}/eat_jwks_int_key.pem" "${CERT_DIR}/eat_jwks_int_leaf" "${CERT_DIR}/eat_jwks_int_leaf_key.pem" "${CERT_DIR}/leaf_cert_fsp_cn" "${CERT_DIR}/leaf_cert_gsp_cn"

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

# Generate ES384 CoRIM signing chain (used by signed-CoRIM unit + fuzz tests)
generate_cose_signing_chain

# Generate EC P-384 EAT/JWKS signing cert + key (used by the verify_attestation_result e2e test)
generate_eat_jwks_leaf

# Generate EC P-384 EAT/JWKS CA + chain leaf (used by the x5c chain validation test)
generate_eat_jwks_chain_certs

# Generate EC P-384 3-level chain (root -> intermediate -> leaf) for partial-chain test
generate_eat_jwks_int_chain_certs

generate_fsp_gsp_responder_leaf_certs

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
echo "CoRIM Signing Root: ${COSE_SIGNING_ROOT_CERT}"
echo "CoRIM Signing Leaf: ${COSE_SIGNING_LEAF_CERT}"
echo "EAT/JWKS Signing Leaf: ${EAT_JWKS_CERT}"
echo "EAT/JWKS Signing Key: ${EAT_JWKS_KEY}"
echo "EAT/JWKS Chain CA: ${CERT_DIR}/eat_jwks_ca"
echo "EAT/JWKS Chain Leaf: ${CERT_DIR}/eat_jwks_chain_leaf"
echo "EAT/JWKS Int chain root: ${CERT_DIR}/eat_jwks_root"
echo "EAT/JWKS Int chain intermediate: ${CERT_DIR}/eat_jwks_int"
echo "EAT/JWKS Int chain leaf: ${CERT_DIR}/eat_jwks_int_leaf"
echo "EAT/JWKS Int chain leaf key: ${CERT_DIR}/eat_jwks_int_leaf_key.pem"
echo "Valid Signature: ${CERT_DIR}/valid_signature.sig"
echo "Signed Data: ${CERT_DIR}/signed_data.txt"
