package policy
import future.keywords.every

default nv_match := false

nv_match {
    count(input) > 0
    every claim in input {
        validate_claim_by_device_type(claim)
    }
}

validate_claim_by_device_type(claim) {
    claim["x-nvidia-device-type"] == "gpu"
    validate_gpu_claims(claim)
}

validate_claim_by_device_type(claim) {
    claim["x-nvidia-device-type"] == "nvswitch"
    validate_switch_claims(claim)
}

validate_gpu_claims(claims) {
    check_gpu_measurements_match(claims)
    check_gpu_ar_cert_chain(claims)
    check_gpu_driver_rim_cert_chain(claims)
    check_gpu_vbios_rim_cert_chain(claims)
}

validate_switch_claims(claims) {
    check_switch_measurements_match(claims)
    check_switch_ar_cert_chain(claims)
    check_switch_bios_rim_cert_chain(claims)
}

# GPU: Allow success
check_gpu_measurements_match(claims) {
    claims.measres == "success"
}

# GPU: Allow failure only if all mismatched indices are in the allowed set (index 7)
check_gpu_measurements_match(claims) {
    claims.measres == "fail"
    mismatch_records := claims["x-nvidia-mismatch-measurement-records"]
    every record in mismatch_records {
        record.index == 7
    }
}

# Switch: Only allow success (no measurement mismatches allowed)
check_switch_measurements_match(claims) {
    claims.measres == "success"
}

check_gpu_ar_cert_chain(claims) {
    cert_chain := claims["x-nvidia-gpu-attestation-report-cert-chain"]
    cert_chain["x-nvidia-cert-status"] == "valid"
    cert_chain["x-nvidia-cert-ocsp-status"] == "good"
    cert_chain["x-nvidia-cert-ocsp-nonce-matches"] == true
    cert_chain["x-nvidia-cert-ocsp-response-valid"] == true
}

check_gpu_driver_rim_cert_chain(claims) {
    cert_chain := claims["x-nvidia-gpu-driver-rim-cert-chain"]
    cert_chain["x-nvidia-cert-status"] == "valid"
    cert_chain["x-nvidia-cert-ocsp-status"] == "good"
    cert_chain["x-nvidia-cert-ocsp-nonce-matches"] == true
    cert_chain["x-nvidia-cert-ocsp-response-valid"] == true
}

check_gpu_vbios_rim_cert_chain(claims) {
    cert_chain := claims["x-nvidia-gpu-vbios-rim-cert-chain"]
    cert_chain["x-nvidia-cert-status"] == "valid"
    cert_chain["x-nvidia-cert-ocsp-status"] == "good"
    cert_chain["x-nvidia-cert-ocsp-nonce-matches"] == true
    cert_chain["x-nvidia-cert-ocsp-response-valid"] == true
}

check_switch_ar_cert_chain(claims) {
    cert_chain := claims["x-nvidia-switch-attestation-report-cert-chain"]
    cert_chain["x-nvidia-cert-status"] == "valid"
    cert_chain["x-nvidia-cert-ocsp-status"] == "good"
    cert_chain["x-nvidia-cert-ocsp-nonce-matches"] == true
    cert_chain["x-nvidia-cert-ocsp-response-valid"] == true
}

check_switch_bios_rim_cert_chain(claims) {
    cert_chain := claims["x-nvidia-switch-bios-rim-cert-chain"]
    cert_chain["x-nvidia-cert-status"] == "valid"
    cert_chain["x-nvidia-cert-ocsp-status"] == "good"
    cert_chain["x-nvidia-cert-ocsp-nonce-matches"] == true
    cert_chain["x-nvidia-cert-ocsp-response-valid"] == true
}

