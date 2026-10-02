package policy
import future.keywords.every

# This example ignores opaque RIM data mismatches (x-nvidia-mismatch-opaque-data-records,
# checked by the SDK's default policy) and allows RIM cert chains to be revoked.
#
# check_measurements_match checks x-nvidia-mismatch-measurement-records directly
# rather than measres, since measres also reflects opaque-data mismatches.


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
    check_measurements_match(claims)
    check_gpu_ar_cert_chain(claims)
    check_gpu_driver_rim_cert_chain(claims)
    check_gpu_vbios_rim_cert_chain(claims)
}

validate_switch_claims(claims) {
    check_measurements_match(claims)
    check_switch_ar_cert_chain(claims)
    check_switch_bios_rim_cert_chain(claims)
}

check_measurements_match(claims) {
    object.get(claims, "x-nvidia-mismatch-measurement-records", null) == null
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
    cert_chain["x-nvidia-cert-ocsp-status"] in {"good", "revoked"}
    cert_chain["x-nvidia-cert-ocsp-nonce-matches"] == true
    cert_chain["x-nvidia-cert-ocsp-response-valid"] == true
}

check_gpu_vbios_rim_cert_chain(claims) {
    cert_chain := claims["x-nvidia-gpu-vbios-rim-cert-chain"]
    cert_chain["x-nvidia-cert-status"] == "valid"
    cert_chain["x-nvidia-cert-ocsp-status"] in {"good", "revoked"}
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
    cert_chain["x-nvidia-cert-ocsp-status"] in {"good", "revoked"}
    cert_chain["x-nvidia-cert-ocsp-nonce-matches"] == true
    cert_chain["x-nvidia-cert-ocsp-response-valid"] == true
}
