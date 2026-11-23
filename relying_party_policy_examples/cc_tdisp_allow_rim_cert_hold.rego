# DISCLAIMER: The EAR format and this policy are pre-release and subject to
# change without notice.

package policy

import future.keywords.every
import future.keywords.in

# Reference policy for TDISP EARs. It accepts what builtin:cc-tdisp accepts,
# and also accepts a GPU whose CoRIM leaf signing certificate is on hold: OCSP
# status "revoked" with reason "certificateHold".
#
# The verifier marks such a submod contraindicated, so this policy re-derives
# the rest of the appraisal from the EAR and accepts the submod only when the
# hold is the sole problem. Nothing else is relaxed: a hold on any other RIM
# chain cert, any other revocation reason, an expired cert, an OCSP nonce or
# response failure, any evidence (attestation report) chain failure, any
# measurement mismatch, or any other verifier error is still rejected.

default nv_match := false

gpu_purposes := {"TDISP"}

nv_match {
    startswith(input.eat_profile, "tag:nvidia.com,2026:ear/profiles/composite/generic/pre-1.")
    # The top-level ear_status is the least favorable submod status, so it is
    # contraindicated whenever a RIM leaf is on hold. Each submod is judged
    # individually below instead.
    count(input.submods) > 0
    every submod in input.submods {
        validate_submod_by_profile(submod)
    }
}

validate_submod_by_profile(submod) {
    # GPU 1.x claims
    startswith(submod.eat_profile, "tag:nvidia.com,2026-05:ear/profiles/gpu/1.")
    submod.ear_nvidia_purpose in gpu_purposes
    submod.ear_verifier_claims.ear_nvidia_evidence.nonce_match == true
    appraisal_accepted(submod)
}

appraisal_accepted(submod) {
    submod.ear_status == "affirming"
}

appraisal_accepted(submod) {
    submod.ear_status == "contraindicated"
    only_rim_leaf_cert_hold(submod)
}

# True when the RIM leaf cert hold is the only reason the submod failed.
only_rim_leaf_cert_hold(submod) {
    claims := submod.ear_verifier_claims

    # Evidence signature, anchoring and device cert chain: no relaxation.
    evidence := claims.ear_nvidia_evidence
    evidence.signature_verified == true
    every cert in object.get(evidence, "cert_chain", []) {
        cert_trusted(cert)
    }

    rims := claims.ear_nvidia_rims
    count(rims) > 0
    every rim in rims {
        rim_accepted(rim)
    }
    some_rim_leaf_on_hold(rims)

    # Every reported error must be a held RIM signing chain. This excludes
    # stage errors, other RIM failures and appraisal diagnostics.
    errors := submod.ear_nvidia_error_details
    count(errors) > 0
    every detail in errors {
        rim_signing_chain_error(detail)
    }

    cmp := claims.ear_nvidia_evidence_rim_cmp
    count(cmp.mismatched_env) == 0
    count(cmp.matched_env) > 0
}

rim_signing_chain_error(detail) {
    detail.code == 802
}

rim_verified(rim) {
    rim.fetched == true
    rim.parsed == true
    rim.signature_verified == true
}

# A RIM with no error must have a fully trusted signing chain.
rim_accepted(rim) {
    rim_verified(rim)
    not rim.error
    every index, cert in object.get(rim, "cert_chain", []) {
        rim_cert_trusted(index, cert)
    }
}

# A RIM whose only error is its signing chain, where the leaf is on hold and
# every other cert in the chain is trusted.
rim_accepted(rim) {
    rim_verified(rim)
    rim.error.code == 802
    leaf_on_hold_rest_trusted(rim.cert_chain)
}

some_rim_leaf_on_hold(rims) {
    some rim in rims
    rim.error
    leaf_on_hold_rest_trusted(rim.cert_chain)
}

# cert_chain is ordered root first, so the leaf is the last entry.
leaf_on_hold_rest_trusted(chain) {
    leaf_index := count(chain) - 1
    leaf_index >= 0
    cert_on_hold(chain[leaf_index])
    every index, cert in chain {
        trusted_unless_leaf(index, leaf_index, cert)
    }
}

trusted_unless_leaf(index, leaf_index, _) {
    index == leaf_index
}

trusted_unless_leaf(index, leaf_index, cert) {
    index != leaf_index
    rim_cert_trusted(index, cert)
}

# RIM signing chains: only the root may skip OCSP. Every other cert must
# have been checked and found good.
rim_cert_trusted(index, cert) {
    index == 0
    cert_trusted(cert)
}

rim_cert_trusted(index, cert) {
    index != 0
    cert.expired == false
    ocsp_good(cert)
}

cert_on_hold(cert) {
    cert.expired == false
    cert.ocsp_crl_status == "revoked"
    cert.revocation_reason == "certificateHold"
    cert.ocsp_nonce_matches == true
    cert.ocsp_response_status == true
}

# Mirrors the SDK's all_certs_trusted: unexpired, and when OCSP applies, good
# with a matching nonce and a valid response. Used as-is for the evidence
# chain, whose device leaf the SDK never checks over OCSP.
cert_trusted(cert) {
    cert.expired == false
    ocsp_acceptable(cert)
}

ocsp_acceptable(cert) {
    not cert.ocsp_crl_status
}

ocsp_acceptable(cert) {
    cert.ocsp_crl_status == "not_checked"
}

ocsp_acceptable(cert) {
    ocsp_good(cert)
}

ocsp_good(cert) {
    cert.ocsp_crl_status == "good"
    cert.ocsp_nonce_matches == true
    cert.ocsp_response_status == true
}
