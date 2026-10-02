#!/bin/bash
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Public dependencies
BUILD_DEPS="cmake git pkg-config clang clang-tidy lld llvm curl wget"
COMPILE_DEPS="libxml2-dev zlib1g-dev"

echo "--- Installing starter dependencies ---"
apt-get update && apt-get install -y $BUILD_DEPS

# NVIDIA dependencies
# Derive distro: ubuntu2204, ubuntu2404
if [ -f /etc/os-release ]; then
    . /etc/os-release
    NV_DISTRO="ubuntu${VERSION_ID//./}"
else
    echo "ERROR: Cannot detect OS version from /etc/os-release"
    exit 1
fi

# Derive architecture: x86_64, aarch64 (sbsa)
HOST_ARCH=$(uname -m)
case "$HOST_ARCH" in
    x86_64)  NV_ARCH="x86_64" ;;
    aarch64) NV_ARCH="sbsa" ;;
    *)
        echo "ERROR: Unsupported architecture: $HOST_ARCH"
        exit 1
        ;;
esac

GPU_COMPILE_DEPS="cuda-nvml-dev-$NV_CUDA_RELEASE libnvidia-compute-$NV_GPU_RELEASE nvidia-dkms-$NV_GPU_RELEASE"
NVLINK_COMPILE_DEPS="libnvidia-nscq-$NV_SWITCH_RELEASE"

echo "--- Adding CUDA keyring ---"
wget -O cuda-keyring.deb "https://developer.download.nvidia.com/compute/cuda/repos/$NV_DISTRO/$NV_ARCH/cuda-keyring_1.1-1_all.deb"
dpkg -i cuda-keyring.deb
rm cuda-keyring.deb

echo "--- Installing SDK dependencies ---"
apt-get update
apt-get -y install \
    $COMPILE_DEPS \
    $GPU_COMPILE_DEPS \
    $NVLINK_COMPILE_DEPS

echo "--- Installing rustc ---"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > rust-install.sh \
    && chmod +x rust-install.sh \
    && ./rust-install.sh -y \
    || exit 1
export PATH="$HOME/.cargo/bin:$PATH"

echo "--- Installing cbor-diag ---"
# Version pin lives here (single source of truth); nv-attestation-sdk-cpp/Makefile reads
# it from this file. Keep self-contained — the CI image build only COPYs this script in,
# not the SDK tree (see ci/dockerfiles/build-env/Dockerfile).
cargo install cbor-diag-cli --version 0.1.8 --locked

echo "--- Installing Python deps (venv) ---"
apt-get -y install python3-venv
# Delegate venv layout + pinning to scripts/setup-venv.sh (single source of truth).
bash "$(dirname "$0")/../nv-attestation-sdk-cpp/scripts/setup-venv.sh"
