# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

ARG BASE_IMAGE=ubuntu
ARG BASE_VERSION=22.04

FROM ${BASE_IMAGE}:${BASE_VERSION}

ENV NV_CUDA_RELEASE=12-9
ENV NV_GPU_RELEASE=575
ENV NV_SWITCH_RELEASE=575

# TARGETARCH is automatically set by Docker Buildx from --platform (e.g. linux/amd64 → amd64, linux/arm64 → arm64).
# Map it to the NVIDIA package repository architecture name used by install-deps.sh.
ARG TARGETARCH=amd64
RUN case "$TARGETARCH" in \
        amd64) echo "NV_ARCH=x86_64" >> /etc/environment ;; \
        arm64) echo "NV_ARCH=sbsa"   >> /etc/environment ;; \
        *) echo "Error: Unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac

COPY dev/install-deps.sh .
RUN  ./install-deps.sh && rm install-deps.sh

RUN apt-get install -y vim strace

RUN apt-get install -y doxygen && \
    git clone --depth 1 https://github.com/jothepro/doxygen-awesome-css.git -b v2.3.4 && \
    cd doxygen-awesome-css \
    && make install \
    && rm -rf doxygen-awesome-css

CMD ["/bin/bash"]
