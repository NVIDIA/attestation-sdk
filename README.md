# NVIDIA Attestation SDK (NVAT)

[![license](https://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)](./LICENSE)
![version](https://img.shields.io/badge/version-alpha-orange)

NVAT (**NV**IDIA **At**ttestation SDK)
is an open-source C++ SDK that provides resources for implementing and
validating Trusted Computing Solutions on NVIDIA hardware.
It focuses on attestation, a crucial aspect of ensuring the integrity and 
security of confidential computing environments.

The core SDK is written in C++ and wrapped with a C API and CLI,
with more bindings to come.

## Documentation

- [CLI introduction](https://docs.nvidia.com/attestation/nv-attestation-cli/latest/introduction.html)
- [SDK introduction](https://docs.nvidia.com/attestation/nv-attestation-sdk-c/latest/introduction.html)
- [NVIDIA Confidential Computing](https://docs.nvidia.com/confidential-computing/index.html)
- [NVIDIA Attestation Suite](https://docs.nvidia.com/attestation/overview-attestation-suite/latest/introduction.html)

## Project Status

This project is the successor of the guest tools in [nvTrust](https://github.com/NVIDIA/nvtrust),
which are written in Python.
Attestation at NVIDIA is evolving and we aim to provide utilities that are
suitable across a broader range of environments and use-cases.

Note that this project is in **Alpha**.
Though we will aim to keep breaking ABI and CLI changes to a minimum,
breakages may still occur before the SDK is stabilized.

## Quick Start Guide

The Attestation SDK is in **Alpha** and requires an installation from source.
This guide will walk through the process of installing the `nvattest` CLI 
and the `nvat` shared library on a confidential virtual machine and attesting the connected GPUs.

### Prerequisites

- A supported NVIDIA GPU connected to a CVM. See [NVIDIA Trusted Computing Solutions](https://docs.nvidia.com/nvtrust/) for deployment guides covering Intel TDX and AMD SNP.
- The above CVM must be running Ubuntu 22.04 or 24.04.

### Installation

The steps below must be performed in a CVM connected to an NVIDIA GPU.
See [Prerequisites](#prerequisites) above.

1. Install the NVIDIA Management Library (NVML). See [Driver Installation](https://docs.nvidia.com/datacenter/tesla/driver-installation-guide/index.html#ubuntu-installation-common).

2. Install the Rust compiler. See [rustup](https://www.rust-lang.org/tools/install)

3. Install additional build dependencies:
```shell
apt update && \
apt install cmake git pkg-config clang \
    libcurl4-openssl-dev libssl-dev libxml2-dev \
    libxmlsec1-dev libxmlsec1-openssl libspdlog-dev
```

4. Install the CLI:
```shell
git clone https://github.com/NVIDIA/attestation-sdk.git
cd attestation-sdk/nv-attestation-cli
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_NVML=ON
cmake --build build
cmake --install build
sudo ldconfig
```

### Attestation

Attest the GPU(s) attached to your CVM with the following command:

```shell
nvattest attest --device gpu --verifier local
```

Use `--help` to view all the options associated with the attest subcommand:

```shell
nvattest attest --help
```

### More

To get started with the C API, refer to the documentation in the
[SDK introduction](https://docs.nvidia.com/attestation/nv-attestation-sdk-c/latest/introduction.html).

## Confidential Computing

NVIDIA Confidential Computing offers a solution for securely processing data and code in use,
preventing unauthorized users from both access and modification.
When running AI training or inference, the data and the code must be protected. 
Often the input data includes personally identifiable information (PII) or enterprise secrets, 
and the trained model is highly valuable intellectual property (IP). 
Confidential computing is the ideal solution to protect both AI models and data.

NVIDIA is at the forefront of confidential computing, collaborating with CPU partners, 
cloud providers, and independent software vendors (ISVs) to ensure that the change from traditional, 
accelerated workloads to confidential, accelerated workloads will be smooth and transparent.

For more information, including documentation, white papers, 
and videos regarding the Confidential Computing story, 
please visit [NVIDIA Confidential Computing docs](https://docs.nvidia.com/confidential-computing/index.html).

## License

This repository is licensed under Apache License v2.0 except where otherwise noted.

This project will download and install additional third-party open source software projects. 
Review the license terms of these open source projects before use.

## Support

For issues or questions, please [raise an issue on GitHub](https://github.com/NVIDIA/attestation-sdk/issues). 
For additional support, contact us at [attestation-support@nvidia.com](mailto:attestation-support@nvidia.com).
