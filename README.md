# NVIDIA Attestation SDK (NVAT)

[![license](https://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)](./LICENSE)
[![docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/overview.html)
[![downloads](https://img.shields.io/badge/downloads-latest-brightgreen.svg)](https://developer.nvidia.com/nvat-downloads)
[![Issues](https://img.shields.io/github/issues/NVIDIA/attestation-sdk.svg)](https://github.com/NVIDIA/attestation-sdk/issues)
[![Pull Requests](https://img.shields.io/github/issues-pr/NVIDIA/attestation-sdk.svg)](https://github.com/NVIDIA/attestation-sdk/pulls)
[![Stars](https://img.shields.io/github/stars/NVIDIA/attestation-sdk?style=social)](https://github.com/NVIDIA/attestation-sdk/stargazers)
[![Forks](https://img.shields.io/github/forks/NVIDIA/attestation-sdk?style=social)](https://github.com/NVIDIA/attestation-sdk/network/members)

NVAT (**NV**IDIA **At**ttestation SDK)
is an open-source C++ SDK that provides resources for implementing and
validating Trusted Computing Solutions on NVIDIA hardware.
It focuses on attestation, a crucial aspect of ensuring the integrity and 
security of confidential computing environments.

The core SDK is written in C++ and wrapped with a C API and CLI,
with more bindings to come.

## Project Status

This project is the successor of the Python-based guest tools in [nvTrust](https://github.com/NVIDIA/nvtrust).
NVAT provides utilities suitable for a broader range of environments and use-cases.

## Components

NVAT provides two components for different use cases:

- **CLI (`nvattest`)**: For quick testing, scripts, and getting started. [Documentation](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-cli/introduction.html)
- **C API**: For integrating attestation into C/C++ applications. [Documentation](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-c/introduction.html)

## Quick Start Guide

### Prerequisites

**For Confidential Computing (CC) attestation:**
- A supported NVIDIA GPU connected to a CVM running Ubuntu 22.04 or 24.04. See [NVIDIA Trusted Computing Solutions](https://docs.nvidia.com/nvtrust/) for deployment guides covering Intel TDX and AMD SNP.

**For general GPU attestation (non-CC):**
- A supported NVIDIA GPU
- Supported architectures: x86-64, aarch64
- Supported operating systems: Ubuntu 22.04, Ubuntu 24.04, and others (see [downloads](https://developer.nvidia.com/nvat-downloads) for full list)

### Installation

1. Install the NVIDIA Management Library (NVML). See [Driver Installation](https://docs.nvidia.com/datacenter/tesla/driver-installation-guide/index.html#ubuntu-installation-common).

2. Install `nvattest`. Navigate to [NVIDIA Attestation SDK Downloads](https://developer.nvidia.com/nvat-downloads) and select your architecture and operating system.

For a source install, refer to the [CLI Introduction](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/overview.html).

**Note:** For Confidential Computing attestation, these steps must be performed in a CVM connected to an NVIDIA GPU. See [Prerequisites](#prerequisites) above.

### Attestation

Attest the GPU(s) attached to your CVM with the following command:

```shell
nvattest attest --device gpu --verifier local
```

Use `--help` to view all the options associated with the attest subcommand:

```shell
nvattest attest --help
```

### Using the C API

To get started with the C API, refer to the documentation in the
[SDK introduction](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-c/introduction.html).

## Documentation

- [CLI introduction](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-cli/introduction.html)
- [SDK introduction](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-c/introduction.html)
- [NVIDIA Confidential Computing](https://docs.nvidia.com/confidential-computing/index.html)
- [NVIDIA Attestation Suite](https://docs.nvidia.com/attestation)

## License

This repository is licensed under Apache License v2.0 except where otherwise noted.

This project will download and install additional third-party open source software projects. 
Review the license terms of these open source projects before use.

## Support

For issues or questions, please [raise an issue on GitHub](https://github.com/NVIDIA/attestation-sdk/issues). 
For additional support, contact us at [attestation-support@nvidia.com](mailto:attestation-support@nvidia.com).
