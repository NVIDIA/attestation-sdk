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

## Project Status

This project is the successor of the Python-based guest tools in [nvTrust](https://github.com/NVIDIA/nvtrust), providing utilities suitable for a broader range of environments and use-cases.

**Note:** This project is in **Alpha**. While we strive to minimize breaking changes, the ABI and CLI may change before stabilization.

## Components

NVAT provides two components for different use cases:

- **CLI (`nvattest`)**: For quick testing, scripts, and getting started. [Documentation](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-cli/introduction.html)
- **C API**: For integrating attestation into C/C++ applications. [Documentation](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-c/introduction.html)

## Quick Start Guide

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
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
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
