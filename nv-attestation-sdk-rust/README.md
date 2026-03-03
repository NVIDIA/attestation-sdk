# NVIDIA Attestation SDK - Rust Bindings

Rust bindings for the NVIDIA Attestation SDK C library.

## Overview

This workspace provides idiomatic Rust bindings to the NVIDIA Attestation SDK, which enables attestation of NVIDIA GPUs and NVSwitches. The bindings provide type-safe wrappers, automatic memory management, and Result-based error handling.

**[Full Documentation](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-rust/introduction.html)**

## Workspace Structure

This is a Cargo workspace containing two crates:

- **`nv-attestation-sdk-sys`** - Raw FFI bindings to the C library
- **`nv-attestation-sdk`** - Safe, idiomatic Rust wrapper

For optional features like logging integration, see the [User Guide](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-rust/user_guide.html).

## Quick Start

**Prerequisites:**
- Rust 1.80 or later
- NVIDIA Attestation SDK C library (`libnvat.so.1`)
- Clang/LLVM (for bindgen)

**Using system-installed library:**
```bash
export NVAT_USE_SYSTEM_LIB=1
cargo build
cargo run --example basic_remote_attestation
```

For detailed installation instructions, local development setup, and bindings generation, see the [Introduction](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-rust/introduction.html).

## Building from Source

For SDK developers:

1. **Build the C++ SDK:**
```bash
cd ../nv-attestation-sdk-cpp
make build-sdk
```

2. **Build the Rust workspace:**
```bash
cd ../nv-attestation-sdk-rust
cargo build --workspace
```

3. **Run examples:**
```bash
export LD_LIBRARY_PATH=$(pwd)/../nv-attestation-sdk-cpp/build:$LD_LIBRARY_PATH
cargo run --example basic_remote_attestation
```

For more details, see the [Development Guide](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-rust/development.html).

## Usage & Examples

See the [User Guide](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-rust/user_guide.html) for comprehensive usage examples, API documentation, and detailed guides.

## Documentation

- [Introduction & Installation](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-rust/introduction.html)
- [User Guide](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-rust/user_guide.html)
- [Configuration](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-rust/configuration.html)
- [Development Guide](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-rust/development.html)
- [Claims Schema](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-c/claims_schema.html)

## Support

- GitHub Issues: https://github.com/NVIDIA/attestation-sdk/issues
- Email: attestation-support@nvidia.com

## License

This project follows the same license as the NVIDIA Attestation SDK.
