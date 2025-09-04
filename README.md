# NVIDIA Attestation SDK (NVAT)

[![license](https://img.shields.io/badge/License-Apache%202.0-brightgreen.svg)](./LICENSE)

NVAT (**NV**IDIA **At**ttestation SDK)
is an open-source C++ SDK that provides resources for implementing and
validating Trusted Computing Solutions on NVIDIA hardware.
It focuses on attestation, a crucial aspect of ensuring the integrity and 
security of confidential computing environments.

The core SDK is written in C++ and wrapped with a C API and CLI,
with more bindings to come.

For more information, including documentation, white papers, 
and videos regarding NVIDIA Confidential Computing, please visit [NVIDIA docs](https://docs.nvidia.com/confidential-computing/index.html).

## Project Status

This project is the successor of [nvTrust](https://github.com/NVIDIA/nvtrust),
which is written in Python.
Attestation at NVIDIA is evolving and we aim to provide utilities that are
suitable across a broader range of environments and use-cases.

Note that this project is still in **Alpha**.
Though we will aim to keep breaking changes to a minimum,
breakages may still occur before the SDK is stabilized.

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
and videos regarding the Hopper Confidential Computing story, 
please visit [NVIDIA docs](https://docs.nvidia.com/confidential-computing/index.html).

## License

This repository is licensed under Apache License v2.0 except where otherwise noted.

## Support

For issues or questions, please [raise an issue on GitHub](https://github.com/NVIDIA/attestation-sdk/issues). 
For additional support, contact us at [attestation-support@nvidia.com](mailto:attestation-support@nvidia.com).
