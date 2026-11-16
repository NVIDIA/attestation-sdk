# SDK tests on GitHub

The SDK workflow runs the same tests in four independent builds: normal, ASan,
TSan, and UBSan. The normal build uses Release; sanitizer builds use Debug and
the SDK's existing `SANITIZER` option. A failed matrix job does not cancel the
other jobs. Each job uploads its JUnit report and CTest log when available.

`.github/sdk-tests.txt` lists exact CTest names. Its 180 existing tests cover
utilities, encoding, hashes, logging, cache operations and concurrency, CMW
parsing and serialization, CoRIM matching, and the selected C++ and C API CMW
verification paths. Local malformed-input checks are included. Two legacy GPU
verification tests also contact production services in every build variant.
These tests require no service key or GPU; the workflow does not load `test.env`.
It sets `NVAT_TEST_REQUIRE_SERVICE_KEY=0`; the test runner still requires a key
by default outside this workflow.

The Blackwell CMW checks exercise evidence parsing and signature verification.
The Rubin checks use local RIM fixtures with RIM signature and revocation checks
disabled; they cover measurement matching and appraisal output.

To add an existing test, check its helpers and fixtures for service or hardware
dependencies, confirm it exists in the public checkout, then add its exact name
to the manifest. Every matrix job validates the manifest against CTest discovery;
unknown or duplicate names fail the job. Avoid adding tests that depend on
staging services or send malformed requests to production services.

The workflow pins Clang 18 and CMake/CTest 3.31.10. The manifest option
`--tests-from-file` requires CTest 3.29 or newer. SDK source dependencies retain
their CMake pins, including zcbor commit
`bd28ef9fc2abe154cb420c232910a1a9f8258114`. Fixture tooling uses the same zcbor
commit through `requirements-dev.txt`; `cbor-diag-cli` is pinned to 0.1.8.
OpenSSL, curl, libxml2, xmlsec, and zlib use Ubuntu packages. Rust follows the
stable toolchain.

ASan and TSan jobs reduce address-space randomization on their ephemeral runner
to avoid conflicts with sanitizer shadow memory. Fuzz testing is separate from
this workflow.
