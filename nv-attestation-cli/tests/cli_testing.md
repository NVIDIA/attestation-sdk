<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Testing the nvattest CLI

CLI code is tested in two styles. Pick per the code path you need to reach.

Note: the CLI **test binary does not link libnvat** (the SDK). libnvat statically
bundles spdlog/fmt/regorus/openssl, and the tests fetch their own copies; linking
both risks ODR/symbol clashes. It includes `nvat.h` only for result-code
constants. This shapes both styles below.

## Background: out-of-process vs in-process

**Out-of-process (black-box)** testing runs the built `nvattest` binary as a
separate process and checks only its external behavior (exit code, stdout). It
tests exactly what ships and needs no special build, but it can only *observe* —
it can't reach a code path unless the running process can actually get there.

**In-process (white-box)** testing calls the CLI code directly inside the test
process, so it can construct inputs, fake dependencies, and inspect results. What
that brings here: by faking the SDK, the **success and error-handling paths run
with no real hardware, services, or signed inputs** — deterministically and fast.
That covers the CLI's orchestration and result/exit-code mapping, which the
black-box process can't reach in the unit/coverage job (a real success needs an
environment that job lacks). It does not test the SDK's real behavior — that
stays with the integration tests.

## 1. Out-of-process (subprocess) tests — the default

Run the real `nvattest` binary via `popen(...)`
(`test_utils.h::exec_and_capture_output`) and assert on its exit code and stdout.
This exercises the shipped artifact end-to-end and needs no fakes. Because the
test binary can't call the SDK directly, this is how it reaches SDK-backed code.
A **successful** run needs whatever the SDK really needs (real hardware, a live
service, a valid signed token), so in the unit/coverage job these tests reach
only the argument-handling and error branches.

```cpp
TEST(VerifyTokenArgHandling, MissingTokenFileReturnsExitCode1) {
    std::string bin = get_env_or_default("NVATTEST_BIN", "../nvattest");
    int exit_code = 0;
    std::string out = exec_and_capture_output(
        bin + " --format json verify-token --token-file /no/such/file", exit_code);
    EXPECT_EQ(exit_code, 1) << out;
}
```

## 2. In-process (mock) tests — for success/orchestration paths

Compile the CLI handler into the test binary and fake the SDK responses, so the
success and error branches run deterministically with no environment. These test
the CLI *wiring* — call order, and result/error/exit-code mapping — **not** SDK
behavior, which stays the integration tests' job.

```cpp
TEST_F(VerifyTokenMock, PolicyMismatchReturnsTwo) {
    write_policy("package policy\n");
    g_fake_nvat.policy_apply_rc = NVAT_RC_RP_POLICY_MISMATCH;  // steer one SDK call
    EXPECT_EQ(run(), 2);                                       // assert exit code
}
```

### How it works — the link seam

Since the test binary links no libnvat, the `nvat_*` symbols are undefined. That
is the seam:

1. Compile the CLI source under test into the test binary
   (`../src/<cmd>.cpp`, `utils.cpp`, `logging.cpp`).
2. Provide fake `nvat_*` definitions (`fake_nvat.cpp`); the linker binds the
   CLI's calls to them.
3. Steer them per test via a control block (`fake_nvat_control.h`).

```text
                    nv-attestation-cli-tests  (links NO libnvat)
   +----------------------------------------------------------------------+
   |  (1) SUBPROCESS tests             (2) IN-PROCESS mock tests           |
   |  <cmd>_tests.cpp                   <cmd>_mock_tests.cpp                |
   |      | popen("../nvattest <cmd>")      | handle_<cmd>_subcommand(...)  |
   |      v                                 v  (compiled into this binary) |
   |  real nvattest (links libnvat)     CLI <cmd>.cpp -> nvat_* (unresolved)|
   |      | real SDK                                      v                 |
   |      v                                 fake_nvat.cpp <- g_fake_nvat    |
   |  real behavior (needs env)             (fake nvat_* symbols)  control  |
   +----------------------------------------------------------------------+
      covers arg/error paths              covers success/orchestration paths
```

`llvm-cov` merges coverage per source file across objects, and the coverage merge
(`ci/scripts/merge-cpp-coverage.sh`) passes both the `nvattest` binary and the
test binary as objects, so the two styles combine into one figure per source file.

## Files

| File | Role |
|------|------|
| `fake_nvat.cpp` | Concrete stand-ins for the opaque SDK handle types + fake definitions of the `nvat_*` functions the covered CLI paths call. |
| `fake_nvat_control.h` | `g_fake_nvat` control block (return codes + payloads the fakes hand back) and `fake_nvat_reset()`. |
| `<cmd>_tests.cpp` | Subprocess tests for a subcommand. |
| `<cmd>_mock_tests.cpp` | In-process tests that set `g_fake_nvat` and call `handle_<cmd>_subcommand(...)`. |

## Adding a mock for a new subcommand

Add the extra `nvat_*` functions that command calls to `fake_nvat.cpp` (plus any
control fields to steer them), compile its `../src/<cmd>.cpp` into the test
binary, and add `<cmd>_mock_tests.cpp`. Keep the fakes minimal — enough to drive
the orchestration, never reimplementing SDK behavior.

## Gotcha

`CliLogger` registers a process-global spdlog logger named `"cli"`, so a per-test
instance throws *"logger with name 'cli' already exists"*. Construct it once via a
function-local `static`.
