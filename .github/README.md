# SDK tests on GitHub

The workflow runs existing SDK tests in normal, ASan, TSan, and UBSan builds.
Each job uploads its test results and CTest log when available.

To add a test, add its exact CTest name to `.github/sdk-tests.txt`. Check that
the test and its helpers and fixtures require no credentials, GPU hardware, or
staging services, and do not send malformed requests to production services.
The workflow rejects unknown or duplicate test names.
