.DEFAULT_GOAL := help

BUILD_DIR := build
TESTS_BUILD_DIR := unit-tests/build
EXAMPLES_BUILD_DIR := examples/build

# dev/install-deps.sh is the single source of truth for CBOR_DIAG_VERSION (it must stay
# self-contained: the CI image build only COPYs that script in, not this Makefile — see
# ci/dockerfiles/build-env/Dockerfile). Derive it here instead of duplicating the pin.
CBOR_DIAG_VERSION := $(shell grep -m1 'cargo install cbor-diag-cli' $(CURDIR)/../dev/install-deps.sh | sed -E 's/.*--version ([0-9.]+).*/\1/')
GTEST_VERSION := v1.16.0

CC  := clang
CXX := clang++
CMAKE_OPTS ?=
UNIT_TEST_FILTER ?= -L unit
ENV_FILE ?= test.env

-include $(ENV_FILE)
export

##@ Helpers

.PHONY: help
help:  ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: check-root
check-root:
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Error: This target requires root privileges. Please run with sudo."; \
		exit 1; \
	fi

.PHONY: check-stg-service-key
check-stg-service-key:
	@if [ -z "$$NVAT_C_SDK_TEST_SERVICE_KEY" ] || [ "$$NVAT_C_SDK_TEST_SERVICE_KEY" = '""' ]; then \
		echo "Error: NVAT_C_SDK_TEST_SERVICE_KEY environment variable is not set or empty"; \
		echo "Please set it (in test.env) before running tests:"; \
		exit 1; \
	fi

.PHONY: check-cbor-diag
# Falls back to $HOME/.cargo/bin because sudo's secure_path strips it from PATH even when
# HOME is preserved; assumes install-deps and this check share the same sudo HOME.
check-cbor-diag:
	@if ! command -v cbor-diag >/dev/null 2>&1 && [ ! -x "$$HOME/.cargo/bin/cbor-diag" ]; then \
		echo "Error: cbor-diag missing. Run 'make install-deps' or 'cargo install cbor-diag-cli --version $(CBOR_DIAG_VERSION) --locked'."; \
		exit 1; \
	fi

##@ Dependencies

.PHONY: install-deps
install-deps: check-root  ## Install system dependencies (requires sudo)
	@echo "Installing system dependencies..."
	apt-get update && \
	apt-get install -y cmake git pkg-config clang \
		libcurl4-openssl-dev libssl-dev libxml2-dev \
		libxmlsec1-dev libxmlsec1-openssl libspdlog-dev \
		python3 python3-venv \
		curl
	@echo "Installing Rust..."
	@if command -v cargo >/dev/null 2>&1; then \
		echo "Rust already installed (cargo found), skipping..."; \
	else \
		curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; \
	fi
	@echo "Installing cbor-diag-cli (provides the cbor-diag binary used by prepare-test-data)..."
	@export PATH="$$HOME/.cargo/bin:$$PATH"; \
	if command -v cbor-diag >/dev/null 2>&1; then \
		echo "cbor-diag already installed, skipping..."; \
	else \
		cargo install cbor-diag-cli --version $(CBOR_DIAG_VERSION) --locked; \
	fi
	@echo "Setting up Python venv at $(CURDIR)/venv (idempotent)..."
	@bash $(CURDIR)/scripts/setup-venv.sh
	@echo "Dependencies installed successfully!"
	@echo "Note: You may need to restart your shell or run 'source $$HOME/.cargo/env' to use Rust"

.PHONY: install-dev-deps
install-dev-deps: install-deps  ## Install system dependencies + gtest (requires sudo)
	@echo "Installing gtest..."
	git clone --depth 1 https://github.com/google/googletest.git -b $(GTEST_VERSION) && \
	cd googletest && \
	mkdir build && \
	cd build && \
	cmake .. && \
	cmake --build . --target install && \
	cd ../.. && \
	rm -rf googletest
	@echo "Development dependencies installed successfully!"

##@ Building

.PHONY: build-sdk
build-sdk:  ## Build the SDK (supports CMAKE_OPTS)
	@echo "Building SDK..."
	@mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake .. -DCMAKE_EXPORT_COMPILE_COMMANDS=ON $(CMAKE_OPTS)
	cd $(BUILD_DIR) && cmake --build .
	@echo "SDK built successfully!"

.PHONY: install-sdk
install-sdk: build-sdk check-root  ## Build and install the SDK to system (requires sudo, supports CMAKE_OPTS)
	@echo "Installing SDK..."
	cd $(BUILD_DIR) && cmake --install . --strip
	ldconfig
	@echo "SDK installed successfully!"

.PHONY: uninstall-sdk
uninstall-sdk: check-root  ## Uninstall the SDK from system (requires sudo)
	@echo "Uninstalling SDK..."
	@if [ ! -f "$(BUILD_DIR)/install_manifest.txt" ]; then \
		echo "Error: install_manifest.txt not found in $(BUILD_DIR)"; \
		echo "Please make sure you have installed the SDK first with 'sudo make install-sdk'"; \
		exit 1; \
	fi
	@echo "Removing installed files..."
	@while read file; do \
		if [ -f "$$file" ] || [ -L "$$file" ]; then \
			echo "Removing $$file"; \
			rm -f "$$file"; \
		fi; \
	done < $(BUILD_DIR)/install_manifest.txt
	@echo "Removing empty directories..."
	@while read file; do \
		dir=$$(dirname "$$file"); \
		if [ -d "$$dir" ] && [ -z "$$(ls -A "$$dir")" ]; then \
			echo "Removing empty directory $$dir"; \
			rmdir "$$dir" 2>/dev/null || true; \
		fi; \
	done < $(BUILD_DIR)/install_manifest.txt
	ldconfig
	@echo "SDK uninstalled successfully!"

##@ Testing

.PHONY: prepare-test-data
prepare-test-data: check-cbor-diag  ## Generate test certs, materialize unsigned CoRIM/CoMID .cbor from .diag, build signed CoRIM fixtures (idempotent)
	@bash $(CURDIR)/scripts/prepare-test-data.sh $(CURDIR)/unit-tests/testdata

.PHONY: run-unit-tests
run-unit-tests: check-stg-service-key check-cbor-diag  ## Build SDK and run unit tests (requires NVAT_C_SDK_TEST_SERVICE_KEY env var, supports CTEST_OPTS and CMAKE_OPTS)
	@echo "Building SDK with unit tests enabled..."
	@mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake .. -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DBUILD_TESTING=ON $(CMAKE_OPTS)
	cd $(BUILD_DIR) && cmake --build .
	@echo "Running unit tests..."
	cd $(BUILD_DIR) && ctest $(UNIT_TEST_FILTER) --output-on-failure $(CTEST_OPTS)

.PHONY: corim-verify-docs
corim-verify-docs:  ## Regenerate CoRIM verify test documentation (markdown) into $(BUILD_DIR)/corim-verify-docs.md. Skips writing if any test fails.
	@echo "Building unit-test binary..."
	@mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake .. -DBUILD_TESTING=ON $(CMAKE_OPTS) >/dev/null
	cd $(BUILD_DIR) && cmake --build . --target nv-attestation-unit-tests
	@echo "Running verify-suite tests..."
	@cd $(BUILD_DIR) && ./unit-tests/nv-attestation-unit-tests --gtest_filter='CorimVerify.Verify*' --gtest_brief=1 > .corim-verify-docs.raw 2>&1 \
	  || { echo "Verify-suite tests FAILED; doc NOT regenerated."; cat .corim-verify-docs.raw; rm -f .corim-verify-docs.raw; exit 1; }
	@{ \
	  printf '# CoRIM Verify — Test Documentation\n\n'; \
	  printf '_Auto-generated by `make corim-verify-docs`. Re-run to regenerate after code changes._\n'; \
	  grep -v -E '^(\[(==|--| RUN|       OK|  PASSED|  FAILED|  SKIPPED)|Note: |sh: 1:|Warning: |python3:|TEST_MODE:)' $(BUILD_DIR)/.corim-verify-docs.raw; \
	} > $(BUILD_DIR)/corim-verify-docs.md
	@rm -f $(BUILD_DIR)/.corim-verify-docs.raw
	@echo "Wrote $(BUILD_DIR)/corim-verify-docs.md"

.PHONY: run-integration-tests-build-tree
run-integration-tests-build-tree: check-stg-service-key check-cbor-diag  ## Build SDK and run integration tests (uses TEST_DEVICE from test.env, supports CTEST_OPTS)
	@echo "Building SDK with tests enabled..."
	@mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake .. -DBUILD_TESTING=ON $(CMAKE_OPTS)
	cd $(BUILD_DIR) && cmake --build .
	@echo "Running $(TEST_DEVICE) integration tests..."
	rm -rf $(BUILD_DIR)/test-results
	cd $(BUILD_DIR) && TEST_MODE=integration TEST_DEVICES=$(TEST_DEVICE) \
		ctest -L unit --output-on-failure $(CTEST_OPTS)
	@python3 ../common_scripts/display_junit_test_results.py $(BUILD_DIR)/test-results

.PHONY: run-integration-tests-install-tree
run-integration-tests-install-tree: check-stg-service-key check-cbor-diag  ## Run integration tests against installed SDK (uses TEST_DEVICE from test.env, supports CTEST_OPTS)
	@echo "Building SDK tests against installed SDK..."
	@mkdir -p $(TESTS_BUILD_DIR)
	cd $(TESTS_BUILD_DIR) && cmake .. $(CMAKE_OPTS)
	cd $(TESTS_BUILD_DIR) && cmake --build .
	@echo "Running $(TEST_DEVICE) integration tests..."
	rm -rf $(TESTS_BUILD_DIR)/test-results
	cd $(TESTS_BUILD_DIR) && TEST_MODE=integration TEST_DEVICES=$(TEST_DEVICE) \
		ctest -L unit --output-on-failure $(CTEST_OPTS)
	@python3 ../common_scripts/display_junit_test_results.py $(TESTS_BUILD_DIR)/test-results

.PHONY: build-fuzz-tests
build-fuzz-tests:  ## Build fuzz test executables with ASan (supports CMAKE_OPTS)
	@echo "Building SDK with fuzz tests enabled..."
	@mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake .. -DBUILD_FUZZ_TESTS=ON -DSANITIZER=address $(CMAKE_OPTS)
	cd $(BUILD_DIR) && cmake --build .
	@echo "Fuzz tests built successfully!"

FUZZ_TARGET ?=
FUZZ_TIME ?= 30

.PHONY: generate-fuzz-corpus
generate-fuzz-corpus: prepare-test-data  ## Populate $(BUILD_DIR)/fuzz-tests/corpus from fuzz-tests/generate_corpus.py
	@$(CURDIR)/venv/bin/python3 $(CURDIR)/fuzz-tests/generate_corpus.py $(BUILD_DIR)/fuzz-tests/corpus

.PHONY: run-fuzz-tests
run-fuzz-tests: build-fuzz-tests generate-fuzz-corpus  ## Fuzz all targets for FUZZ_TIME seconds each (default 30; FUZZ_TARGET=name to run one; logs in $(BUILD_DIR)/fuzz-tests/logs/)
	@if [ -n "$(FUZZ_TARGET)" ]; then \
		targets="$(BUILD_DIR)/fuzz-tests/$(FUZZ_TARGET)"; \
		[ -x "$$targets" ] || { echo "Error: $(FUZZ_TARGET) not found at $$targets"; exit 1; }; \
	else \
		targets="$$(ls $(BUILD_DIR)/fuzz-tests/fuzz_*)"; \
	fi; \
	echo "Running fuzz targets ($(FUZZ_TIME)s each)..."; \
	mkdir -p $(BUILD_DIR)/fuzz-tests/logs; \
	overall=0; \
	for target in $$targets; do \
		name=$$(basename $$target); \
		corpus_name=$$(echo $$name | sed 's/^fuzz_//'); \
		corpus_dir=$(BUILD_DIR)/fuzz-tests/corpus/$$corpus_name; \
		crash_dir=$(BUILD_DIR)/fuzz-tests/crashes/$$name; \
		if [ ! -d "$$corpus_dir" ]; then \
			echo "Error: corpus directory not found: $$corpus_dir"; \
			echo "  (expected populated by fuzz-tests/generate_corpus.py — see generate-fuzz-corpus target)"; \
			exit 1; \
		fi; \
		mkdir -p "$$crash_dir"; \
		dict=$(CURDIR)/fuzz-tests/dict/$$name.dict; \
		dict_opt=$$([ -s "$$dict" ] && echo "-dict=$$dict" || echo ""); \
		log=$(BUILD_DIR)/fuzz-tests/logs/$$name.log; \
		echo "--- $$name ---"; \
		if $$target "$$corpus_dir" $$dict_opt -artifact_prefix=$$crash_dir/ -max_total_time=$(FUZZ_TIME) >"$$log" 2>&1; then \
			result=PASS; \
		else \
			result=FAIL; \
			overall=1; \
		fi; \
		(grep -E '^Done [0-9]+ runs|^SUMMARY: |^==[0-9]+==ERROR:|INITED cov:' "$$log" || true) | sed 's/^/  /'; \
		peak_cov=$$(grep -oE 'cov: [0-9]+ ft: [0-9]+ corp: [0-9]+/[0-9]+[bKM]+' "$$log" | tail -n 1); \
		[ -n "$$peak_cov" ] && echo "  final $$peak_cov" || true; \
		dict_entries=$$(grep -oE 'DE: [^ ]+' "$$log" | grep -oE '"[^"]+"' | sort -u); \
		if [ -n "$$dict_entries" ]; then \
			printf '  Dict candidates:\n'; \
			printf '%s\n' "$$dict_entries" | sed 's/^/    /'; \
		fi; \
		echo "  [$$result] log: $$log"; \
	done; \
	exit $$overall

##@ Code Quality

.PHONY: lint
lint:  ## Run clang-tidy on changed files (requires SDK to be built first)
	@echo "Running clang-tidy on changed files..."
	./scripts/lint.sh

.PHONY: lint-all
lint-all:  ## Run clang-tidy on all files (requires SDK to be built first)
	@echo "Running clang-tidy on all files..."
	./scripts/lint.sh --all

##@ Examples

.PHONY: build-examples
build-examples:  ## Build examples against installed SDK
	@echo "Building examples from install tree..."
	@mkdir -p $(EXAMPLES_BUILD_DIR)
	cd $(EXAMPLES_BUILD_DIR) && cmake ..
	cd $(EXAMPLES_BUILD_DIR) && cmake --build .
	@echo "Examples built successfully!"

.PHONY: run-examples
run-examples: build-examples  ## Build and run examples built against installed SDK
	@echo "Running examples from install tree..."
	./scripts/run-examples.sh $(EXAMPLES_BUILD_DIR)/bin

##@ Cleanup

.PHONY: clean
clean:  ## Remove build artifacts
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR) $(TESTS_BUILD_DIR) $(EXAMPLES_BUILD_DIR) googletest
	@echo "Clean complete!"
