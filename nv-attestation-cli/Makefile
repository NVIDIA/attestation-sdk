.DEFAULT_GOAL := help

BUILD_DIR := build
TESTS_BUILD_DIR := tests/build

CC  := clang
CXX := clang++
CMAKE_OPTS ?=
UNIT_TEST_FILTER ?= -L cli
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

##@ Building

.PHONY: build-cli
build-cli:  ## Build the CLI (supports CMAKE_OPTS)
	@echo "Building CLI..."
	@mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake .. -DCMAKE_EXPORT_COMPILE_COMMANDS=ON $(CMAKE_OPTS)
	cd $(BUILD_DIR) && cmake --build .
	@echo "CLI built successfully!"

.PHONY: install-cli
install-cli: build-cli check-root  ## Build and install the CLI to system (requires sudo, supports CMAKE_OPTS)
	@echo "Installing CLI..."
	cd $(BUILD_DIR) && cmake --install . --strip
	@echo "CLI installed successfully!"

.PHONY: uninstall-cli
uninstall-cli: check-root  ## Uninstall the CLI from system (requires sudo)
	@echo "Uninstalling CLI..."
	@if [ ! -f "$(BUILD_DIR)/install_manifest.txt" ]; then \
		echo "Error: install_manifest.txt not found in $(BUILD_DIR)"; \
		echo "Please make sure you have installed the CLI first with 'sudo make install-cli'"; \
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
	@echo "CLI uninstalled successfully!"

##@ Testing

.PHONY: list-cli-test-labels
list-cli-test-labels:  ## List available CLI test labels (NVAT_CLI_TEST_LABEL values)
	@echo "Available CLI test labels (set NVAT_CLI_TEST_LABEL in test.env):"
	@grep -rhE 'test_label\s*(!=|==)\s*"[^"]*"' tests/ 2>/dev/null \
		| sed -E 's/.*test_label\s*(!=|==)\s*"([^"]*)".*/\2/' \
		| sort -u \
		| while read label; do echo "  $$label"; done

.PHONY: run-unit-tests
run-unit-tests: check-stg-service-key  ## Build CLI and run unit tests (requires NVAT_C_SDK_TEST_SERVICE_KEY env var, supports CTEST_OPTS and CMAKE_OPTS)
	@echo "Building CLI with unit tests enabled..."
	@mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake .. -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DBUILD_TESTING=ON $(CMAKE_OPTS)
	cd $(BUILD_DIR) && cmake --build .
	@echo "Running unit tests..."
	cd $(BUILD_DIR) && ctest $(UNIT_TEST_FILTER) --output-on-failure $(CTEST_OPTS)

.PHONY: run-integration-tests-build-tree
run-integration-tests-build-tree: check-stg-service-key  ## Build CLI and run integration tests (uses TEST_DEVICE from test.env, supports CTEST_OPTS)
	@echo "Building CLI with tests enabled..."
	@mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake .. -DBUILD_TESTING=ON $(CMAKE_OPTS)
	cd $(BUILD_DIR) && cmake --build .
	@echo "Running $(TEST_DEVICE) integration tests..."
	rm -rf $(BUILD_DIR)/test-results
	cd $(BUILD_DIR) && TEST_MODE=integration TEST_DEVICES=$(TEST_DEVICE) \
		NVATTEST_BIN=../nvattest \
		ctest -L cli --output-on-failure $(CTEST_OPTS)
	@python3 ../common_scripts/display_junit_test_results.py $(BUILD_DIR)/test-results

.PHONY: run-integration-tests-install-tree
run-integration-tests-install-tree: check-stg-service-key  ## Run integration tests against installed SDK (uses TEST_DEVICE from test.env, supports CTEST_OPTS)
	@echo "Building CLI tests against installed SDK..."
	@mkdir -p $(TESTS_BUILD_DIR)
	cd $(TESTS_BUILD_DIR) && cmake .. $(CMAKE_OPTS)
	cd $(TESTS_BUILD_DIR) && cmake --build .
	@echo "Running $(TEST_DEVICE) integration tests..."
	rm -rf $(TESTS_BUILD_DIR)/test-results
	cd $(TESTS_BUILD_DIR) && TEST_MODE=integration TEST_DEVICES=$(TEST_DEVICE) \
		NVATTEST_BIN=nvattest \
		ctest -L cli --output-on-failure $(CTEST_OPTS)
	@python3 ../common_scripts/display_junit_test_results.py $(TESTS_BUILD_DIR)/test-results

##@ Cleanup

.PHONY: clean
clean:  ## Remove build artifacts
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR) $(TESTS_BUILD_DIR)
	@echo "Clean complete!"
