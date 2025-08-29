#pragma once

#include <gtest/gtest.h>
#include <cstdlib>
#include <iostream>
#include <vector>
#include "nv_attestation/init.h"
#include "nv_attestation/error.h"
#include "nv_attestation/utils.h"
#include "test_utils.h"

using namespace nvattestation;

class Environment : public ::testing::Environment {
 public:
  std::string test_mode; // "unit" or "integration"
  bool test_device_gpu=false;
  bool test_device_switch=false;
  std::string common_test_data_dir;

  ~Environment() override {
  }

  // Override this to define how to set up the environment.
  void SetUp() override {
    // Always run the certificate generation script (it will check if certs already exist)
    const std::string cert_dir = "testdata/x509_cert_chain/";
    std::string command = "cd " + cert_dir + " && ./generate_test_certs.sh";
    
    int result = std::system(command.c_str());
    if (result != 0) {
      std::cerr << "Warning: Certificate generation script failed. Exit code: " << result << std::endl;
    }

    std::shared_ptr<SdkOptions> options = std::make_shared<SdkOptions>();
    options -> logger = std::make_shared<SpdLogLogger>(LogLevel::TRACE);

    // read env variables used to configure the tests
    test_mode = get_env_or_default("TEST_MODE", "unit");
    std::string test_devices_env = get_env_or_default("TEST_DEVICES", "");
    std::stringstream ss(test_devices_env);
    std::string device;
    std::cout << "TEST_MODE: " << test_mode << std::endl;
    if (test_mode != "integration" && test_mode != "unit") {
      std::cerr << "Invalid test mode: " << test_mode << std::endl;
      exit(1);
    }

    while (std::getline(ss, device, ',')) {
      std::cout << "TEST_DEVICE: " << device << std::endl;
      if (test_mode == "integration" && (device != "gpu" && device != "nvswitch")) {
        std::cerr << "Invalid test device: " << device << std::endl;
        exit(1);
      }
      if (device == "gpu") {
        test_device_gpu = true;
        std::cout << "Initializing NVML" << std::endl;
      }
      if (device == "nvswitch") {
        test_device_switch = true;
        std::cout << "Initializing NSCQ" << std::endl;
      }
    }

    ASSERT_EQ(init(options), Error::Ok);

    std::string git_repo_root;
    ASSERT_EQ(get_git_repo_root(git_repo_root), Error::Ok);
    common_test_data_dir = git_repo_root + "/common-test-data";
  }

  // Override this to define how to tear down the environment.
  void TearDown() override {
    shutdown();
  }
};

extern Environment* g_env;