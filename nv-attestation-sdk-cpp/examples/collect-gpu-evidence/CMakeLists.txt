add_executable(collect-gpu-evidence
  main.c
)

target_link_libraries(collect-gpu-evidence
    spdlog::spdlog
    xmlsec::xmlsec
    OpenSSL::SSL
    OpenSSL::Crypto
    nvat
    nlohmann_json::nlohmann_json
)