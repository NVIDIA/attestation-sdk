add_executable(attest
  main.c
)

target_link_libraries(attest
    spdlog::spdlog
    xmlsec::xmlsec
    OpenSSL::SSL
    OpenSSL::Crypto
    nvat
    nlohmann_json::nlohmann_json
)