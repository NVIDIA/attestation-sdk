add_executable(custom-logger
  main.c
)

target_link_libraries(custom-logger
    spdlog::spdlog
    xmlsec::xmlsec
    OpenSSL::SSL
    OpenSSL::Crypto
    nvat
    nlohmann_json::nlohmann_json
)