add_executable(attest
  main.c
)

target_link_libraries(attest
    nvat
)