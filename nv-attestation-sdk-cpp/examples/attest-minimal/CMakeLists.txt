add_executable(attest-minimal
  main.c
)

target_link_libraries(attest-minimal
    nvat
)