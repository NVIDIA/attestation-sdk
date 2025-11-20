add_executable(parallel-verification
  main.c
)

target_link_libraries(parallel-verification
    nvat
)