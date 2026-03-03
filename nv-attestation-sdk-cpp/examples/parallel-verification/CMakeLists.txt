add_executable(parallel-verification
  main.c
)

find_package(Threads REQUIRED)
target_link_libraries(parallel-verification
    nvat
    Threads::Threads
)
