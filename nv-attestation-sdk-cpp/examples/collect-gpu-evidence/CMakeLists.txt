add_executable(collect-gpu-evidence
  main.c
)

target_link_libraries(collect-gpu-evidence
    nvat
)