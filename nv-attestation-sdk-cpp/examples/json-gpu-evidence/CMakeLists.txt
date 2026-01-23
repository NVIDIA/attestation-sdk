add_executable(json-gpu-evidence
  main.c
)

target_link_libraries(json-gpu-evidence
    nvat
)