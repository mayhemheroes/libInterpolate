add_executable(fuzz_interpolate fuzz_interpolate.cpp)

target_compile_options(fuzz_interpolate PRIVATE -fsanitize=fuzzer,undefined)
target_link_options(fuzz_interpolate PRIVATE -fsanitize=fuzzer,undefined)

target_link_libraries(fuzz_interpolate Interpolate)
