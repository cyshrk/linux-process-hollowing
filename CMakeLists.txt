project("Linux Process Hollowing" C)
cmake_minimum_required(VERSION 3.17)

add_compile_options(-nostdlib -fno-plt -fdata-sections -ffunction-sections -fcf-protection=none)
add_link_options(-nostdlib -T${CMAKE_SOURCE_DIR}/src/ldscript.txt -static -Wl,--gc-sections -Wl,-Map=mapfile)

add_executable(hello_shellcode src/hello_shellcode.c)
