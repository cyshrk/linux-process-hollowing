#!/bin/bash

# Override some libc code with the shellcode

set -x

# Dump shellcode
objcopy --dump-section .shellcode=shellcode.bin shellcode.elf

# Execute GDB commands
gdb -batch -x level2.gdb
