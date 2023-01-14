#!/bin/bash

# Put the shellcode at the padding of an executable segment

set -x

# Dump shellcode
objcopy --dump-section .shellcode=shellcode.bin shellcode.elf

# Execute GDB commands
gdb -batch -x level3.gdb
