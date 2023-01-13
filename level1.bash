#!/bin/bash

# Put shellcode into a anonymous RWX memory page

set -x

# Dump shellcode
objcopy --dump-section .shellcode=shellcode.bin shellcode.elf

# Execute GDB commands
gdb -batch -x level1.gdb
