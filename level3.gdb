define log
    echo +++ $arg0\n
end

set $shellcode_file = "shellcode.bin"

file /usr/bin/sleep

log "Set breakpoint on nanosleep"
break nanosleep

log "Run sleep"
run 10

log "Allocate heap for shellcode"
set $shellcode_heap = mmap(0, 0x2000, 3, 0x22, -1, 0)

log "Resolve address for shellcode"
python
import struct

pid = gdb.selected_inferior().pid

for map in open(f"/proc/{pid}/maps", "r").read().splitlines():
    parts = [x for x in map.split(" ") if x]

    # Skip anonymous sections
    if len(parts) == 5:
        continue

    range, perms, _, _, _, file = parts
    if "libc" in file:
        if "x" in perms:
            start, end = range.split("-")
            libc_exec_end = int(f"0x{end}", 16)

with open(gdb.convenience_variable("shellcode_file").string(), "rb") as file:
    file.seek(0, 2)
    shellcode_size = file.tell()


# Put the shellcode at the end of executable libc segment
gdb.set_convenience_variable("shellcode_addr", libc_exec_end - shellcode_size)
end

log "Load shellcode using GDB into libc executable segment"
restore shellcode.bin binary $shellcode_addr

log "Call shellcode"
call ((void (*) ()) $shellcode_addr ) ()

log "Quit program"
detach
