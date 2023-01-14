define log
    echo +++ $arg0\n
end

file /usr/bin/sleep

log "Set breakpoint on nanosleep"
break nanosleep

log "Run sleep"
run 10

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
            libc_exec_start = int(f"0x{start}", 16)

# Put the shellcode at the beginning of executable libc segment
gdb.set_convenience_variable("shellcode_addr", libc_exec_start)
end

log "Load shellcode using GDB into libc executable segment"
restore shellcode.bin binary $shellcode_addr

log "Call shellcode"
call ((void (*) ()) $shellcode_addr ) ()

log "Detach program"
detach
