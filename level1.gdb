define log
    echo +++ $arg0\n
end

file /usr/bin/sleep

log "Set breakpoint on nanosleep"
break nanosleep

log "Run sleep"
run 10

log "Memory map anonymous page for shellcode"
call (void *)mmap(-1, 0x1000, 4 | 1, 0x22, -1, 0)

log "Load shellcode using GDB into anonymous page"
restore shellcode.bin binary $1

log "Call shellcode"
call ((void (*) ()) $1 ) ()

log "Detach program"
detach
