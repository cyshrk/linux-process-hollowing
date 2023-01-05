#include <string.h>
#include <syscall.h>
#include <unistd.h>

unsigned long syscall3(long n, long a1, long a2, long a3)
{
    unsigned long ret;
    __asm__ __volatile__("syscall"
                         : "=a"(ret)
                         : "a"(n), "D"(a1), "S"(a2), "d"(a3)
                         : "rcx", "r11", "memory");
    return ret;
}

ssize_t write(int fd, const void *buf, size_t count)
{
    return syscall3(SYS_write, fd, (long)buf, count);
}

size_t strlen(const char *s)
{
    const char *c;
    for (c = s; *c != '\x00'; ++c) {
    }
    return c - s;
}

int puts(const char *s)
{
    return (int)(write(1, s, strlen(s)) + write(1, "\n", 1));
}

__attribute__((section(".shellcode.start"))) __attribute__((used)) void shellcode_start()
{
    puts("Hello Shellcode!");
}
