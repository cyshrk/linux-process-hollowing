import re
from pathlib import Path

import lief


def main():
    suspicious_procs = set()

    # Maybe other path, but I use mine
    libc: lief.ELF.Binary = lief.parse("/usr/lib/x86_64-linux-gnu/libc.so.6")
    libc_exec_content = [bytes(segment.content)
                         for segment in libc.segments
                         if segment.flags & 1][0]

    all_processes = list(Path("/proc").glob("[0-9]*"))
    for process_root in all_processes:
        pid = process_root.name

        process_root = Path("/proc", pid)
        map_path = process_root.joinpath("maps")
        mem_path = process_root.joinpath("mem")

        for mapping in map_path.read_text().splitlines():
            parts = [x for x in mapping.split(" ") if x]
            (start, _), perms, offset, file = parts[0].split("-"), parts[1], int(parts[2], 16), parts[5] if len(
                parts) >= 6 else ""
            if "x" in perms and re.match("/usr/lib/x86_64-linux-gnu/libc-[0-9.]+.so", file):
                with mem_path.open("rb") as mem_file:
                    start = int(start, 16)
                    mem_file.seek(start)
                    if mem_file.read(len(libc_exec_content)) != libc_exec_content:
                        suspicious_procs.add(pid)
                        print(f"{pid} is suspicious! Diff in RX segment between file and mem!")

    print(f"Found {len(suspicious_procs)} suspicious processes out of {len(all_processes)}")


if __name__ == '__main__':
    main()
