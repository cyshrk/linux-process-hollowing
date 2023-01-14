import hashlib
import re
from pathlib import Path


def main():
    proc_libc_hash = {}

    for process_root in Path("/proc").glob("[0-9]*"):
        pid = process_root.name

        process_root = Path("/proc", pid)
        map_path = process_root.joinpath("maps")
        mem_path = process_root.joinpath("mem")

        for mapping in map_path.read_text().splitlines():
            parts = [x for x in mapping.split(" ") if x]
            (start, end), perms, file = parts[0].split("-"), parts[1], parts[5] if len(parts) >= 6 else ""
            if "x" in perms and re.match("/usr/lib/x86_64-linux-gnu/libc-[0-9.]+.so", file):
                with mem_path.open("rb") as mem_file:
                    start, end = int(start, 16), int(end, 16)
                    mem_file.seek(start)
                    md5 = hashlib.md5(mem_file.read(end - start)).hexdigest()
                    if md5 not in proc_libc_hash:
                        proc_libc_hash[md5] = set()
                    proc_libc_hash[md5].add(pid)

    for md5, pids in proc_libc_hash.items():
        print(md5, len(pids))


if __name__ == '__main__':
    main()
