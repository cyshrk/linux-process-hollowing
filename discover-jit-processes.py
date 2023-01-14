from os import readlink
from pathlib import Path


def main():
    jit_enabled_elfs = {}

    for process_root in Path("/proc").glob("[0-9]*"):
        pid = process_root.name

        exe_link = process_root.joinpath("exe")
        map_file = process_root.joinpath("maps")

        try:
            memory_map = map_file.read_text()
        except PermissionError:
            continue
        except FileNotFoundError:
            print(f"That's odd, maps file not found for {pid}")
            continue

        for mapping in memory_map.splitlines():
            parts = [x for x in mapping.split(" ") if x]
            perms, file = parts[1], parts[5] if len(parts) >= 6 else ""
            if "x" in perms and not file:
                if readlink(exe_link) not in jit_enabled_elfs:
                    jit_enabled_elfs[readlink(exe_link)] = set()
                jit_enabled_elfs[readlink(exe_link)].add(pid)

    for elf, pids in jit_enabled_elfs.items():
        print(elf, pids)


if __name__ == '__main__':
    main()
