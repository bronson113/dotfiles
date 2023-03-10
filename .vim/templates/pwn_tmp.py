#!/usr/bin/python3

from pwn import *
# from ctypes import CDLL


context.binary = bin_name = "<++>"
context.terminal = ["tmux", "splitw", "-h"]

elf = ELF(bin_name)
#libc = ELF("<++>")


def connect():
    if args.REMOTE:
        nc_str = "<++>"
        _, host, port = nc_str.split(" ")
        p = remote(host, int(port))

    else:
        p = process(bin_name)
        if args.GDB:
            gdb_script = """
            """
            gdb.attach(p, gdb_script)

    return p


def main():
    p = connect()
    p.interactive()


if __name__ == "__main__":
    main()

