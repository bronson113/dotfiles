#!/usr/bin/python3
from pwn import *
from ctypes import CDLL

context.terminal = ["tmux", "splitw", "-h"]
context.binary = binary_name = "<++>"
elf = context.binary

# libc = ELF("<++>")
# libc_func = CDLL("<++>")
gdb_script = """
<++>
"""

nc_str = "<++>"
if REMOTE:
    _, host, port = nc_str.split(" ")
    p = remote(host, int(port))
else:
    p = process(binary_name)

pause = input()
#gdb.attach(p, gdb_script)
p.interactive()

