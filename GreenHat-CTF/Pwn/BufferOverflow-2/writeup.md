# BufferOverflow-2 Write-Up

## Challenge Details:
**-Author:** "Younesfdj". <br>
**-Description:** "Are you ready to master the art of buffer overflow??" <br>
**-Files:** [Binary Executable](chall), [Source Code](chall.c), [Flag](flag.txt), [Solver](script.py). <br>

## Solution:

### **Initial Approach:** <br>
Let's check our source code: <br>
    ![image](https://github.com/user-attachments/assets/27d53be1-06de-4992-a064-2f90ce9406b2) <br> <br>
-Let's focus on our main function: we have a setup function that's running first, then "vuln". In vuln, we have a string of 24 chars, which is filled from the input using gets. <br>  
-We also have a "win" function that is not being called at all, and it prints "You win" and opens a shell in the remote server using "system" function. This latter executes any command given as parameters in a shell then exits, that's why here they passed "/bin/sh" to the function, so that a shell opens and we can execute any command we want. <br>  
-Logically, after we get a shell in the remote server, we'll find the flag and can read it. Luckily, "Gets" is a vulnerable function, which allows us to do bufferoverflows if the size of the input isn't specified (like in this case). So, we'll have to exploit our bufferoverflow to somehow execute the "Win" function.  
     
### **Detailed Solution** <br>
Using file command, we can see that our executable is x32 bits, meaning that the registers we'll have on our stack are "EBP" & "EIP" (if it was x64 bits it would be "RBP" & "RIP").  
![image](https://github.com/user-attachments/assets/25e2c663-d18e-47d9-8508-beeecf219071)

Let's visualize the stack to understand better:
![image](https://github.com/user-attachments/assets/3b134902-de8f-41b7-a911-78bca79f7eeb)

-We have the cases of our buf string, and on top of the stack we have EIP (Instructions Pointer), which contains the return address of our function "vuln" which is in this case the instruction "return 0" in main. Now we gotta overwrite it with the address of the function "win", but the thing is that the number of cases between "buf" & "EIP" is unknown.<br>  

-In order to craft a proper payload for our bufferoverflow and get the flag, we need 2 information next:
  
    -The number of cases between "buf" & "EIP" which is called "Offset".
    -The address of "win" function.
-To determine the offset, we'll be using "Pwndbg" to analyze the content of our memory after execution. First, we'll generate a random string of 100 using "cyclic" and use it as input. Mostly the EIP will be overwritten with random characters causing a segmentation fault (SIGSEGV). We'll check the content of "EIP" (the 4 chars that caused the program to crash), and determine their position in our payload using -l tag in cyclic, followed by the 4 chars.  
![image](https://github.com/user-attachments/assets/7e7c8aa0-f7f0-4f72-9cfa-37759f77c2f6)
As you can see, the payload caused the program to crash, and the exact values behind that are "jaaa". Let's just find the offset:  
![image](https://github.com/user-attachments/assets/bacbaeb4-e1cb-48b6-b0f5-6215de777633)
### We got our Offset: 36
-Let's determine the return address now. We can use "nm" (name list) command, which shows us the symbols of our binary:  
![image](https://github.com/user-attachments/assets/502e5575-c185-40c5-9887-baae4122cf5e)

### We got our Address: 0x08049220
-Let's write a simple script that crafts our payload with a padding of 36 "A"s and then "win"'s address, and then sends it to the executable:  
```python
from pwn import *

ret2win = 0x08049220
payload = b"A" * 36 + p32(ret2win)

p = process("./chall")

p.send(payload)
p.sendline()
p.interactive()
```
-Let's run it:  
![image](https://github.com/user-attachments/assets/78a67a4b-171a-4383-86dc-0981bf0f08e5)  
Niceee, we successfully returned to "win" function and got access to a shell! Let's finally get the flag:  
![image](https://github.com/user-attachments/assets/0ae0dbb4-6cf5-4156-97e9-477ba436ea3c)
# Congrats on your first ret2win!


