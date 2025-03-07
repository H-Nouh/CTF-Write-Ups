# BufferOverflow-1 Write-Up

## Challenge Details:
-Description: "I can tell you're still a buffer overflow novice. Can you prove me wrong?" <br>
-Files: [Binary Executable](chall), [Source Code](chall.c), [Flag](flag.txt), [Solver](solver.py). <br>
-Author: Younesfdj. <br>

## Tools:
-Gnu Debugger (gdb): Used to analyze programs and their behavior to better understand them. <br>
-Pwn Tools: Python library to write scripts. <br>
-Pwn Cyclic: Used to generate strings of specific length, containing a sequence of unique 4 characters. <br>

## Solution:

### **Initial Approach:** <br>
We'll first check our source code using **cat** command: <br>
    ![image](https://github.com/user-attachments/assets/16d55e29-690a-41d7-813f-129c0e84b213) <br> <br>
    We can notice 3 main functions:<br>  
        -**Flag:** It opens a .txt file that contains the flag, and then prints it. <br>
        -**Main:** We just have to know that it calls back Vuln function. <br>
        -**Vuln:** This is our main interest! We can notice 3 variables, "a" & "b" integers both initialized with 0, and we can't really change their values, and the third is a string "buf", which we can change its 
         value through an input using **gets** function. We have 2 conditions regarding the values of "a" & "b", and if we succeed to meet them, our **flag** function will run. <br>
         
-The first question that comes to mind is: how can we change the values of our variables to match the condition? <br>
-We have to be aware that **gets** function is vulnerable, since it takes our input without any length restrictions, allowing us to exceed "buf"'s limit. <br>
-The second question that we should ask is: what will we happen to the characters inserted in our variable that exceed the limit? And that's what we'll discover pretty soon! <br>
    
-Our time with the source code is over, now we have to turn to our executable file. First of all, we'll use file command on it to verify whether it is **x32 or x64 bits** and whether it is **Little or Big Endian**, which is really important: <br> <br>
    ![image](https://github.com/user-attachments/assets/4a18c874-0b36-417d-b4c8-7371f0b5e838) <br> <br>
-We can see that it is x32 bits, which makes things easier (the process would be different with x64 bits, you can check BufferOverflow-3 for more details). Also, the "LSB" (Least Significant Byte) indicates that it's little endian, if it was big endian it would be "MSB" (Most Significant Byte) [You can check here for more details about the endianees](#common-mistakes) <br>
 
 ### **Detailed Solution** <br>
-First, we need to prepare the string that we will give as an input to the program, which we call: **"Payload"**. We'll first generate a random string of 65 characters (1 more than the size of buf) using **cyclic**, and then analyze it using **gdb** <br> <br>
    ![image](https://github.com/user-attachments/assets/81397dca-3e1e-425b-89c0-62b11bfdc2a5) <br><br>
    Before we get going, here are some commands of gdb that we'll use, and their functionalities: <br>
        **Disass (function_name)**: It will turn our specified function from an executable code into a readable Assembly code. <br> 
        **B\*(function_name)+(offset)**: It will create a breakpoint at the line with our specified offset in our specified function. The code will stop executing on breakpoints, allowing us to analyze its behavior and the content of different registers, which helps us understand it. <br>
        **x $ebp-(variable_offset)**: to examine the content of a variable specified by its offset. <br>
        **r**: to run our program. <br>
        **c**: to continue execution after a breakpoint. <br>
        **ni**: to execute the next instruction, if we ever want to have a step by step execution. <br>
        **q**: to quit our gdb session. <br>
    -We'll open our chall file with gdb, disass our vuln function, create a breakpoint right after we get our input through gets, run it with our payload as an input, and finally examine the content of our variables. <br> <br> 
    ![image](https://github.com/user-attachments/assets/cdc5c1a2-047f-4c85-8448-f695054f6a28) ![image](https://github.com/user-attachments/assets/6d08c036-ec94-4397-bb22-63151f86417c) <br> <br>
    -As we can see, a = 0 & b = q, and hopefully you can notice that "q" is the last character in our payload, which means that the additional character in buf went to b. Since buf is a string and b is an integer, q was turned into hexadecimal (I have used x/s to get the string value of b, otherwise the result would have been: 0x00000072, which is the hexadecimal value of q). In case you're wondering where I got the offsets of the variable from, I've checked the comparisons of our 2 conditions (in lines +47 & +56 respectively for a & b). <br>  
     Now to fully understand what happened, we have to grasp the way our **Stack** behaves:  
![image](https://github.com/user-attachments/assets/3ab8716d-c7d3-488e-86af-0d92d1cf42fa)

Let's analyse the actual contents of our stack:  
-First, you gotta know that the lower we go the higher the adresses are. There are two types of adresses: Logical & Physical. Physical is the actual adress on the stack, and logical is what we also call offset. Offsets are positions relative to where is our EBP.    
-Now what is EBP? It's the Base Pointer, which you can consider as the head of our stack. When we call a function, we need to reserve some space in the memory for its local variables (local variables are the ones declared and used inside the function, and global ones are those we use in the whole program) and other things. Now if you make the connection, that's why we used ebp-offset when we wanted to consult the values of our variables, since the EBP value is usually know and the offset as well, we just substracted it to go lower in adress (higher in the stack).  
-For the EIP, it's the instruction pointer, which contains the return adress of the next instruction after our function, so that we can continue executing our code after we're done with our function.  
-In between we might or might not have some aditional things that don't really matter to us now.  
-Now moving to our main focus: the variables! First, I'll explain more the size of each case and all. Here we need the information of whether our file is x32 or x64 bits. For more context to those who don't know, x32 bits represents the size of one case in our memory. The smallest size unit in memory is Byte, which is equivalent to 8 Bits, and thus 32/8 equals 4 Bytes, and that's actually the size of one case in our memory.  
-Both our "a" & "b" variables have just 1 case, since the size of an integer is 4 bytes by default. For "buf", it's length is 64 and each character is 1 byte by default, so 64/4 = 16 which is the number of the cases we have. We have filled it with 65 bytes, so the last one "q" was inserted into "b" which was next in stack.  
-If you are curious about the order of the variables, well stacks follow "LIFO" method when inserting elements, which means Last In First Out, so the last element that was inserted is the first to be removed. In our case "buf" was the first one so that's why it's in the bottom of the stack (remember that's it's technically flipped upside down), then after comes "a" then "b". However, in our case "b" came before "a" so why's that? <br>
### -----IMPORTANT: 
-When programs are compiled, some optimizations can be done including the memory layout, so the order in which the variables are placed in the stack won't necessarily be the same in which they were declared. This is one of the main benefits of debugging our binary: observing exactly how our program is behaving.  
### --------------------
-I hope you can assume what we gotta do next...Yes exactly, simply fill "buf" with 64 random characters which we call **padding**, then insert the required values of "b" & "a". You just gotta be careful, since they asked for hex values: "13371337" & "deadbeef" (you can notice that by the 0x at the beginning which means hexadecimal), and since our input will be converted to hex automatically (string to int), so we have to go the other way around, and give a string that when converted will result in 0x13371337 & 0xdeadbeef. (literally get their ascii values) <br> 
-The command we'll use is: **python2 -c "print('A' * 64 + '\xef\xbe\xad\xde' + '\x37\x13\x37\x13')" > payload**    
-The flag "-c" is used to execute the code directly in our terminal without having to create a python script file.  
-">" is used to direct the output into our payload file.  
-Since an int is 4 bytes, so we have to divide our input 0xdeadbeef into 4: 'de' 'ad' 'be' 'ef', and as I mentioned earlier it's a hexa value, so we need a string that would be equivalent to that value when converted from str to int, and that's why we use "\x": it converts the next 2 characters into 1 byte (2 hex values).  
-Now all what is left is running our binary with the crafted payload as input, using the input redirection "<":  <br>
![image](https://github.com/user-attachments/assets/aec228f6-b1d5-42d0-8cbf-524e22c87bd9)
# Congrats on your first BufferOverflow!
## Common mistakes: 
-Not respecting the endianees and writing **'\xde\xad\xbe\xef' + '\x13\x37\x13\x37'**: There are 2 types of endianees: Big & Little endian. For the big endian, the data is stored like it is in memory (deadbeef), while for the little endian it's in the opposite order byte (2 hex values) per byte (efbeadde). Most systems now use Little Endian, since it can be more optimal in several cases, but we still should confirm and check what we're working on using "file" command like we did in the beginning.  
-Writing '\efbeadde' or directly 'efbeadde': As I mentioned earlier, our input is str and we want to overwrite an int, and since it's mentioned (0xdeadbeef), we technically want to input a string that when it's converted to hex it results in deadbeef. If we simply send deadbeef, that'll simply be: "6465616462656566". Also when we use \xefbeadde, only the first 2 charas will be affected since the hex escape sequence "\x" needs exactly 2 characters after it to convert them.  
-Writing '\xef\xbe\xad\xde\x37\x13\x37\x13'instead of separating them: It won't necessarily cause issues all the times, like in this example it works all fine, but it's better to avoid it since it can cause issues when we have to explicitly separate them.  
## IMPORTANT NOTE: 
-I used python2 cause it's simpler, if you would use the same command on python3 it would generate a wrong payload and that's mainly because the print function in python3 automatically generates a new line at the end of our printed string. It also encodes the result and treats strings as unicode, so we have to add b"" before every part to ensure that it's turned into bytes, but the newline problem would still be there. What we can do instead if we still want to use python3 we can use a function that writes raw bytes directly to output (without having a newline at the end) we just have to add b"" in this case as well since we are dealing with bytes and not string, and our command would be:  <br>
**python3 -c 'import sys; sys.stdout.buffer.write(b"A" * 64 + b"\xef\xbe\xad\xde" + b"\x37\x13\x37\x13")' > payload**  <br>
## Pwntools Script: 
-The more we advance in challenges, the more complex they get, and thus the more necessary it'll be to automate things. Luckily, there's a really powerful python library named "Pwntools", which literally can do wonders (cyclic is part of it btw). I'll show you a simple script to solve this challenge using pwntools, and explain it in details:  
```python
from pwn import *
p = process("./chall")

payload = b"A" * 64 + p32(0xdeadbeef) + p32(0x13371337)

p.sendline(payload)
p.interactive()
```
-First, we have to import our library "pwn". Afterwards, we have to create our process "p". Since we are working locally I used p = process(./name-of-your-binary), but when we want to work on a remote server we should instead use: p = remote ("Host", Port), to create a connection.  
-For the payload, since we're working with python3, we should have elements of the same type when concatinating, that's why we added b"" to the "A"s. For "a" & "b" values, as you can see instead of all the previous work of respecting endianees and using "\x" which can be super tedious with longer payloads especially in x64, we simply can use p32 (p64 for x64 bits), and just write the value we want in hexa, **and that's the power & beauty of pwntools!**  
-After crafting our payload, we should send it using sendline() function. This would print the flag automatically if it worked, but the remote connection will close directly afterwards without even being able to see the result, and that's why we used the interactive() function, which keeps the connection alive and gives us the hand to interract with it.  <br>
# Additional Resources:
### [Pwndbg cheatsheet:](https://drive.google.com/file/d/16t9MV8KTFXK7oX_CzXhmDdaVnjT8IYM4/view?pli=1)
### [Pwntools documentation:](https://docs.pwntools.com/en/stable/intro.html)
### [Amazing Bof explanation video (you can check the playlist for more vulnerabilities):](https://www.youtube.com/watch?v=wa3sMSdLyHw&list=PLHUKi1UlEgOIc07Rfk2Jgb5fZbxDPec94)
