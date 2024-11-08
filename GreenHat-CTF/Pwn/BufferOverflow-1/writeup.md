# BufferOverflow-1 Write-Up

## Challenge Details:
-Description: "I can tell you're still a buffer overflow novice. Can you prove me wrong?" <br>
-Port: nc greenhat.microclub.info 5001 <br>
-Files: [executable program](chall), [C program](chall.c) <br>

## Tools:
-Gnu Debugger (gdb): We'll mainly use it to analyze our program and test whether our bof (bufferoverflow) works or not. <br>
-Pwn Cyclic: It's a tool that generates random characters from the alphabet to form a string of a specified length. We'll use it mainly to generate our payloads, and identify the offset of certain cases in our stack. <br>

## Solution:

1.  **Initial Approach** <br>
    -We'll first check our source code using **cat** command: <br> <br>
    ![image](https://github.com/user-attachments/assets/16d55e29-690a-41d7-813f-129c0e84b213) <br> <br>
    -We can notice 3 main functions:  
        -Flag: It opens a .txt file that contains the flag, and then prints it. <br>
        -Main: We just have to know that it calls back Vuln function. <br>
        -Vuln: This is our main dish! We can notice that we have 3 variables, "a" & "b" integers both initialized with 0, and we can't really change their values, and the third is a string "buf", which we can change its 
         value through an input using **gets** function, and it has a specific length. We have 2 conditions regarding the values of "a" & "b", and if we succeed to meet them, our **flag** function will run. <br>
         
    -The first question that comes to mind is: how can we change the values of our variables to match the condition? <br>
    -We have to be aware that **gets** function is vulnerable, since it takes our input without really checking whether it matches the specified length or not, which allows us to literally put any string into our variable. <br>
    -The second question that we should ask is: what will we happen to the characters inserted in our variable that exceed the limit? And that's what we'll discover pretty soon! <br>
    
    -Our time with the source code is over, now we have to turn to our executable file. First of all, we'll use file command on it to verify whether it is **x32 or x64 bits**, which is really important: <br> <br>
    ![image](https://github.com/user-attachments/assets/4a18c874-0b36-417d-b4c8-7371f0b5e838) <br> <br>
    -We can see that it is x32 bits, which makes things easier (the process would be longer with x64 bits, you can check BufferOverflow-3 for more details). <br>
 
 2.  **Detailed Solution** <br>
    -First, we need to prepare the string that we will give as an input to the program, which we call: **"Payload"**. We'll first generate a random string of 65 characters (1 more than the size of buf) using **cyclic**, and then analyze it using **gdb** <br> <br>
    ![image](https://github.com/user-attachments/assets/81397dca-3e1e-425b-89c0-62b11bfdc2a5) <br><br>
    -Before we get going, here are some commands of gdb that we'll use, and their functionalities: <br>
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
     -Now to fully understand what happened, we have to grasp the way our **Stack** behaves:  
![image](https://github.com/user-attachments/assets/b2eda0d0-2c05-4c20-a2eb-25bd00b151e7)  
-Let's analyse the actual contents of our stack:  
-First, you gotta know that the lower we go the higher the adresses are. There are two types of adresses: Logical & Physical. Physical is the actual adress on the stack, and logical is what we also call offset. Offsets are positions relative to where is our EBP.  
-Now what is EBP? It's the Base Pointer, which you can consider as the head of our stack. When we call a function, we need to reserve some space in the memory for its local variables (local variables are the ones declared and used inside the function, and global ones are those we use in the whole program) and other things. Now if you make the connection, that's why we used ebp-offset when we wanted to consult the values of our variables, since the EBP value is usually know and the offset as well, we just substracted it to go lower in adress (higher in the stack).  
-For the EIP, it's the instruction pointer, which contains the return adress of the next instruction after our function, so that we can continue executing our code after we're done with our function.  
-In between we might or might not have some aditional things that don't really matter to us now.  
-Now moving to our big catch: the variables! First, I'll explain more the size of each case and all. Here we need the information of whether our file is x32 or x64 bits. For more context to those who don't know, x32 bits represents the size of one case in our memory. The smallest size unit in memory is Byte, which is equivalent to 8 Bits, and thus 32/8 equals 4 Bytes, and that's actually the size of one case in our memory.
-Both our "a" & "b" variables have just 1 case, since the size of an integer is 4 bytes by default. For "buf", it's length is 64 and each character is 1 byte by default, so 64/8 = 16 which is the number of the cases we have. We have filled it with 65 bytes, so the last one "q" was inserted into "b" which was next in stack.
-If you are curious about the order of the variables, well stacks follow "LIFO" method when inserting elements, which means Last In First Out, so the last element that was inserted is the first to be removed. In our case "buf" was the first one so that's why it's in the bottom of the stack (remember that's it's technically flipped upside down), then after comes "b" then "a".  <br>
-I hope you can assume what we gotta do next...Yes exactly, simply fill "buf" with 64 random characters which we call **padding**, then insert the required values of "b" & "a". You just gotta be careful, since they asked for the hex values of "13371337" & "deadbeef" (you can notice that by the 0x at the beginning which means hexadecimal). Another problem is that our variables are of 4 bytes, which means they can hold 4 charas, while the values we want are 8 charas. To deal with both of these, we gotta take 2 charas at once and convert their value to hexadecimal, which can be done by adding "\x" before each 2 charas.  
![image](https://github.com/user-attachments/assets/a14f60e1-b6f6-4581-81bb-5b3297ba68cf)



        
        
## Flag:
`microCTF{}`

## Additional Resources:
