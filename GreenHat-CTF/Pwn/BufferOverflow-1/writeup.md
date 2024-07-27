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
    -We have to be aware that **gets** function is vulnerable, since it takes our input without really checking whether it matches the specified length or not, which allows us to literally put any string into our     
    variable. <br>
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


        
        
## Flag:
`microCTF{}`

## Additional Resources:
