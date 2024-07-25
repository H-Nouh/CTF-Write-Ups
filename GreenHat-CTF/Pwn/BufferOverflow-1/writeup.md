# BufferOverflow-1 Write-Up

## Challenge Details:
-Description: "I can tell you're still a buffer overflow novice. Can you prove me wrong?" <br>
-Port: nc greenhat.microclub.info 5001 <br>
-Files: [executable program](chall), [C program](chall.c) <br>

## Tools:
-Gnu Debugger (gdb): We'll mainly use it to analyze our program, and test whether our bof (bufferoverflow) works or not. <br>
-Pwn Cyclic: It's a tool that generates random characters from the alphabet to form a string of a specified length. We'll use it mainly to generate our payloads, and identify the offset of certain cases in our stack. <br>

## Solution:

1.  **Initial Approach**
    -We'll first check our source code using **cat** command: <br>
    ![image](https://github.com/user-attachments/assets/16d55e29-690a-41d7-813f-129c0e84b213) <br>
    -We can notice 3 main functions:
        -Flag: It opens a .txt file that contains the flag, and then prints it. <br>
        -Main: We just have to know that it calls back Vuln function. <br>
        -Vuln: This is our main dish! We can notice that we have 3 variables, "a" & "b" integers both initialized with 0, and we can't really change their values, and the third is a string "buf", which we can change its 
         value through an input using **gets** function, and it has a specific length. We have 2 conditions regarding the values of "a" & "b", and if we succeed to meet them, our **flag** function will run. <br>
         
    -The first question that comes to mind is: how can we change the values of our variables to match the condition? <br>
    -We have to be aware that **gets** function is vulnerable, since it takes our input without really checking whether it matches the specified length or not, which allows us to literally put any string into our     
    variable. <br>
    -The second question that we should ask is: what will we happen to the characters inserted in our variable that exceed the limit? And that's what we'll discover pretty soon! <br>
    
    -Our time with the source code is over, now we have to turn to our executable file. First of all, we'll use file command on it to verify whether it is **x32 or x64 bits**, which is really important: <br>
    ![image](https://github.com/user-attachments/assets/4a18c874-0b36-417d-b4c8-7371f0b5e838)
    -We can see that it is x32 bits, which makes things easier (the process would be longer with x64 bits, you can check BufferOverflow-3 for more details).
 
3.  **Detailed Solution**
   
    

## Flag:
`microCTF{}`

## Additional Resources:
