# Sugar Free Candies Write-Up
## Challenge Details:
-Description: For years, strange signals pulsed through the air on the eve of October 31st. Some said it was the voice of an ancient witch, others believed it was a message from something far darker. A cryptic message, scattered in three parts, was intercepted by a daring group of villagers. Legend spoke of a deal made between the witch and a shadowy figure, but the true intent of their secret could only be revealed by those brave enough to decipher it before midnight, when the veil between worlds would thin.<br>  
-Context: The flag is hidden through a non-linear equation system.<br>  
-Files: [Script](source.py), [Encrypted Entities](output.txt)  

## Detailed Solution:
1.  **Initial Approach:**  
    -First, I started by reading the script and trying to understand it:  
<img width="565" alt="image" src="https://github.com/user-attachments/assets/092663cd-af3c-4b81-b9bc-1e9fafe665f2"><br>
    -The flag was extracted from a txt file and put in the "FLAG" variable. Then its length was divided into 3 to identify the length of each part (which makes sense since in the description it was mentioned that the message is scattered in 3 parts).  
    -Afterwards, each part was isolated through a loop and then converted from bytes to long for an initial obfuscation, and they all were put in a list named "Candies".  
    -At the end, each part was put in a dedicated variable "cnd1" "cnd2" "cnd3" and then encrypted somehow and each of their values were put in a file.  
    -After checking out the last part more closely, it turned out to be a system of non-linear equations with 4 equations and 3 unknowns.  
2.  **Detailed Solution:**
    -To make reading the system easier, I replaced cnd1, cnd2, cnd3 by: x, y, z, and here is how it looks like:  
    x^3+z^2+y=v1  
    y^3+x^2+z=v2  
    z^3+y^2+x=v3  
    x+y+z=v4
    -I tried solving it manually, but given that it is non-linear, it didn't really go well. After some research, I found that there is a function in python that we can use to solve our system automatically, so I wrote a script that does that.



## Flag:
`HTB{__protecting_the_secret_in_equations_is_not_secure__}`
