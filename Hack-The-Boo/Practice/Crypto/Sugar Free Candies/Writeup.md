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
    -I tried solving it manually, but given that it is non-linear, it didn't really go well. After some research, I found that there is a function in python that we can use to solve our system automatically, and chatgpt wrote me a script that does that:
    
from sympy import symbols, Eq, solve

# Define variables
x, y, z = symbols('x y z')

# Given values
v1 = 4196604293528562019178729176959696479940189487937638820300425092623669070870963842968690664766177268414970591786532318240478088400508536
v2 = 11553755018372917030893247277947844502733193007054515695939193023629350385471097895533448484666684220755712537476486600303519342608532236
v3 = 14943875659428467087081841480998474044007665197104764079769879270204055794811591927815227928936527971132575961879124968229204795457570030
v4 = 6336816260107995932250378492551290960420748628

# Define the system of equations
eq1 = Eq(x**3 + z**2 + y, v1)
eq2 = Eq(y**3 + x**2 + z, v2)
eq3 = Eq(z**3 + y**2 + x, v3)
eq4 = Eq(x + y + z, v4)

# Solve the system
solution = solve([eq1, eq2, eq3, eq4], (x, y, z))

solution
x=1612993708938936929835517754497931126786454632
𝑦
=
2260690199455691264676123410341531247524997487
y=2260690199455691264676123410341531247524997487
𝑧
=
2463132351713367737738737327711828586109296509
z=2463132351713367737738737327711828586109296509  

Then I asked it to convert these values from bytes to strings:  
# Convert the long integers to bytes
x_val = 1612993708938936929835517754497931126786454632
y_val = 2260690199455691264676123410341531247524997487
z_val = 2463132351713367737738737327711828586109296509

# Converting to bytes
x_bytes = x_val.to_bytes((x_val.bit_length() + 7) // 8, byteorder='big')
y_bytes = y_val.to_bytes((y_val.bit_length() + 7) // 8, byteorder='big')
z_bytes = z_val.to_bytes((z_val.bit_length() + 7) // 8, byteorder='big')

x_bytes, y_bytes, z_bytes  

Then I asked it to concatinate them:  
# Concatenate the byte values
concatenated_bytes = x_bytes + y_bytes + z_bytes
concatenated_bytes.decode()  # Decode to get the complete message  

## Flag:
`HTB{__protecting_the_secret_in_equations_is_not_secure__}`  

## Useful Resources:  
-https://stackoverflow.com/questions/15995913/using-fsolve-to-find-the-solution  
-https://www.youtube.com/watch?v=v4R6K4RxADE  

