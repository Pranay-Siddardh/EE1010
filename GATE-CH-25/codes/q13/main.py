#Code By T.Pranay
#Date:- 28 September 2026
#Question Number 13 in Chemical Engineering Gate Paper 2025

import numpy as np

#Creating a complex number directly in python using a + bj
z1 = 1-1j
z2 = 1j 

#Multiplying the numbers to get the result cpmplex number
z = z1*z2

# Phase in radians
arg_rad = np.angle(z)
print("Argument (radians) of z1*z2 :", arg_rad)  

# Phase directly in degrees
arg_deg = np.angle(z, deg=True)
print("Argument (degrees) of z1*z2 :", arg_deg)  
