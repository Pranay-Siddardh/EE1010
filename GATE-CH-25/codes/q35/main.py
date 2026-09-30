#Code By T.Pranay
#Date:- 28 September 2026
#Question Number 35 in Chemical Engineering Gate Paper 2025

import sympy as sp

# Define symbolic variable
t = sp.Symbol('t')

# Define functions
E = 1 - 2*t
tE = t * (1 - 2*t)

# 1. Indefinite Integrals (Anti-derivatives)
print("Integral of E(t):  ", sp.integrate(E, t))     # Output: -t**2 + t
print("Integral of t*E(t):", sp.integrate(tE, t))    # Output: -2*t**3/3 + t**2/2

# 2. Definite Integrals over [0, 0.5]
num = sp.integrate(tE, (t, 0, 0.5))
den = sp.integrate(E, (t, 0, 0.5))

mean_time = num / den

print("Floating Point Result:  ", float(mean_time))    # Output: 0.16666666666666666
