#Code By T.Pranay
#Date:- 28 September 2026
#Question Number 37 in Chemical Engineering Gate Paper 2025

import sympy as sp

# Define symbolic variables with positive domain assumption
x, a = sp.symbols('x a', positive=True)

# Define probability distribution p(x) and target function f(x)
p_x = 1 / a
f_x = x**2

# Integrand: f(x) * p(x)
integrand = f_x * p_x

# Anti-derivative (Integrated Function)
anti_derivative = sp.integrate(integrand, x)

# 1. Symbolic Definite Integration method
expectation_symbolic = sp.integrate(integrand, (x, 0, a))

# 2. Limit Substitution Method: F(a) - F(0)
F_upper = anti_derivative.subs(x, a)
F_lower = anti_derivative.subs(x, 0)
expectation_exact = F_upper - F_lower

# Sample Evaluation (e.g., when a = 3)
sample_a = 3
numerical_val = float(expectation_symbolic.subs(a, sample_a))

# Display Formatted Output
print("============================================================")
print("         EXPECTATION VIA INTEGRATION METHOD SUMMARY          ")
print("============================================================")
print(f"Probability Density p(x)  : 1/{a}")
print(f"Function f(x)             : {f_x}")
print(f"Integrand f(x)*p(x)       : {integrand}")
print("-" * 60)
print(f"Anti-Derivative F(x)      : {anti_derivative}")
print(f"Evaluated F(a) - F(0)     : ({F_upper}) - ({F_lower})")
print("-" * 60)
print(f"Symbolic Expectation E[X²]: {expectation_symbolic}")
print(f"Sample Value (for a = {sample_a}) : {numerical_val:.4f} (Exact: {sample_a}^2/3 = 3)")
print("============================================================")