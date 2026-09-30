#Code By T.Pranay
#Date:- 28 September 2026
#Question Number 44 in Chemical Engineering Gate Paper 2025


import numpy as np

# =============================================================================
# THEORETICAL DERIVATION RECAP (IN CODE COMMENTS):
# Differential Equation : dy/dx + y/x = 0
# Separation           : (1/y) dy = -(1/x) dx
# Integration          : ln|y| + ln|x| = C'  ==>  x*y = C  ==>  y(x) = C / x
# Assuming C = 1       : y(x) = 1 / x
# Definite Integral    : Integral_{a}^{b} (1/x) dx = ln(b) - ln(a)
# =============================================================================

def y_exact(x, C=1.0):
    """Integrated solution y(x) = C / x."""
    return C / x

def trapezoidal_rule(func, a, b, n, C=1.0):
    """
    Computes the area under y(x) using the Trapezoidal Rule:
    Integral approx = (h / 2) * [ f(x_0) + 2*sum(f(x_i)) + f(x_n) ]
    """
    x = np.linspace(a, b, n + 1)
    y = func(x, C)
    h = (b - a) / n
    
    # Trapezoidal approximation formula
    integral_approx = (h / 2.0) * (y[0] + 2 * np.sum(y[1:-1]) + y[-1])
    return x, y, integral_approx

# Parameters
a, b = 1.0, 2.0  # Integration bounds [1, 2]
n_subintervals = 1000
C_val = 1.0

# Numerical Integration via Trapezoidal Method
x_vals, y_vals, numerical_area = trapezoidal_rule(y_exact, a, b, n_subintervals, C=C_val)
exact_area = np.log(b) - np.log(a)  # Exact integral = ln(2)

print("============================================================")
print("  SOLVING dy/dx + y/x = 0 VIA TRAPEZOIDAL INTEGRATION      ")
print("============================================================")
print(f"Integrated Expression y(x)     : y = {C_val} / x")
print(f"Sample Evaluations:")
print(f"  y(1.0) = {y_exact(1.0, C_val):.4f}")
print(f"  y(1.5) = {y_exact(1.5, C_val):.4f}")
print(f"  y(2.0) = {y_exact(2.0, C_val):.4f}")
print("-" * 60)
print(f"Trapezoidal Area Int[1, 2] y dx : {numerical_area:.8f}")
print(f"Exact Analytical Area ln(2)    : {exact_area:.8f}")
print(f"Absolute Numerical Error       : {abs(numerical_area - exact_area):.2e}")
print("============================================================")