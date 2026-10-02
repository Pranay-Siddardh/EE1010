#Code By T.Pranay
#Date:- 28 September 2026
#Question Number 44 in Chemical Engineering Gate Paper 2025

import numpy as np
import matplotlib.pyplot as plt

def y_exact(x, C=1.0):
    return C / x

def trapezoidal_method(a, b, n_points, C=1.0):
    x = np.linspace(a, b, n_points)
    y = np.zeros(n_points)
    y[0] = C / a  # Initial condition at x = 0.5
    
    # Trapezoidal method iteration for dy/dx = -y/x
    for i in range(n_points - 1):
        h = x[i+1] - x[i]
        y[i+1] = y[i] * (1.0 - h / (2.0 * x[i])) / (1.0 + h / (2.0 * x[i+1]))
        
    return x, y

# Parameters
a, b = 0.5, 4.5
n_points = 5000
C_val = 1.0

# Exact curve data
x_dense = np.linspace(0.2, 5.0, 500)
y_dense = y_exact(x_dense, C=C_val)

# Trapezoidal method data (5000 points from 0.5 to 4.5)
x_trap, y_trap = trapezoidal_method(a, b, n_points, C=C_val)

plt.figure(figsize=(7, 7), dpi=100)

# Continuous plot without scatter markers
plt.plot(x_dense, y_dense, color='#1f77b4', lw=2.5, label='Actual Solution $y = 1/x$')
plt.plot(x_trap, y_trap, color='#d62728', ls='--', lw=1.5, label=f'Trapezoidal Method ($N = {n_points}$)')

# Uniform Grid Setup
plt.xlim(0, 5)
plt.ylim(0, 5)
plt.xticks(np.arange(0, 5.5, 0.5))
plt.yticks(np.arange(0, 5.5, 0.5))
plt.gca().set_aspect('equal', adjustable='box')

plt.xlabel('x')
plt.ylabel('y(x)')
plt.grid(True, linestyle=':', alpha=0.6)
plt.title('Q-44: Actual Solution vs Trapezoidal Method')
plt.legend(loc='upper right')
plt.tight_layout()
plt.savefig("Diff-Eqn.pdf")
print("The Curve is y=c/x and we take c=1 for this plot.")