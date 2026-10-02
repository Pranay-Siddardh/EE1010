#Code By T.Pranay
#Date:- 28 September 2026
#Question Number 46 in Chemical Engineering Gate Paper 2025

import numpy as np
import matplotlib.pyplot as plt

def f(x):
    return x**2 - x - 1.0

def df(x):
    return 2.0 * x - 1.0

# Initial guess x0 = 1
x0 = 1.0

# Iteration 1
f_x0 = f(x0)
df_x0 = df(x0)
x1 = x0 - (f_x0 / df_x0)

print(f"  First iterate x1 = {x1:.4f}")

# Iteration 2
f_x1 = f(x1)
df_x1 = df(x1)
x2 = x1 - (f_x1 / df_x1)

print(f"  Second iterate x2 = {x2:.4f} (Rounded: {x2:.2f})")

# Plotting setup
x_grid = np.linspace(0.5, 2.5, 500)
y_grid = f(x_grid)

plt.figure(figsize=(8, 5), dpi=100)

plt.plot(x_grid, y_grid, color='#1f77b4', lw=2.5, label=r'$f(x) = x^2 - x - 1$')

# Solid y = 0 reference line
plt.axhline(0, color='gray', linestyle='-', lw=1.2)

# Tangent line at x0 (intersects y=0 at x1)
x_tan0 = np.linspace(0.8, 2.1, 100)
y_tan0 = f_x0 + df_x0 * (x_tan0 - x0)
plt.plot(x_tan0, y_tan0, color='#e377c2', linestyle='--', lw=1.5, label=f'Tangent at $x_0$ (meets $y=0$ at $x_1$)')

# Tangent line at x1 (intersects y=0 at x2)
x_tan1 = np.linspace(1.5, 2.2, 100)
y_tan1 = f_x1 + df_x1 * (x_tan1 - x1)
plt.plot(x_tan1, y_tan1, color='#2ca02c', linestyle='--', lw=1.5, label=f'Tangent at $x_1$ (meets $y=0$ at $x_2$)')

# Vertical projection lines from y=0 to curve for iterations
plt.vlines(x1, 0, f(x1), color='gray', linestyle=':', lw=1.0)
plt.vlines(x2, 0, f(x2), color='gray', linestyle=':', lw=1.0)

# Curve evaluation points (unfilled small circles)
plt.scatter([x0, x1, x2], [f(x0), f(x1), f(x2)], facecolors='none', edgecolors='#d62728', s=25, linewidths=1.2, zorder=5)

# Axis intersection points (roots of tangents - unfilled small circles)
plt.scatter([x1, x2], [0, 0], facecolors='none', edgecolors='#2ca02c', s=25, linewidths=1.2, zorder=5)

plt.annotate(f'$x_0 = {x0:.1f}$', (x0, f(x0)), textcoords="offset points", xytext=(-15, -15), ha='center')
plt.annotate(f'$x_1 = {x1:.1f}$', (x1, f(x1)), textcoords="offset points", xytext=(15, 10), ha='center')
plt.annotate(f'$x_2 = {x2:.2f}$', (x2, f(x2)), textcoords="offset points", xytext=(15, -15), ha='center')

plt.xlabel('x')
plt.ylabel('f(x)')
plt.xlim(0.5, 2.5)
plt.ylim(-2.0, 3.0)
plt.grid(True, linestyle=':', alpha=0.6)
plt.title('Q-46: Newton-Raphson Iterations with Tangent Lines')
plt.legend(loc='upper left')
plt.tight_layout()
plt.savefig("Newton-Raphson.pdf")