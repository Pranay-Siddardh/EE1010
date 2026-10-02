#Code By T.Pranay
#Date:- 28 September 2026
#Question Number 37 in Chemical Engineering Gate Paper 2025

import numpy as np
import matplotlib.pyplot as plt
import time

# ==============================================================================
# THEORETICAL EXPECTED VALUE CALCULATION (Commentary):
# X ~ Uniform(0, a) with PDF p(x) = 1/a for x in (0, a).
# f(x) = x^2
# E[f(X)] = ∫_0^a f(x) * p(x) dx 
#          = (1/a) * ∫_0^a x^2 dx 
#          = (1/a) * [x^3 / 3]_0^a = a^2 / 3
# For a = 5: E[f(X)] = 5^2 / 3 = 25 / 3 ≈ 8.333333
# ==============================================================================

# Parameters
filename = "main.dat"
a_val = 5.0
N = 5000
theoretical_avg = (a_val ** 2) / 3.0  # Exact a^2 / 3 = 25 / 3 ≈ 8.3333

# 1. Load N = 5000 random points generated in [0, 5] by the C program
try:
    x_data = np.loadtxt(filename)
except OSError:
    current_time_seed = int(time.time())
    np.random.seed(current_time_seed)
    x_data = np.random.uniform(0.0, a_val, N)

# Target function f(x) = x^2
def f(x_arr):
    return x_arr ** 2

# 2. Compute empirical average from the N = 5000 dataset
f_data = f(x_data)
empirical_avg = np.mean(f_data)

print(f"Theoretical Expected Value E[f(X)] (a^2 / 3) : {theoretical_avg:.6f}")
print(f"Empirical Dataset Average (N={len(x_data)})           : {empirical_avg:.6f}")

# 3. Plotting f(x) = x^2 vs x till a = 5
x_grid = np.linspace(0, a_val, 1000)
f_grid = f(x_grid)

fig, ax = plt.subplots(figsize=(9, 5.5), dpi=100)

# Continuous function curve f(x) = x^2
ax.plot(x_grid, f_grid, color='#1f77b4', lw=2.5, label=r'$f(x) = x^2$')

# Scatter plot of N = 5000 evaluated sample points
ax.scatter(x_data, f_data, color='#ff7f0e', alpha=0.15, s=8, label=f'Evaluated Data Points ($N = {N}$)')

# Horizontal line for Theoretical Expected Value (25/3 ≈ 8.3333)
ax.axhline(y=theoretical_avg, color='#2ca02c', linestyle='-', lw=2, 
           label=f'Theoretical $E[f(X)] = a^2/3 = {theoretical_avg:.4f}$')

# Horizontal line for Empirical Average from data
ax.axhline(y=empirical_avg, color='#d62728', linestyle='--', lw=2, 
           label=f'Empirical Average (N=5000) = {empirical_avg:.4f}')

# Formatting
ax.set_xlabel('Random Variable $x in [0, a]$', fontsize=11)
ax.set_ylabel('$f(x) = x^2$', fontsize=11)
ax.set_xlim(0, a_val)
ax.set_ylim(-0.5, a_val**2 + 1.5)
ax.grid(True, linestyle=':', alpha=0.6)
ax.set_title(f'Q-37: $f(x) = x^2$ vs $x$ ($N = {N}, a = {a_val}$)', fontsize=12, fontweight='bold')
ax.legend(loc='upper left', frameon=True)

plt.tight_layout()
plt.savefig("Expected-Value.pdf")