#Code By T.Pranay
#Date:- 28 September 2026
#Question Number 37 in Chemical Engineering Gate Paper 2025

import numpy as np
import matplotlib.pyplot as plt
import time
import sys
import os
from pathlib import Path


# ==============================================================================
# CoordGeo Path
# ==============================================================================

# 1. Get the directory of the current script
script_dir = Path(__file__).resolve().parent

# 2. Go up one level to the root, then down into the parallel folder
parallel_dir = os.path.join(script_dir, "..", "CoordGeo")
sys.path.append(parallel_dir)

from conics.funcs import parab_gen
from line.funcs import line_gen


# ==============================================================================
# THEORETICAL EXPECTED VALUE CALCULATION
#
# X ~ Uniform(0, a) with PDF p(x) = 1/a for x in (0, a).
# f(x) = x^2
#
# E[f(X)] = ∫_0^a f(x) * p(x) dx
#          = (1/a) * ∫_0^a x^2 dx
#          = (1/a) * [x^3 / 3]_0^a
#          = a^2 / 3
#
# For a = 5:
#
# E[f(X)] = 5^2 / 3 = 25 / 3 ≈ 8.333333
# ==============================================================================


# Parameters
filename = "main.dat"
a_val = 5.0
N = 5000

theoretical_avg = (a_val ** 2) / 3.0


# ==============================================================================
# 1. Load N = 5000 random points generated in [0, 5]
# ==============================================================================

try:
    x_data = np.loadtxt(filename)

except OSError:
    current_time_seed = int(time.time())
    np.random.seed(current_time_seed)

    x_data = np.random.uniform(0.0, a_val, N)


# ==============================================================================
# Target function
# ==============================================================================

def f(x_arr):
    return x_arr ** 2


# ==============================================================================
# 2. Compute empirical average
# ==============================================================================

f_data = f(x_data)

empirical_avg = np.mean(f_data)


print(
    f"Theoretical Expected Value E[f(X)] (a^2 / 3) : "
    f"{theoretical_avg:.6f}"
)

print(
    f"Empirical Dataset Average (N={len(x_data)})           : "
    f"{empirical_avg:.6f}"
)


# ==============================================================================
# 3. Generate f(x) = x^2 using CoordGeo
# ==============================================================================

# CoordGeo parab_gen(y,a) generates:
#
#              y^2 = a*x
#
# For a = 1:
#
#              y^2 = x
#
# We require:
#
#              Y = X^2
#
# Therefore we interchange the coordinates using:
#
#                  [ 0  1 ]
#              S = [ 1  0 ]
#
# Starting point:
#
#              P = [ y^2 ]
#                  [ y   ]
#
# After transformation:
#
#              P' = S P
#
#                 = [ 0  1 ] [ y^2 ]
#                   [ 1  0 ] [ y   ]
#
#                 = [ y   ]
#                   [ y^2 ]
#
# Hence:
#
#              X = y
#              Y = y^2
#
# Therefore:
#
#              Y = X^2
#
# No translation or scaling is required.
# ==============================================================================


# Parameter used by CoordGeo parabola
a_parabola = 1.0

# Parameter of the original CoordGeo parabola
y_param = np.linspace(0.0, a_val, 1000)

# CoordGeo generates x = y^2 / a
x_coordgeo = parab_gen(y_param, a_parabola)

# Ordered pairs of the original CoordGeo parabola
P = np.vstack((x_coordgeo, y_param))


# Transformation matrix for coordinate interchange
S = np.array([
    [0.0, 1.0],
    [1.0, 0.0]
])


# Apply the transformation
P_transformed = S @ P


# The transformed coordinates are:
x_grid = P_transformed[0, :]
f_grid = P_transformed[1, :]


# ==============================================================================
# Plot
# ==============================================================================

fig, ax = plt.subplots(figsize=(9, 5.5), dpi=100)


# ==============================================================================
# Continuous function curve f(x) = x^2
# Generated from CoordGeo parab_gen() and transformed using S
# ==============================================================================

ax.plot(
    x_grid,
    f_grid,
    color='#1f77b4',
    lw=2.5,
    label=r'$f(x) = x^2$'
)


# ==============================================================================
# Scatter plot of N = 5000 evaluated sample points
# ==============================================================================

ax.scatter(
    x_data,
    f_data,
    color='#ff7f0e',
    alpha=0.15,
    s=8,
    label=f'Evaluated Data Points ($N = {N}$)'
)


# ==============================================================================
# Horizontal line for theoretical expected value
# ==============================================================================

A_theory = np.array([
    [0.0],
    [theoretical_avg]
])

B_theory = np.array([
    [a_val],
    [theoretical_avg]
])

theory_line = line_gen(A_theory, B_theory)

ax.plot(
    theory_line[0, :],
    theory_line[1, :],
    color='#2ca02c',
    linestyle='-',
    lw=2,
    label=f'Theoretical $E[f(X)] = a^2/3 = {theoretical_avg:.4f}$'
)


# ==============================================================================
# Horizontal line for empirical average
# ==============================================================================

A_empirical = np.array([
    [0.0],
    [empirical_avg]
])

B_empirical = np.array([
    [a_val],
    [empirical_avg]
])

empirical_line = line_gen(A_empirical, B_empirical)

ax.plot(
    empirical_line[0, :],
    empirical_line[1, :],
    color='#d62728',
    linestyle='--',
    lw=2,
    label=f'Empirical Average (N=5000) = {empirical_avg:.4f}'
)


# ==============================================================================
# Formatting
# ==============================================================================

ax.set_xlabel(
    r'Random Variable $x \in [0,a]$',
    fontsize=11
)

ax.set_ylabel(
    r'$f(x) = x^2$',
    fontsize=11
)

ax.set_xlim(0, a_val)

ax.set_ylim(
    -0.5,
    a_val**2 + 1.5
)

ax.grid(
    True,
    linestyle=':',
    alpha=0.6
)

ax.set_title(
    f'Q-37: $f(x) = x^2$ vs $x$ ($N = {N}, a = {a_val}$)',
    fontsize=12,
    fontweight='bold'
)

ax.legend(
    loc='upper left',
    frameon=True
)

plt.tight_layout()

plt.savefig("Expected-Value.pdf")

plt.show()