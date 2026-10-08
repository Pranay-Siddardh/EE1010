# Code By T.Pranay
# Date:- 28 September 2026
# Question Number 35 in Chemical Engineering Gate Paper 2025

import numpy as np
import matplotlib.pyplot as plt
import sys
import os
from pathlib import Path

# 1. Get the directory of the current script
script_dir = Path(__file__).resolve().parent

# 2. Go up one level to the root, then down into the parallel folder
parallel_dir = os.path.join(script_dir, "..", "CoordGeo")
sys.path.append(parallel_dir)

from line.funcs import line_gen


# -----------------------------------------------------------
# 1. Direct analytical results
# -----------------------------------------------------------

area_E = 0.25

integral_tE = 1.0 / 24.0

t_avg = integral_tE / area_E


print(f"Area under E(t) dt         = {area_E}")
print(f"Integral of t*E(t) dt       = {integral_tE:.6f}")
print(f"Mean Residence Time (t_avg) = {t_avg:.4f} min ({t_avg * 60:.2f} s)")
print(f"Rounded Answer              = {t_avg:.3f} min")


# -----------------------------------------------------------
# 2. Generate the RTD line using CoordGeo
#
# E(t) = 4 - 8t
#
# The line joins:
#
# A = (0, 4)
# B = (0.5, 0)
# -----------------------------------------------------------

A = np.array([
    [0],
    [4]
])

B = np.array([
    [0.5],
    [0]
])

line_E = line_gen(A, B)


# -----------------------------------------------------------
# 3. Mean residence time point
# -----------------------------------------------------------

E_avg = 4.0 - 8.0 * t_avg

P_avg = np.array([
    [t_avg],
    [E_avg]
])


# -----------------------------------------------------------
# 4. Plotting
# -----------------------------------------------------------

fig, ax = plt.subplots(
    figsize=(8, 4.5),
    dpi=100
)


# RTD line generated using CoordGeo
ax.plot(
    line_E[0, :],
    line_E[1, :],
    color='#1f77b4',
    lw=2.5,
    label=r'Normalized $E(t) = 4 - 8t$'
)


# Mean residence time vertical line
ax.plot(
    [t_avg, t_avg],
    [0, E_avg],
    color='#d62728',
    linestyle='--',
    lw=2,
    label=r'Mean Lifetime $\bar{t} = 0.17$ min'
)


# Mean residence time point
ax.plot(
    P_avg[0, :],
    P_avg[1, :],
    'ro',
    markersize=7
)


# -----------------------------------------------------------
# Formatting
# -----------------------------------------------------------

ax.set_xlabel(
    'Time $t$ (min)',
    fontsize=11
)

ax.set_ylabel(
    'Exit Age Density $E(t)$ (min$^{-1}$)',
    fontsize=11
)

ax.set_xlim(0, 0.5)

ax.set_ylim(0, 4.2)

ax.grid(
    True,
    linestyle=':',
    alpha=0.6
)

ax.set_title(
    'Residence Time Distribution $E(t)$ & Mean Value',
    fontsize=12,
    fontweight='bold'
)

ax.legend(
    loc='upper right',
    frameon=True
)


plt.tight_layout()

plt.savefig("RTD-Plot.pdf")