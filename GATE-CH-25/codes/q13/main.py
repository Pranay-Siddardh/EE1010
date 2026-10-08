# Code By T.Pranay
# Date:- 28 September 2026
# Question Number 13 in Chemical Engineering Gate Paper 2025

import numpy as np
import matplotlib.pyplot as plt
import sys
import os
from pathlib import Path
from matplotlib.patches import Arc

# 1. Get the directory of the current script
script_dir = Path(__file__).resolve().parent

# 2. Go up one level to the root, then down into the parallel folder
parallel_dir = os.path.join(script_dir, "..", "CoordGeo")
sys.path.append(parallel_dir)

from line.funcs import line_gen


# -----------------------------------------------------------
# Creating complex numbers
# -----------------------------------------------------------

z1 = 1 - 1j
z2 = 1j


# -----------------------------------------------------------
# Multiplying the numbers
# -----------------------------------------------------------

z = z1 * z2


# -----------------------------------------------------------
# Phase in radians and degrees
# -----------------------------------------------------------

arg_rad = np.angle(z)

print("Argument (radians) of z1*z2 :", arg_rad)

arg_deg = np.angle(z, deg=True)

print("Argument (degrees) of z1*z2 :", arg_deg)


# -----------------------------------------------------------
# Argand Plane Visualization
# -----------------------------------------------------------

plt.figure(figsize=(7, 7), dpi=100)


# -----------------------------------------------------------
# Real and Imaginary Reference Axes
# -----------------------------------------------------------

plt.axhline(
    0,
    color='black',
    linestyle='-',
    lw=1.0
)

plt.axvline(
    0,
    color='black',
    linestyle='-',
    lw=1.0
)


# -----------------------------------------------------------
# Origin and complex-number points
# -----------------------------------------------------------

O = np.array([
    [0],
    [0]
])

A = np.array([
    [z1.real],
    [z1.imag]
])

B = np.array([
    [z2.real],
    [z2.imag]
])

C = np.array([
    [z.real],
    [z.imag]
])


# -----------------------------------------------------------
# Generate vector lines using CoordGeo
# -----------------------------------------------------------

line_z1 = line_gen(O, A)

line_z2 = line_gen(O, B)

line_z = line_gen(O, C)


# -----------------------------------------------------------
# Plot the CoordGeo-generated lines
# -----------------------------------------------------------

plt.plot(
    line_z1[0, :],
    line_z1[1, :],
    color='#d62728',
    lw=2.0,
    label=r'$z_1$'
)

plt.plot(
    line_z2[0, :],
    line_z2[1, :],
    color='#2ca02c',
    lw=2.0,
    label=r'$z_2$'
)

plt.plot(
    line_z[0, :],
    line_z[1, :],
    color='#1f77b4',
    lw=2.5,
    label=r'$z_1 \cdot z_2$'
)


# -----------------------------------------------------------
# Unfilled circular point markers
# -----------------------------------------------------------

plt.scatter(
    [z1.real, z2.real, z.real],
    [z1.imag, z2.imag, z.imag],
    facecolors='none',
    edgecolors=[
        '#d62728',
        '#2ca02c',
        '#1f77b4'
    ],
    s=35,
    linewidths=1.5,
    zorder=5
)


# -----------------------------------------------------------
# Labeling Complex Points
# -----------------------------------------------------------

plt.text(
    z1.real + 0.1,
    z1.imag - 0.1,
    r'$z_1 = 1 - i$',
    fontsize=11,
    color='#d62728'
)

plt.text(
    z2.real + 0.1,
    z2.imag + 0.08,
    r'$z_2 = i$',
    fontsize=11,
    color='#2ca02c'
)

plt.text(
    z.real + 0.1,
    z.imag + 0.08,
    r'$z_1 \cdot z_2 = 1 + i$',
    fontsize=11,
    color='#1f77b4'
)


# -----------------------------------------------------------
# Arc 1: Argument of z1*z2
# -----------------------------------------------------------

arc_z = Arc(
    (0, 0),
    0.8,
    0.8,
    angle=0,
    theta1=0,
    theta2=45,
    color='#1f77b4',
    lw=1.8,
    linestyle='--'
)

plt.gca().add_patch(arc_z)

plt.text(
    0.48,
    0.18,
    r'$\arg(z_1 \cdot z_2) = 45^\circ$',
    fontsize=10,
    color='#1f77b4',
    fontweight='bold'
)


# -----------------------------------------------------------
# Arc 2: Angle between z1 and z2
# -----------------------------------------------------------

arc_between = Arc(
    (0, 0),
    1.2,
    1.2,
    angle=0,
    theta1=-45,
    theta2=90,
    color='#ff7f0e',
    lw=1.8,
    linestyle=':'
)

plt.gca().add_patch(arc_between)

plt.text(
    -0.75,
    0.35,
    r'$\angle(z_1, z_2) = 135^\circ$',
    fontsize=10,
    color='#ff7f0e',
    fontweight='bold'
)


# -----------------------------------------------------------
# Graph Formatting
# -----------------------------------------------------------

plt.xlim(-1.5, 2.0)

plt.ylim(-1.5, 2.0)

plt.xlabel(
    r'Real Axis ($\mathrm{Re}$)',
    fontsize=11
)

plt.ylabel(
    r'Imaginary Axis ($\mathrm{Im}$)',
    fontsize=11
)

plt.title(
    r'Q-13: Argand Plane Representation of $z_1$, $z_2$, and $z_1 \cdot z_2$',
    fontsize=12,
    fontweight='bold'
)

plt.grid(
    True,
    linestyle=':',
    alpha=0.6
)

plt.gca().set_aspect(
    'equal',
    adjustable='box'
)

plt.legend()

plt.tight_layout()

plt.savefig("Argument-Complex.pdf")