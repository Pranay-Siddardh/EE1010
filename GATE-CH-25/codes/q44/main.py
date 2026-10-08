# Code By T.Pranay
# Date:- 28 September 2026
# Question Number 44 in Chemical Engineering Gate Paper 2025

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
from conics.funcs import hyper_gen


# -----------------------------------------------------------
# Hyperbola generation using CoordGeo
#
# Standard hyperbola:
#
#        u^2 - v^2 = 1
#
# CoordGeo hyper_gen(v) gives:
#
#        u = sqrt(1 + v^2)
#
# -----------------------------------------------------------

v = np.linspace(-5, 5, 1000)

u = hyper_gen(v)


# -----------------------------------------------------------
# Scale the hyperbola
#
#        u^2/2 - v^2/2 = 1
#
# which is
#
#        u^2 - v^2 = 2
#
# -----------------------------------------------------------

u = np.sqrt(2) * u
v = np.sqrt(2) * v


# -----------------------------------------------------------
# Rotation transformation
#
#        [ x ]       [ cos(theta)  -sin(theta) ] [ u ]
#        [ y ]   =   [ sin(theta)   cos(theta) ] [ v ]
#
# theta = 45 degrees
# -----------------------------------------------------------

theta = np.pi / 4

R = np.array([
    [np.cos(theta), -np.sin(theta)],
    [np.sin(theta),  np.cos(theta)]
])


# -----------------------------------------------------------
# Rotate first branch using matrix multiplication
# -----------------------------------------------------------

P = np.vstack((u, v))

P_rotated = R @ P

x_hyperbola = P_rotated[0, :]
y_hyperbola = P_rotated[1, :]


# -----------------------------------------------------------
# Generate the second branch
# -----------------------------------------------------------

u_2 = -np.sqrt(2) * hyper_gen(v / np.sqrt(2))

v_2 = v

P_2 = np.vstack((u_2, v_2))

P_2_rotated = R @ P_2

x_hyperbola_2 = P_2_rotated[0, :]
y_hyperbola_2 = P_2_rotated[1, :]


# -----------------------------------------------------------
# Trapezoidal Method
#
# dy/dx = -y/x
# -----------------------------------------------------------

def trapezoidal_method(a, b, n_points, C=1.0):

    x = np.linspace(a, b, n_points)

    y = np.zeros(n_points)

    y[0] = C / a

    for i in range(n_points - 1):

        h = x[i + 1] - x[i]

        y[i + 1] = (
            y[i] * (1.0 - h / (2.0 * x[i]))
            /
            (1.0 + h / (2.0 * x[i + 1]))
        )

    return x, y


# -----------------------------------------------------------
# Parameters
# -----------------------------------------------------------

a = 0.5
b = 4.5

n_points = 5000

C_val = 1.0


# -----------------------------------------------------------
# Trapezoidal Method Data
# -----------------------------------------------------------

x_trap, y_trap = trapezoidal_method(
    a,
    b,
    n_points,
    C=C_val
)


# -----------------------------------------------------------
# Plot
# -----------------------------------------------------------

plt.figure(figsize=(7, 7), dpi=100)


# Rotated hyperbola
plt.plot(
    x_hyperbola,
    y_hyperbola,
    color='#1f77b4',
    lw=2.5,
    label=r'Rotated Hyperbola'
)

plt.plot(
    x_hyperbola_2,
    y_hyperbola_2,
    color='#1f77b4',
    lw=2.5
)


# Trapezoidal solution
plt.plot(
    x_trap,
    y_trap,
    color='#d62728',
    ls='--',
    lw=1.5,
    label=f'Trapezoidal Method ($N = {n_points}$)'
)


# -----------------------------------------------------------
# Uniform Grid Setup
# -----------------------------------------------------------

plt.xlim(-5, 5)
plt.ylim(-5, 5)

plt.xticks(np.arange(-5, 5.5, 0.5))
plt.yticks(np.arange(-5, 5.5, 0.5))

plt.gca().set_aspect('equal', adjustable='box')


plt.xlabel('x')
plt.ylabel('y(x)')

plt.grid(
    True,
    linestyle=':',
    alpha=0.6
)

plt.title(
    r'Q-44: Rotated Hyperbola and Trapezoidal Method'
)

plt.legend(loc='upper right')

plt.tight_layout()

plt.savefig("Diff-Eqn.pdf")

print("Hyperbola generated using CoordGeo.")
print("Rotation angle theta = pi/4.")
print("Rotated hyperbola represents xy = 1.")