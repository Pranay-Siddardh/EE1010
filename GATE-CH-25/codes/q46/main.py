#Code By T.Pranay
#Date:- 28 September 2026
#Question Number 46 in Chemical Engineering Gate Paper 2025

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

# CoordGeo functions
from conics.funcs import parab_gen
from line.funcs import line_gen


# -----------------------------------------------------------
# Newton-Raphson functions
# -----------------------------------------------------------

def f(x):
    return x**2 - x - 1.0


def df(x):
    return 2.0 * x - 1.0


# Initial guess x0 = 1
x0 = 1.0


# -----------------------------------------------------------
# Iteration 1
# -----------------------------------------------------------

f_x0 = f(x0)
df_x0 = df(x0)

x1 = x0 - (f_x0 / df_x0)

print(f"  First iterate x1 = {x1:.4f}")


# -----------------------------------------------------------
# Iteration 2
# -----------------------------------------------------------

f_x1 = f(x1)
df_x1 = df(x1)

x2 = x1 - (f_x1 / df_x1)

print(f"  Second iterate x2 = {x2:.4f} (Rounded: {x2:.2f})")


# -----------------------------------------------------------
# CoordGeo Parabola Transformation
# -----------------------------------------------------------

# CoordGeo parab_gen(y,a) generates:
#
#       y^2 = a*x
#
# For a = 1:
#
#       y^2 = x
#
# We want the parabola:
#
#       Y = X^2 - X - 1
#
# Complete the square:
#
#       Y = (X - 1/2)^2 - 5/4
#
# -----------------------------------------------------------
# Step 1: Generate the CoordGeo parabola y^2 = x
# -----------------------------------------------------------

t = np.linspace(-1.0, 2.0, 500)

x_coordgeo = parab_gen(t, 1)
y_coordgeo = t

P = np.vstack((x_coordgeo, y_coordgeo))


# -----------------------------------------------------------
# Step 2: Swap x and y using a transformation matrix
#
#        [ 0  1 ]
#    S = [ 1  0 ]
#
# Therefore:
#
#        [x]       [0 1] [t^2]     [t]
#        [y]  =    [1 0] [ t ]  =  [t^2]
#
# Hence:
#
#        y = x^2
# -----------------------------------------------------------

S = np.array([
    [0, 1],
    [1, 0]
])

P_swapped = S @ P


# -----------------------------------------------------------
# Step 3: Translate the parabola
#
# We need:
#
#        y = x^2 - x - 1
#
#        y = (x - 1/2)^2 - 5/4
#
# Therefore translate every point by:
#
#        [ 1/2 ]
#        [-5/4]
#
# Final transformation:
#
#        P_final = S P + translation
# -----------------------------------------------------------

translation = np.array([
    [1/2],
    [-5/4]
])

P_final = P_swapped + translation


# -----------------------------------------------------------
# Plotting setup
# -----------------------------------------------------------

plt.figure(figsize=(8, 5), dpi=100)


# Plot transformed CoordGeo parabola
plt.plot(
    P_final[0, :],
    P_final[1, :],
    color='#1f77b4',
    lw=2.5,
    label=r'$f(x)=x^2-x-1$'
)


# -----------------------------------------------------------
# x-axis: y = 0
# Generated using CoordGeo line_gen
# -----------------------------------------------------------

X_axis_A = np.array([[0.5], [0]])
X_axis_B = np.array([[2.5], [0]])

x_axis = line_gen(X_axis_A, X_axis_B)

plt.plot(
    x_axis[0, :],
    x_axis[1, :],
    color='gray',
    linestyle='-',
    lw=1.2
)


# -----------------------------------------------------------
# Tangent at x0
#
# Tangent equation:
#
# y = f(x0) + f'(x0)(x-x0)
# -----------------------------------------------------------

A0 = np.array([[0.8], [f_x0 + df_x0 * (0.8 - x0)]])
B0 = np.array([[2.1], [f_x0 + df_x0 * (2.1 - x0)]])

tangent0 = line_gen(A0, B0)

plt.plot(
    tangent0[0, :],
    tangent0[1, :],
    color='#e377c2',
    linestyle='--',
    lw=1.5,
    label=r'Tangent at $x_0$ (meets $y=0$ at $x_1$)'
)


# -----------------------------------------------------------
# Tangent at x1
# -----------------------------------------------------------

A1 = np.array([[1.5], [f_x1 + df_x1 * (1.5 - x1)]])
B1 = np.array([[2.2], [f_x1 + df_x1 * (2.2 - x1)]])

tangent1 = line_gen(A1, B1)

plt.plot(
    tangent1[0, :],
    tangent1[1, :],
    color='#2ca02c',
    linestyle='--',
    lw=1.5,
    label=r'Tangent at $x_1$ (meets $y=0$ at $x_2$)'
)


# -----------------------------------------------------------
# Vertical projection from x1 to the parabola
# -----------------------------------------------------------

P_x1_bottom = np.array([[x1], [0]])
P_x1_top = np.array([[x1], [f(x1)]])

projection1 = line_gen(P_x1_bottom, P_x1_top)

plt.plot(
    projection1[0, :],
    projection1[1, :],
    color='gray',
    linestyle=':',
    lw=1.0
)


# -----------------------------------------------------------
# Vertical projection from x2 to the parabola
# -----------------------------------------------------------

P_x2_bottom = np.array([[x2], [0]])
P_x2_top = np.array([[x2], [f(x2)]])

projection2 = line_gen(P_x2_bottom, P_x2_top)

plt.plot(
    projection2[0, :],
    projection2[1, :],
    color='gray',
    linestyle=':',
    lw=1.0
)


# -----------------------------------------------------------
# Curve evaluation points
# -----------------------------------------------------------

plt.scatter(
    [x0, x1, x2],
    [f(x0), f(x1), f(x2)],
    facecolors='none',
    edgecolors='#d62728',
    s=25,
    linewidths=1.2,
    zorder=5
)


# -----------------------------------------------------------
# Tangent-axis intersection points
# -----------------------------------------------------------

plt.scatter(
    [x1, x2],
    [0, 0],
    facecolors='none',
    edgecolors='#2ca02c',
    s=25,
    linewidths=1.2,
    zorder=5
)


# -----------------------------------------------------------
# Labels
# -----------------------------------------------------------

plt.annotate(
    f'$x_0 = {x0:.1f}$',
    (x0, f(x0)),
    textcoords="offset points",
    xytext=(-15, -15),
    ha='center'
)

plt.annotate(
    f'$x_1 = {x1:.1f}$',
    (x1, f(x1)),
    textcoords="offset points",
    xytext=(15, 10),
    ha='center'
)

plt.annotate(
    f'$x_2 = {x2:.2f}$',
    (x2, f(x2)),
    textcoords="offset points",
    xytext=(15, -15),
    ha='center'
)


# -----------------------------------------------------------
# Plot formatting
# -----------------------------------------------------------

plt.xlabel('x')
plt.ylabel('f(x)')

plt.xlim(0.5, 2.5)
plt.ylim(-2.0, 3.0)

plt.grid(True, linestyle=':', alpha=0.6)

plt.title('Q-46: Newton-Raphson Iterations with Tangent Lines')

plt.legend(loc='upper left')

plt.tight_layout()

plt.savefig("Newton-Raphson.pdf")