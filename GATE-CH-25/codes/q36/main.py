#Code By T.Pranay
#Date:- 28 September 2026
#Question Number 36 in Chemical Engineering Gate Paper 2025

import sympy as sp

# Define symbolic variables
x, y, a, b = sp.symbols('x y a b')

# Define vector components
v_x = a * x
v_y = -b * y

# Calculate partial derivatives
dv_x_dx = sp.diff(v_x, x)  # ∂(v_x)/∂x
dv_y_dy = sp.diff(v_y, y)  # ∂(v_y)/∂y

# Calculate divergence: ∇ · v
div_v = dv_x_dx + dv_y_dy

# Solve for condition where ∇ · v = 0
solution = sp.solve(sp.Eq(div_v, 0), a)

# Formatted Output Display
print(f"Vector Field v            : ({v_x}) i^ + ({v_y}) j^")
print(f"Divergence (∇ · v)        : {div_v}")
print(f"Zero Divergence Equation  : {div_v} = 0")
print(f"Condition for Zero Div    : a = {solution[0]}")