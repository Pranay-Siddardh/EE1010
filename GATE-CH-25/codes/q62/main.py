#Code By T.Pranay
#Date:- 28 September 2026
#Question Number 62 in Chemical Engineering Gate Paper 2025


import sympy as sp
import numpy as np
import matplotlib.pyplot as plt
import scipy.signal as signal

# -----------------------------------------------------------------------------
# SYMPY FEEDBACK LOOP SIMPLIFIER & STABILITY BOUNDARY DERIVER
# -----------------------------------------------------------------------------

# Define Laplace domain variable 's' and gain 'K_cm'
s = sp.Symbol('s', complex=True)
K_cm = sp.Symbol('K_cm', real=True)

# 1. Define transfer functions
D_M = K_cm * (8 * s + 1) / (8 * s)                     # Main PI controller
D_S = 1                                                # Secondary P controller
G_1 = 1 / (2 * s + 1)                                  # Secondary process
G_2 = 2 / ((8 * s + 1) * (4 * s + 1))                  # Primary process
H1 = 1                                                 # Inner feedback path
H2 = 1                                                 # Outer feedback path

# 2. Reduce inner loop: G_CL_S = D_S*G_1 / (1 + D_S*G_1*H1)
G_CL_S = sp.cancel((D_S * G_1) / (1 + D_S * G_1 * H1))

# 3. Reduce outer loop: L(s) = D_M * G_CL_S * G_2 * H2
L = sp.cancel(D_M * G_CL_S * G_2 * H2)

# 4. Extract characteristic polynomial from numerator of 1 + L(s) = 0
num, den = sp.fraction(L)
char_poly_expr = sp.expand(den + num)

# 5. Extract polynomial coefficients [a3, a2, a1, a0]
poly = sp.Poly(char_poly_expr, s)
coeffs = poly.all_coeffs()
a3, a2, a1, a0 = coeffs[0], coeffs[1], coeffs[2], coeffs[3]

# 6. Compute Routh-Hurwitz Column 1 elements
col1_s3 = a3
col1_s2 = a2
col1_s1 = sp.simplify((a2 * a1 - a3 * a0) / a2)
col1_s0 = a0

# 7. Formulate and solve stability inequalities (Column 1 > 0)
inequalities = [
    col1_s1 > 0,
    col1_s0 > 0
]

stability_range = sp.reduce_inequalities(inequalities, K_cm)
K_min = sp.solve(sp.Eq(col1_s0, 0), K_cm)[0]
K_max = sp.solve(sp.Eq(col1_s1, 0), K_cm)[0]

# Display Formatted Output
print("============================================================")
print("     CASCADE FEEDBACK LOOP SIMPLIFIER & ROUTH SOLVER        ")
print("============================================================")
print("Inner Closed-Loop G_CL_S(s)   :", G_CL_S)
print("Simplified Open-Loop L(s)     :", L)
print("Characteristic Polynomial     :", char_poly_expr)
print("-" * 60)
print("Routh Column 1 Elements:")
print(f"  s^3 Row : {col1_s3}")
print(f"  s^2 Row : {col1_s2}")
print(f"  s^1 Row : {col1_s1}")
print(f"  s^0 Row : {col1_s0}")
print("-" * 60)
print("Stability Inequalities Derived:")
print(f"  s^1 Condition : {col1_s1 > 0}")
print(f"  s^0 Condition : {col1_s0 > 0}")
print("-" * 60)
print("Combined Stability Range      :", stability_range)
print(f"Lower Bound (K_cm min)         : {K_min}")
print(f"Upper Bound (K_cm max)         : {K_max}")
print(f"Final Rounded Upper Target     : {int(K_max)}")
print("============================================================")


# Time vector (0 to 25 seconds)
t = np.linspace(0, 25, 1000)

# Gains to compare
gains = [-3, 3, 20]
styles = [
    {'color': '#d62728', 'linestyle': '--', 'label': '$K_{cM} = -3$ (Unstable: $K_{cM} < 0$)'},
    {'color': '#2ca02c', 'linestyle': '-',  'label': '$K_{cM} = 3$ (Stable: $0 < K_{cM} < 10$)'},
    {'color': '#1f77b4', 'linestyle': '-.', 'label': '$K_{cM} = 12$ (Unstable: $K_{cM} > 10$)'}
]

plt.figure(figsize=(10, 6), dpi=100)

for K, style in zip(gains, styles):
    # Closed-loop transfer function: T(s) = K / (32s^3 + 40s^2 + 8s + K)
    num = [K]
    den = [32, 40, 8, K]
    sys = signal.TransferFunction(num, den)
    
    # Compute unit step response
    t_out, y_out = signal.step(sys, T=t)
    
    plt.plot(t_out, y_out, label=style['label'], color=style['color'], 
             linestyle=style['linestyle'], linewidth=2)

# Reference step input line
plt.axhline(1.0, color='black', linestyle=':', alpha=0.7, label='Unit Step Reference ($r=1$)')
plt.axhline(0.0, color='gray', linestyle='-', alpha=0.3)

# Formatting plot
plt.title('Cascade System Step Response Across Stability Regimes', fontsize=14, fontweight='bold', pad=12)
plt.xlabel('Time (seconds)', fontsize=12)
plt.ylabel('Process Response $y(t)$', fontsize=12)
plt.xlim(0, 25)
plt.ylim(-5, 15)  # Truncate vertical axis so stable/oscillatory curves remain readable
plt.grid(True, linestyle='--', alpha=0.6)
plt.legend(fontsize=11, loc='upper left')
plt.tight_layout()

# Display plot
plt.savefig("response-plot.pdf")
print("Response Graph Generated as response-plot.pdf")
