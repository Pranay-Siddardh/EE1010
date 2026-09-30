# Code By T.Pranay
# Date:- 28 September 2026
# Question Number 60 in Chemical Engineering GATE Paper 2025

import sympy as sp
import numpy as np
import matplotlib.pyplot as plt

# Define symbolic time variable
t = sp.Symbol('t', real=True, positive=True)

# Define step response function y(t) for t >= 1
y = 2 * (1 - (1 + (t - 1) / 5) * sp.exp(-(t - 1) / 5))

# 1. First and second time derivatives
dy_dt = sp.diff(y, t)
d2y_dt2 = sp.diff(dy_dt, t)

# 2. Solve d2y/dt2 = 0 to find inflection point t_i
t_i_solutions = sp.solve(d2y_dt2, t)
t_i = t_i_solutions[0]

# 3. Compute maximum slope S and height y_i at inflection point
S = sp.simplify(dy_dt.subs(t, t_i))
y_i = sp.simplify(y.subs(t, t_i))

# 4. Derive apparent model dead time theta_m (baseline intercept)
theta_m = sp.simplify(t_i - (y_i / S))

# 5. Derive apparent time constant tau_m
process_gain_K = 2
tau_m = sp.simplify(process_gain_K / S)

# 6. Calculate tau_m / theta_m ratio
ratio = sp.simplify(tau_m / theta_m)

# Numeric conversions
e_val = float(sp.E)
t_i_num = float(t_i)
S_num = float(S)
y_i_num = float(y_i)
theta_m_num = float(theta_m)
tau_m_num = float(tau_m)
ratio_num = float(ratio)

# Display Formatted Console Output
print("============================================================")
print("     FOPDT MODEL FIT VIA SYMPY (MAXIMUM SLOPE METHOD)       ")
print("============================================================")
print(f"Inflection Point t_i         : {t_i} min  (~ {t_i_num:.4f})")
print(f"Maximum Slope S              : {S}  (~ {S_num:.4f})")
print(f"Height at Inflection y(t_i)  : {y_i}  (~ {y_i_num:.4f})")
print("-" * 60)
print(f"Apparent Dead Time (theta_m) : {theta_m}  (~ {theta_m_num:.4f} min)")
print(f"Apparent Time Constant (tau_m): {tau_m}  (~ {tau_m_num:.4f} min)")
print("-" * 60)
print(f"Symbolic Ratio (tau_m/theta_m): {ratio}")
print(f"Evaluated Decimal Ratio      : {ratio_num:.4f}")
print(f"Final Rounded Ratio (2 d.p.) : {ratio_num:.2f}")
print("============================================================")


# =============================================================================
# VISUALIZATION: EXACT VS FOPDT MODEL & GRAPHICAL FIT INDICATORS
# =============================================================================

# Define numerical time vector from t = 0 to 40 min
t_vals = np.linspace(0, 40, 1000)

# 1. Compute Exact Step Response y(t)
y_exact = np.where(
    t_vals >= 1.0, 
    2.0 * (1.0 - (1.0 + (t_vals - 1.0) / 5.0) * np.exp(-(t_vals - 1.0) / 5.0)), 
    0.0
)

# 2. Compute FOPDT Approximation Step Response y_FOPDT(t)
y_fopdt = np.where(
    t_vals >= theta_m_num, 
    process_gain_K * (1.0 - np.exp(-(t_vals - theta_m_num) / tau_m_num)), 
    0.0
)

# 3. Maximum Slope Tangent Line: y_tangent = y_i + S * (t - t_i)
# Plot tangent line between t = theta_m and t = theta_m + tau_m
t_tangent = np.linspace(theta_m_num - 1.0, theta_m_num + tau_m_num + 3.0, 200)
y_tangent = y_i_num + S_num * (t_tangent - t_i_num)

# Plotting setup
plt.figure(figsize=(11, 7), dpi=100)

# Plot responses
plt.plot(t_vals, y_exact, 'b-', linewidth=2.5, label='Exact Process Response $y(t)$')
plt.plot(t_vals, y_fopdt, 'r--', linewidth=2.0, label=r'FOPDT Fit Model $y_{FOPDT}(t)$')
plt.plot(t_tangent, y_tangent, color='green', linestyle='-.', linewidth=1.8, 
         label=f'Max Slope Tangent ($S = {S_num:.4f}$)')

# Reference line for Process Gain K = 2.0
plt.axhline(process_gain_K, color='black', linestyle=':', alpha=0.7, label=f'Steady State Gain ($K = {process_gain_K}$)')
plt.axhline(0.0, color='gray', linestyle='-', alpha=0.3)

# Key Point Markers
plt.plot(t_i_num, y_i_num, 'ko', markersize=7, label=f'Inflection Point $t_i = {t_i_num:.1f}$ min')
plt.plot(theta_m_num, 0.0, 'go', markersize=7, label=f'Apparent Dead Time $\\theta_m = {theta_m_num:.2f}$ min')
plt.plot(theta_m_num + tau_m_num, process_gain_K, 'mo', markersize=7, label=f'\\theta_m + \\tau_m = {theta_m_num + tau_m_num:.1f}$ min')

# Vertical guidelines for parameters
plt.vlines(x=theta_m_num, ymin=0, ymax=y_exact[np.argmin(np.abs(t_vals - theta_m_num))], 
           colors='green', linestyles=':', alpha=0.8)
plt.vlines(x=t_i_num, ymin=0, ymax=y_i_num, colors='black', linestyles=':', alpha=0.6)

# Graph Annotations
plt.annotate(
    f'Inflection Point\n($t_i={t_i_num:.0f}, y_i={y_i_num:.3f}$)',
    xy=(t_i_num, y_i_num), xytext=(t_i_num + 2, y_i_num - 0.2),
    arrowprops=dict(arrowstyle='->', color='black', lw=1.2),
    fontsize=10, fontweight='bold'
)

plt.annotate(
    f'Dead Time $\\theta_m = {theta_m_num:.2f}$ min',
    xy=(theta_m_num, 0), xytext=(theta_m_num + 0.5, 0.3),
    arrowprops=dict(arrowstyle='->', color='green', lw=1.2),
    fontsize=10, color='green', fontweight='bold'
)

# Plot Formatting
plt.title('GATE 2025 ChE: Step Response & Maximum Slope FOPDT Model Fit', fontsize=13, fontweight='bold', pad=12)
plt.xlabel('Time $t$ (minutes)', fontsize=12)
plt.ylabel('Process Response $y(t)$', fontsize=12)
plt.xlim(0, 35)
plt.ylim(-0.1, 2.3)
plt.grid(True, linestyle='--', alpha=0.5)
plt.legend(loc='lower right', fontsize=10, framealpha=0.9)
plt.tight_layout()

# Save Plot
plt.savefig("FOPDT-Modelling.pdf")
print("Image Plott Saved as FOPDT-Modelling.pdf")