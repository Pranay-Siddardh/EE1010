# Code By T.Pranay
# Date:- October 2, 2026
# Question Number 60 in Chemical Engineering GATE Paper 2025: FOPDT Model Fitting

import numpy as np
import matplotlib.pyplot as plt

# Time domain grid (minutes)
t = np.linspace(0, 35, 1000)

# FOPDT & Maximum Slope Method Parameters
K = 2.0
t_i = 6.0
y_i = 0.528
S = 0.1472
theta_m = 2.41
tau_m = 13.59  # theta_m + tau_m = 16.0 min

# 1. Analytical Exact Response for G(s) = 2 / ((4s+1)(3s+1)(2s+1))
# Direct closed-form time domain solution:
y_exact = 2.0 - 16.0 * np.exp(-t / 4.0) + 18.0 * np.exp(-t / 3.0) - 4.0 * np.exp(-t / 2.0)

# 2. Analytical FOPDT Model Step Response: y_FOPDT(t)
y_fopdt = np.where(t >= theta_m, K * (1.0 - np.exp(-(t - theta_m) / tau_m)), 0.0)

# 3. Maximum Slope Tangent Line at Inflection Point
y_tangent = y_i + S * (t - t_i)

# Plotting Setup
plt.figure(figsize=(10, 6), dpi=100)

# Continuous Curves
plt.plot(t, y_exact, color='#0000d6', lw=2.5, label=r'Exact Process Response $y(t)$')
plt.plot(t, y_fopdt, color='#d60000', ls='--', lw=2.0, label=r'FOPDT Fit Model $y_{FOPDT}(t)$')
plt.plot(t, y_tangent, color='#008000', ls='-.', lw=1.8, label=f'Max Slope Tangent ($S = {S}$)')

# Reference Lines & Projections
plt.axhline(K, color='black', ls=':', lw=1.2, label=f'Steady State Gain (K = {int(K)})')
plt.vlines(t_i, 0, y_i, color='gray', ls=':', lw=1.0)

# Feature Point Markers matching document colors
plt.scatter([t_i], [y_i], color='black', s=40, zorder=5, label=f'Inflection Point $t_i = {t_i}$ min')
plt.scatter([theta_m], [0], color='green', s=40, zorder=5, label=f'Apparent Dead Time $\\theta_m = {theta_m}$ min')
plt.scatter([theta_m + tau_m], [K], color='magenta', s=40, zorder=5, label=r'$\theta_m + \tau_m = 16.0$ min')

# On-Graph Annotations
plt.annotate(f'Inflection Point\n$(t_i = {t_i}, y_i = {y_i})$', xy=(t_i, y_i), xytext=(t_i + 2.5, y_i - 0.12),
             arrowprops=dict(arrowstyle='->', lw=1.0), fontsize=9, fontweight='bold')
plt.annotate(r'Dead Time $\theta_m = 2.41$ min', xy=(theta_m, 0), xytext=(theta_m - 2.0, 0.22),
             arrowprops=dict(arrowstyle='->', lw=1.0), fontsize=9, fontweight='bold', color='green')

# Formatting & Grid
plt.xlim(0, 35)
plt.ylim(-0.2, 2.2)
plt.xlabel('Time $t$ (minutes)', fontsize=11)
plt.ylabel('Process Response $y(t)$', fontsize=11)
plt.title('GATE 2025 ChE: Step Response & Maximum Slope FOPDT Model Fit', fontsize=12, fontweight='bold')
plt.grid(True, linestyle=':', alpha=0.6)
plt.legend(loc='lower right', frameon=True, fontsize=9.5)

plt.tight_layout()
plt.savefig("FOPDT-Modelling.pdf")