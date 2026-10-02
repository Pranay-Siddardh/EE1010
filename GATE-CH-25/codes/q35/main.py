#Code By T.Pranay
#Date:- 28 September 2026
#Question Number 35 in Chemical Engineering Gate Paper 2025

import numpy as np
import matplotlib.pyplot as plt

# 1. Direct analytical results
area_E = 0.25                            # Integral of (1 - 2t) from 0 to 0.5
integral_tE = 1.0 / 24.0                 # Integral of t*(1 - 2t) from 0 to 0.5
t_avg = integral_tE / area_E             # Mean residence time bar(t) = 1/6 min

print(f"Area under E(t) dt         = {area_E}")
print(f"Integral of t*E(t) dt       = {integral_tE:.6f}")
print(f"Mean Residence Time (t_avg) = {t_avg:.4f} min ({t_avg * 60:.2f} s)")
print(f"Rounded Answer              = {t_avg:.3f} min")

# 2. Evaluation arrays
t = np.linspace(0, 0.5, 500)
E_norm = 4.0 - 8.0 * t                   # Normalized E(t) = (1 - 2t) / 0.25

# 3. Plotting E(t) and Mean Residence Time
fig, ax = plt.subplots(figsize=(8, 4.5), dpi=100)

ax.plot(t, E_norm, color='#1f77b4', lw=2.5, label=r'Normalized $E(t) = 4 - 8t$')

# Mark the mean residence time
ax.axvline(x=t_avg, color='#d62728', linestyle='--', lw=2, label=f'Mean Lifetime $\\bar{{t}} = 0.17$ min')
ax.plot(t_avg, 4.0 - 8.0 * t_avg, 'ro', markersize=7)

# Formatting
ax.set_xlabel('Time $t$ (min)', fontsize=11)
ax.set_ylabel('Exit Age Density $E(t)$ (min$^{-1}$)', fontsize=11)
ax.set_xlim(0, 0.5)
ax.set_ylim(0, 4.2)
ax.grid(True, linestyle=':', alpha=0.6)
ax.set_title('Residence Time Distribution $E(t)$ & Mean Value', fontsize=12, fontweight='bold')
ax.legend(loc='upper right', frameon=True)

plt.tight_layout()
plt.savefig("RTD-Plot.pdf")