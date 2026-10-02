# Code By T.Pranay
# Date:- October 2, 2026
# Question Number 62 in Chemical Engineering GATE Paper 2025: Cascade Control Stability

import numpy as np
import matplotlib.pyplot as plt

# Time vector (0 to 25 seconds)
t = np.linspace(0, 25, 1000)

def analytical_step_response(K, t_vec):
    """
    Closed-loop transfer function: T(s) = K / (32s^3 + 40s^2 + 8s + K)
    
    Analytical time response via residue theorem:
    Y(s) = 1/s + sum_i R_i / (s - p_i)
    y(t) = 1 + sum_i R_i * exp(p_i * t)
    
    where p_i are roots of 32s^3 + 40s^2 + 8s + K = 0
    and R_i = K / [p_i * P'(p_i)] with P'(s) = 96s^2 + 80s + 8
    """
    poly_coeffs = [32.0, 40.0, 8.0, float(K)]
    roots = np.roots(poly_coeffs)
    
    # Analytical residues
    residues = [K / (p * (96.0 * p**2 + 80.0 * p + 8.0)) for p in roots]
    
    # Exact step response signal
    y = np.ones_like(t_vec, dtype=complex)
    for r, p in zip(residues, roots):
        y += r * np.exp(p * t_vec)
        
    return y.real

# Gains & visual styles:
# K_cM = 10: Blue dotted line
# K_cM = 16: Solid orange line replacing K_cM = 12
configs = [
    {'K': -3, 'color': '#d62728', 'ls': '--', 'lw': 2.0, 'label': '$K_{cM} = -3$ (Unstable: $K_{cM} < 0$)'},
    {'K': 3,  'color': '#2ca02c', 'ls': '-',  'lw': 2.0, 'label': '$K_{cM} = 3$ (Stable: $0 < K_{cM} < 10$)'},
    {'K': 10, 'color': '#1f77b4', 'ls': ':',  'lw': 2.5, 'label': '$K_{cM} = 10$ (Limiting / Sustained Oscillation)'},
    {'K': 16, 'color': '#ff7f0e', 'ls': '-',  'lw': 2.0, 'label': '$K_{cM} = 16$ (Unstable: $K_{cM} > 10$)'}
]

plt.figure(figsize=(10, 6), dpi=100)

for cfg in configs:
    y_out = analytical_step_response(cfg['K'], t)
    plt.plot(t, y_out, label=cfg['label'], color=cfg['color'], 
             linestyle=cfg['ls'], linewidth=cfg['lw'])

# Reference step input line
plt.axhline(1.0, color='black', linestyle=':', alpha=0.7, label='Unit Step Reference ($r=1$)')
plt.axhline(0.0, color='gray', linestyle='-', alpha=0.3)

# Formatting plot
plt.title('Cascade System Step Response Across Stability Regimes', fontsize=13, fontweight='bold', pad=12)
plt.xlabel('Time (seconds)', fontsize=11)
plt.ylabel('Process Response $y(t)$', fontsize=11)
plt.xlim(0, 25)
plt.ylim(-5, 15)
plt.grid(True, linestyle='--', alpha=0.6)
plt.legend(fontsize=10, loc='upper left')
plt.tight_layout()

plt.savefig("Response-Plot.pdf")