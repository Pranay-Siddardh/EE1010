#code bty pranay
#date 2-11-26
import numpy as np
import matplotlib.pyplot as plt
import subprocess

# Discrete-time index
n = np.arange(-5, 16)

# Input signal: x[n] = delta[n] - (1/3)delta[n-1]
x = np.zeros(len(n))
x[n == 0] = 1
x[n == 1] = -1/3

# Output signal: y[n] = (1/2)^n u[n]
y = np.zeros(len(n))
y[n >= 0] = (1/2.0)**n[n >= 0]

# Create figure
fig, ax = plt.subplots(2, 1, figsize=(11, 8))

# Input signal
markerline, stemlines, baseline = ax[0].stem(n, x)
plt.setp(markerline, markersize=7)
plt.setp(stemlines, linewidth=1.8)

ax[0].set_title("Input Signal x[n]", fontsize=14)
ax[0].set_xlabel("Discrete Time Index n")
ax[0].set_ylabel("Amplitude")
ax[0].set_xticks(n)
ax[0].grid(True, which='both', linestyle='--', alpha=0.7)

# Name individual points
for i in range(len(n)):
    if x[i] != 0:
        ax[0].annotate(
            f"({n[i]}, {x[i]:.3f})",
            (n[i], x[i]),
            textcoords="offset points",
            xytext=(0, 10 if x[i] > 0 else -18),
            ha='center',
            fontsize=8
        )

# Output signal
markerline, stemlines, baseline = ax[1].stem(n, y)
plt.setp(markerline, markersize=7)
plt.setp(stemlines, linewidth=1.8)

ax[1].set_title("Output Signal y[n]", fontsize=14)
ax[1].set_xlabel("Discrete Time Index n")
ax[1].set_ylabel("Amplitude")
ax[1].set_xticks(n)
ax[1].grid(True, which='both', linestyle='--', alpha=0.7)

# Name individual points
for i in range(len(n)):
    if y[i] != 0:
        ax[1].annotate(
            f"({n[i]}, {y[i]:.3f})",
            (n[i], y[i]),
            textcoords="offset points",
            xytext=(0, 9),
            ha='center',
            fontsize=7
        )

# Layout and save
plt.tight_layout()
plt.savefig("graph.pdf", format="pdf", bbox_inches="tight")

print("Graph saved successfully as graph.pdf")

# Open PDF using Termux
subprocess.run(["termux-open", "graph.pdf"], check=False)


