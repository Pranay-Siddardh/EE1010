
import numpy as np
import matplotlib.pyplot as plt
import subprocess

# ==========================================
# 1. Sampling parameters
# ==========================================
Fs = 40
Ts = 1 / Fs
N = 10

n = np.arange(N)
ts = n * Ts

# Dense time axis for smooth continuous signals
t = np.linspace(0, (N - 1) * Ts, 5000)

# ==========================================
# 2. Continuous-time signals
# ==========================================
x1 = np.cos(20 * np.pi * t)       # 10 Hz
x2 = np.cos(100 * np.pi * t)      # 50 Hz

# ==========================================
# 3. Sampled signals
# ==========================================
s1 = np.round(np.cos(20 * np.pi * ts), 10)
s2 = np.round(np.cos(100 * np.pi * ts), 10)

# ==========================================
# 4. Print all ten samples
# ==========================================
print("\nFIRST TEN SAMPLES")
print("=" * 52)
print(f"{'n':>3} {'Time(s)':>10} {'x1[n]':>12} {'x2[n]':>12}")
print("-" * 52)

for i in range(N):
    print(f"{n[i]:3d} {ts[i]:10.3f} "
          f"{s1[i]:12.3f} {s2[i]:12.3f}")

# ==========================================
# 5. Verify options A, B, C and D
# ==========================================
A = np.all(s1[0:3] > s2[0:3])
B = np.all(s1[7:10] > s2[7:10])
C = np.all(s2 > s1)
D = np.all(s1[3:7] == s2[3:7])

print("\nOPTION-WISE VERIFICATION")
print("=" * 52)
print(f"(A) First three: x1 > x2        : {A}")
print(f"(B) Last three: x1 > x2         : {B}")
print(f"(C) All samples: x2 > x1        : {C}")
print(f"(D) Fourth to seventh: x1 = x2  : {D}")

print("\nFINAL ANSWER")
print("Correct option: D" if D and not (A or B or C)
      else "Check option results above.")

# ==========================================
# 6. Plot both sinusoids on the SAME graph
# ==========================================
fig, ax = plt.subplots(figsize=(14, 8))

# Continuous curves in different colors
ax.plot(
    t, x1,
    color='blue', linewidth=2,
    label=r'$x_1(t)=\cos(20\pi t)$, 10 Hz'
)
ax.plot(
    t, x2,
    color='red', linewidth=1.8,
    label=r'$x_2(t)=\cos(100\pi t)$, 50 Hz'
)

# Stem plot for x1
m1, st1, b1 = ax.stem(
    ts, s1,
    linefmt='b-', markerfmt='bo', basefmt='k-',
    label=r'Samples of $x_1[n]$'
)

# Stem plot for x2
m2, st2, b2 = ax.stem(
    ts, s2,
    linefmt='r--', markerfmt='rs', basefmt=' ',
    label=r'Samples of $x_2[n]$'
)

# Style the stem markers and lines
plt.setp(st1, linewidth=1.5, alpha=0.8)
plt.setp(st2, linewidth=1.5, alpha=0.8)
plt.setp(m1, markersize=7)
plt.setp(m2, markersize=6)

# ==========================================
# 7. Mark and annotate the first three samples
# ==========================================
for i in range(3):
    ax.annotate(
        f'x1[{i}]={s1[i]:.0f}',
        xy=(ts[i], s1[i]),
        xytext=(8, 15),
        textcoords='offset points',
        color='blue',
        fontsize=9,
        fontweight='bold'
    )

    ax.annotate(
        f'x2[{i}]={s2[i]:.0f}',
        xy=(ts[i], s2[i]),
        xytext=(8, -22),
        textcoords='offset points',
        color='darkred',
        fontsize=9,
        fontweight='bold'
    )

# ==========================================
# 8. Formatting
# ==========================================
ax.set_title(
    'Two Analog Sinusoids Sampled at Fs = 40 Hz',
    fontsize=15
)
ax.set_xlabel('Time (seconds)', fontsize=12)
ax.set_ylabel('Amplitude', fontsize=12)

ax.set_xlim(-0.005, ts[-1] + 0.005)
ax.set_ylim(-1.45, 1.45)
ax.set_xticks(ts)
ax.set_xticklabels([f'{v:.3f}' for v in ts], rotation=45)

ax.grid(True, linestyle=':', alpha=0.7)
ax.axhline(0, color='black', linewidth=0.7)

ax.legend(loc='upper right', fontsize=9)
fig.tight_layout()

# ==========================================
# 9. Save PDF and open it in Termux
# ==========================================
filename = 'graph.pdf'
fig.savefig(filename, bbox_inches='tight')
plt.close(fig)

print(f"\nPlot saved successfully as {filename}")
print("Opening PDF in Termux...")

subprocess.run(['termux-open', filename], check=True)

