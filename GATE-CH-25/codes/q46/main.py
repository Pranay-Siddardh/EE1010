#Code By T.Pranay
#Date:- 28 September 2026
#Question Number 46 in Chemical Engineering Gate Paper 2025


import os
import sys
import subprocess
import numpy as np
import matplotlib.pyplot as plt

# ---------------------------------------------------------
# Step 1: Generate & Save the Newton-Raphson Plot
# ---------------------------------------------------------
print("[INFO] Generating Newton-Raphson visualization...")

# Define the function and its derivative
def f(x):
    return x**2 - x - 1

def df(x):
    return 2*x - 1

# MODIFIED: Generate points for the curve f(x) from x = 0 to 3
x_vals = np.linspace(0.0, 3.0, 500)
y_vals = f(x_vals)

# MODIFIED: Increased figure size slightly for a bigger look
plt.figure(figsize=(11, 7))
plt.plot(x_vals, y_vals, 'b-', label=r'$f(x) = x^2 - x - 1$', linewidth=2)
plt.axhline(0, color='black', linestyle='--', linewidth=0.8) # x-axis line

# Trace Newton-Raphson iterations starting at x0 = 1.0
x_n = 1.0
colors = ['red', 'green', 'purple', 'orange']

# Plot 3 iterations to visually show convergence
for i in range(3):
    y_n = f(x_n)
    slope = df(x_n)
    
    # Calculate next x intersection
    x_next = x_n - (y_n / slope)
    
    # Draw vertical dashed line from x_n axis to curve
    plt.plot([x_n, x_n], [0, y_n], color='gray', linestyle=':', linewidth=1.5)
    
    # Draw tangent line from (x_n, y_n) meeting the x-axis at (x_next, 0)
    # MODIFIED: Adjusted domain calculation of tangent lines to fit clean within the 0 to 3 window
    x_tangent = np.linspace(0.0, 3.0, 100)
    y_tangent = slope * (x_tangent - x_n) + y_n
    plt.plot(x_tangent, y_tangent, linestyle='--', color=colors[i], 
             label=f'Tangent at $x_{i}$ ({x_n:.4f})')
    
    # Mark points
    plt.scatter([x_n], [y_n], color=colors[i], zorder=5)
    plt.scatter([x_next], [0], color=colors[i], marker='x', s=60, zorder=5)
    
    x_n = x_next

# MODIFIED: Updated title description and tightened scale limits
plt.title('Newton-Raphson Iteration Visual Tracking ($x_0 = 1$ to $3$ Domain)', fontsize=13)
plt.xlabel('x')
plt.ylabel('f(x)')

# MODIFIED: Adjusted limits to zoom in on 0 to 3 horizontally and drop empty upper spaces vertically
plt.xlim(0.0, 3.0)
plt.ylim(-2.0, 6.0) 

# MODIFIED: Clean intervals every 0.5 units for readable scaling
plt.xticks(np.arange(0.0, 3.1, 0.5))
plt.yticks(np.arange(-2.0, 6.1, 1.0))

plt.grid(True, alpha=0.3)
plt.legend(loc='upper left')

# Save the plot
output_image = "newton-raphson.pdf"
plt.savefig(output_image, dpi=300, bbox_inches='tight')
plt.close()
print(f"[SUCCESS] Visual plot saved to: '{output_image}'")

# ---------------------------------------------------------
# Step 2: Execute Existing main.c Using Subprocess
# ---------------------------------------------------------
print("\n[INFO] Compiling and running 'main.c'...")

# Check if main.c exists in the current directory before proceeding
if not os.path.exists("main.c"):
    print("[ERROR] 'main.c' file not found in the current directory!", file=sys.stderr)
    sys.exit(1)

# Combined command requested to compile, execute, and delete binary
command = "gcc main.c -o main -lm && ./main && rm main"

try:
    # shell=True handles chained operators (&&) natively
    result = subprocess.run(
        command,
        shell=True,
        check=True,
        capture_output=True,
        text=True
    )
    
    # Print output from your compiled C execution block
    print(result.stdout)

except subprocess.CalledProcessError as e:
    print(f"[ERROR] Terminal pipeline sequence failed with exit code {e.returncode}", file=sys.stderr)
    print(f"Error Log:\n{e.stderr}", file=sys.stderr)
