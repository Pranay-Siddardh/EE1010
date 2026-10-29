
import os
import shutil
import subprocess

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

# ==================================================
# 1. SURFACE: z^2 = 2x^2 - y^2
# ==================================================
x = np.linspace(-2, 2, 180)
y = np.linspace(-2, 2, 180)
X, Y = np.meshgrid(x, y)

Z2 = 2 * X**2 - Y**2
Z2[Z2 < 0] = np.nan
Z = np.sqrt(Z2)

# ==================================================
# 2. POINT P
# ==================================================
P = np.array([1.0, 0.0, np.sqrt(2.0)])

# ==================================================
# 3. UNIT NORMALS n1 AND -n1
# ==================================================
n1 = np.array([
    2 / np.sqrt(6),
    0.0,
    -1 / np.sqrt(3)
])

n2 = -n1

# ==================================================
# 4. TANGENT PLANE
# Equation: z = sqrt(2)*x
# ==================================================
xp = np.linspace(-1.5, 1.5, 35)
yp = np.linspace(-1.5, 1.5, 35)
XP, YP = np.meshgrid(xp, yp)
ZP = np.sqrt(2.0) * XP

# ==================================================
# 5. TANGENT DIRECTIONS
# ==================================================
v1 = np.array([0.0, 1.0, 0.0])
v2 = np.array([1.0, 0.0, np.sqrt(2.0)])
v2 = v2 / np.linalg.norm(v2)

# ==================================================
# 6. CREATE 3D PLOT
# ==================================================
fig = plt.figure(figsize=(15, 11))
ax = fig.add_subplot(111, projection="3d")

# Surface sheets
ax.plot_surface(
    X, Y, Z,
    color="deepskyblue",
    alpha=0.20,
    linewidth=0
)

ax.plot_surface(
    X, Y, -Z,
    color="deepskyblue",
    alpha=0.20,
    linewidth=0
)

# Tangent plane
ax.plot_surface(
    XP, YP, ZP,
    color="lightgreen",
    alpha=0.40,
    linewidth=0
)

# Point P
ax.scatter(
    P[0], P[1], P[2],
    color="black",
    s=65,
    depthshade=False
)

ax.text(
    1.05, 0.08, np.sqrt(2) + 0.15,
    r"$P=(1,0,\sqrt{2})$",
    fontsize=11,
    color="black"
)

# ==================================================
# 7. DRAW NORMAL VECTORS
# Both arrows start at P.
# Arrow lengths are scaled for visibility.
# ==================================================
L = 1.35

# n1
ax.quiver(
    P[0], P[1], P[2],
    *(L * n1),
    color="red",
    linewidth=3,
    arrow_length_ratio=0.15
)

ax.text(
    *(P + L * n1 + np.array([0.05, 0.05, 0.18])),
    r"$\mathbf{n}_1="
    r"\left(\frac{2}{\sqrt{6}},0,"
    r"-\frac{1}{\sqrt{3}}\right)$",
    color="red",
    fontsize=10
)

# -n1
ax.quiver(
    P[0], P[1], P[2],
    *(L * n2),
    color="purple",
    linewidth=3,
    arrow_length_ratio=0.15
)

ax.text(
    *(P + L * n2 + np.array([0.05, 0.05, -0.22])),
    r"$-\mathbf{n}_1="
    r"\left(-\frac{2}{\sqrt{6}},0,"
    r"\frac{1}{\sqrt{3}}\right)$",
    color="purple",
    fontsize=10
)

# ==================================================
# 8. DRAW TANGENT VECTORS
# ==================================================
T = 0.85

ax.quiver(
    P[0], P[1], P[2],
    *(T * v1),
    color="blue",
    linewidth=2.5,
    arrow_length_ratio=0.18
)

ax.text(
    *(P + T * v1 + np.array([0.02, 0.06, 0.08])),
    r"$v_1=(0,1,0)$",
    color="blue",
    fontsize=11
)

ax.quiver(
    P[0], P[1], P[2],
    *(T * v2),
    color="darkorange",
    linewidth=2.5,
    arrow_length_ratio=0.18
)

ax.text(
    *(P + T * v2 + np.array([0.02, 0.02, 0.10])),
    r"$v_2=\left(\frac{1}{\sqrt{3}},0,"
    r"\sqrt{\frac{2}{3}}\right)$",
    color="darkorange",
    fontsize=10
)

# ==================================================
# 9. AXES AND VIEW
# ==================================================
ax.set_xlabel("x", labelpad=10)
ax.set_ylabel("y", labelpad=10)
ax.set_zlabel("z", labelpad=10)

ax.set_title(
    "Quadratic Surface: Tangent Plane and Normals",
    pad=20,
    fontsize=14
)

ax.set_xlim(-2, 2)
ax.set_ylim(-2, 2)
ax.set_zlim(-3, 3)

ax.set_box_aspect((1, 1, 1.3))
ax.view_init(elev=24, azim=-55)
ax.grid(True)

# Legend
legend_items = [
    Line2D([0], [0], color="red", lw=3,
           label=r"$\mathbf{n}_1$"),
    Line2D([0], [0], color="purple", lw=3,
           label=r"$-\mathbf{n}_1$"),
    Line2D([0], [0], color="blue", lw=3,
           label="Tangent direction v1"),
    Line2D([0], [0], color="darkorange", lw=3,
           label="Tangent direction v2")
]

ax.legend(handles=legend_items, loc="upper left")

# ==================================================
# 10. SAVE PDF
# ==================================================
plt.tight_layout()

pdf_path = os.path.abspath("graph.pdf")

try:
    fig.savefig(
        pdf_path,
        format="pdf",
        bbox_inches="tight"
    )
    print(f"PDF saved successfully: {pdf_path}")
except Exception as error:
    print(f"Could not save PDF: {error}")
    plt.close(fig)
    raise

plt.close(fig)

# ==================================================
# 11. OPEN PDF IN TERMUX
# ==================================================
if shutil.which("termux-open"):
    try:
        subprocess.run(
            ["termux-open", pdf_path],
            check=True
        )
        print("Opening graph.pdf...")
    except (subprocess.CalledProcessError, OSError) as error:
        print(f"Could not open PDF automatically: {error}")
        print(f"Open it manually: {pdf_path}")
else:
    print("termux-open was not found.")
    print(f"PDF is saved at: {pdf_path}")
    print("Try: termux-open graph.pdf")

