#Code By T.Pranay
#Date:- 28 September 2026
#Question Number 12 in Chemical Engineering Gate Paper 2025

import numpy as np

# Create initial 1D arrays
a = np.array([2**0.5, 2**-0.5, 1.0])
b = np.array([2**-0.5, 2**0.5, -1.0])

# Reshape into (3, 1) column vectors
vector_a = a.reshape(3, 1)
vector_b = b.reshape(3, 1)

# Calculate dot product
# Dot product can be calculated as (a)Transpose.b as a matrx multiplication

dot_product = a.T@b

print("Vector A:\n", vector_a)
print("\nVector B:\n", vector_b)
print(f"\nDot Product: {dot_product:.2f}")
