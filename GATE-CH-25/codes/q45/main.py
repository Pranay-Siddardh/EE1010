#Code By T.Pranay
#Date:- 28 September 2026
#Question Number 45 in Chemical Engineering Gate Paper 2025

import numpy as np

# Define a 2x2 square matrix
A = np.array([[5, 2],
              [3, 4]])

# 1. Compute Matrix Trace using np.trace()
trace_A = np.trace(A)

# 2. Compute actual eigenvalues using np.linalg.eig()
eigenvalues, eigenvectors = np.linalg.eig(A)

# Unpack individual eigenvalues
lambda_1 = eigenvalues[0]
lambda_2_actual = eigenvalues[1]

# 3. Sum of calculated eigenvalues
sum_eigenvalues = np.sum(eigenvalues)

# 4. Calculate second eigenvalue using formula: λ_2 = Tr(A) - λ_1
lambda_2_calculated = trace_A - lambda_1

# Check equality verification
is_sum_equal = np.isclose(sum_eigenvalues, trace_A)
is_lambda2_equal = np.isclose(lambda_2_actual, lambda_2_calculated)

# Display Formatted Output
print("============================================================")
print("          MATRIX EIGENVALUES & TRACE RELATIONSHIP           ")
print("============================================================")
print("Matrix A:")
print(A)
print("-" * 60)
print(f"Matrix Trace Tr(A)                     : {trace_A}")
print(f"Actual Eigenvalues (np.linalg.eig)     : {eigenvalues}")
print(f"Sum of Eigenvalues (λ_1 + λ_2)         : {sum_eigenvalues:.4f}")
print("-" * 60)
print(f"Is Sum of Eigenvalues == Trace?        : {is_sum_equal}")
print("-" * 60)
print(f"First Eigenvalue (λ_1)                 : {lambda_1:.4f}")
print(f"Second Eigenvalue Actual (λ_2)         : {lambda_2_actual:.4f}")
print(f"Second Eigenvalue Calculated (Tr - λ_1): {lambda_2_calculated:.4f}")
print(f"Is Calculated λ_2 == Actual λ_2?       : {is_lambda2_equal}")
print("============================================================")
