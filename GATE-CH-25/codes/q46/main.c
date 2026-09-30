//Code By T.Pranay
//Date:- 28 September 2026
//Question Number 46 in Chemical Engineering Gate Paper 2025

#include <stdio.h>
#include <math.h>

/* Theoretical Formulas:
   f(x)  = x^2 - x - 1
   f'(x) = 2x - 1
   x_{n+1} = x_n - (x_n^2 - x_n - 1) / (2x_n - 1)
*/

double f(double x) {
    return x * x - x - 1.0;
}

double df(double x) {
    return 2.0 * x - 1.0;
}

int main() {
    double x0 = 1.0;
    double tol = 1e-4;

    /* 1. Directly calculate x1 and x2 */
    double x1 = x0 - (f(x0) / df(x0));
    double x2 = x1 - (f(x1) / df(x1));

    /* Print main question answers (x1 and x2) */
    printf("=========================================================\n");
    printf("            PRIMARY QUESTION RESULTS (x1, x2)            \n");
    printf("=========================================================\n");
    printf("First Iteration  (x1) : %.6f\n", x1);
    printf("Second Iteration (x2) : %.6f\n", x2);

    /* 2. Count total iterations to reach tolerance limit */
    double x = x0;
    int total_iterations = 0;

    while (1) {
        double x_next = x - (f(x) / df(x));
        double error = fabs(x_next - x);
        total_iterations++;

        if (error < tol) {
            break;
        } else {
            x = x_next;
        }
    }

    /* 3. Print further calculations (Last 2 iterations only) */
    printf("\n=========================================================\n");
    printf("       FURTHER CALCULATIONS (Last 2 Iterations)          \n");
    printf("=========================================================\n");
    printf("Iter |    x_n     |   x_{n+1}   |   Error   \n");
    printf("---------------------------------------------------------\n");

    x = x0;
    for (int i = 1; i <= total_iterations; i++) {
        double x_next = x - (f(x) / df(x));
        double error = fabs(x_next - x);

        /* Print only the last 2 iterations using simple if-else */
        if (i > total_iterations - 2) {
            printf("%4d | %10.6f | %10.6f | %10.6f\n", i, x, x_next, error);
        }

        x = x_next;
    }

    printf("=========================================================\n");
    printf("Final Converged Root  : %.6f\n", x);

    return 0;
}
