//Code By T.Pranay
//Date:- 28 September 2026
//Question Number 37 in Chemical Engineering Gate Paper 2025

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Generates n random numbers directly in [0, a] and saves to filename
void uniform(const char *filename, int n, double a) {
    FILE *fp = fopen(filename, "w");
    if (fp == NULL) {
        perror("Error opening file for writing");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < n; i++) {
        // Direct uniform sample in [0, a]
        double x = a * ((double)rand() / RAND_MAX);
        fprintf(fp, "%.6f\n", x);
    }

    fclose(fp);
}

int main(void) {
    int n = 5000;
    double a = 5.0;
    const char *filename = "main.dat";

    // Seed pseudo-random generator
    srand(time(NULL)); 

    // Generate N uniform random numbers in [0, 5] directly
    uniform(filename, n, a);
    printf("Successfully exported %d random numbers in [0, %.1f] to '%s'\n", n, a, filename);

    return 0;
}