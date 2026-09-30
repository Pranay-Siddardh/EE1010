//Code By T.Pranay
//Date:- 28 September 2026
//Question Number 14 in Chemical Engineering Gate Paper 2025

#include <stdio.h>
#include <stdlib.h>

int main() {
    /* Initialize ball arrays: Blue (0 to 6) and Green (7 to 9) */
    int blue[7]  = {0, 1, 2, 3, 4, 5, 6};
    int green[3] = {7, 8, 9};

    /* Merge all 10 balls into a single container */
    int box[10];
    for (int k = 0; k < 7; k++) {
        box[k] = blue[k];
    }
    for (int k = 0; k < 3; k++) {
        box[7 + k] = green[k];
    }

    /* Track total combinations and favorable pairs */
    int total_possible = 0;
    int favorable_pairs = 0;

    /* Open data file for writing results */
    FILE *fp = fopen("main.dat", "w");
    if (fp == NULL) {
        printf("Error: Unable to create file main.dat\n");
        return 1;
    }

    /* Generate and write favorable ordered pairs (1 Green and 1 Blue) */
    fprintf(fp, "# Top Array: Favorable Ordered Pairs (1 Green & 1 Blue)\n[");
    int first_fav = 1;
    for (int i = 0; i < 10; i++) {
        for (int j = 0; j < 10; j++) {
            if (i != j) {
                int ball1 = box[i];
                int ball2 = box[j];

                int ball1_is_blue  = (ball1 >= 0 && ball1 <= 6);
                int ball1_is_green = (ball1 >= 7 && ball1 <= 9);
                int ball2_is_blue  = (ball2 >= 0 && ball2 <= 6);
                int ball2_is_green = (ball2 >= 7 && ball2 <= 9);

                if ((ball1_is_green && ball2_is_blue) || (ball1_is_blue && ball2_is_green)) {
                    favorable_pairs++;
                    if (!first_fav) {
                        fprintf(fp, ", ");
                    }
                    fprintf(fp, "(%d, %d)", ball1, ball2);
                    first_fav = 0;
                }
            }
        }
    }
    fprintf(fp, "]\n\n");

    /* Generate and write all possible ordered pairs without replacement */
    fprintf(fp, "# Bottom Array: All Possible Pickings (All Ordered Pairs)\n[");
    int first_all = 1;
    for (int i = 0; i < 10; i++) {
        for (int j = 0; j < 10; j++) {
            if (i != j) {
                total_possible++;
                if (!first_all) {
                    fprintf(fp, ", ");
                }
                fprintf(fp, "(%d, %d)", box[i], box[j]);
                first_all = 0;
            }
        }
    }
    fprintf(fp, "]\n");

    /* Close the file connection */
    fclose(fp);

    /* Calculate experimental probability */
    double probability = (double)favorable_pairs / total_possible;

    /* Output console summary and theoretical verification */
    printf("==================================================\n");
    printf("Total possible pickings (ordered pairs): %d\n", total_possible);
    printf("Number of favorable ordered pairs (1 Green & 1 Blue): %d\n", favorable_pairs);
    printf("Probability = favorable / possible = %d / %d = %.4f (or 7/15)\n", 
           favorable_pairs, total_possible, probability);
    printf("Verification: The result is verified with the combination formula (7C1 * 3C1) / 10C2 = (7 * 3) / 45 = 21/45 = 7/15 (0.4667).\n");
    printf("==================================================\n");
    printf("Data containing ordered pairs successfully exported to 'main.dat'.\n");

    return 0;
}
