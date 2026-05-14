#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "squaremult.h"
#include <float.h>
#include <inttypes.h>
#include <time.h>
#include <string.h>

#define REPS 200 
#define target_key 4294967291ULL  // 32 bit key 
#define MODULUS 18446744073709551557ULL   // 64 bit modulus 

int cmp_u64(const void *a, const void *b) { return (*(uint64_t*)a > *(uint64_t*)b) - (*(uint64_t*)a < *(uint64_t*)b); }
int cmp_double(const void *a, const void *b) {
    double da = *(double*)a, db = *(double*)b;
    return (da > db) - (da < db);
}

// filters outliers from timing array using median absolute deviation, returns robust average
// keeps only values within threshold*MAD of the median to avoid skewing from cache spikes etc
uint64_t mad_median(uint64_t *arr, int n, double threshold) {
    uint64_t *sorted = malloc(n * sizeof(uint64_t));
    memcpy(sorted, arr, n * sizeof(uint64_t));
    qsort(sorted, n, sizeof(uint64_t), cmp_u64);
    uint64_t median = (n % 2 == 0)
        ? sorted[n/2-1] + (sorted[n/2] - sorted[n/2-1]) / 2
        : sorted[n/2];

    uint64_t *devs = malloc(n * sizeof(uint64_t));
    for (int i = 0; i < n; i++)
        devs[i] = arr[i] > median ? arr[i] - median : median - arr[i];
    qsort(devs, n, sizeof(uint64_t), cmp_u64);
    uint64_t mad = (n % 2 == 0)
        ? devs[n/2-1] + (devs[n/2] - devs[n/2-1]) / 2
        : devs[n/2];

    double cutoff = threshold * (double)mad;
    unsigned __int128 sum = 0; int kept = 0;
    for (int i = 0; i < n; i++) {
        uint64_t dev = arr[i] > median ? arr[i] - median : median - arr[i];
        if ((double)dev <= cutoff) {
            sum += arr[i];
            kept++;
        }
    }

    free(sorted);
    free(devs);
    return kept > 0 ? (uint64_t)(sum / kept) : median;
}

// generates a random 64 bit value by xoring shifted rand() calls
static uint64_t rng64(void) {
    return ((uint64_t)rand() << 48) ^
           ((uint64_t)rand() << 32) ^
           ((uint64_t)rand() << 16) ^
           (uint64_t)rand();
}

// generates a random ciphertext uniformly in [1, MODULUS-1] using rejection sampling
uint64_t rand_ciphertext(void) {
    uint64_t range = MODULUS - 1;
    uint64_t limit = UINT64_MAX - (UINT64_MAX % range);
    uint64_t x;
    do {
        x = rng64();
    } while (x >= limit);
    return (x % range) + 1;
}

// collects baseline timing measurements for n random ciphertexts
// does a warmup first to stabilize cache, then times each ciphertext REPS times,
// filters outliers, and writes the averaged timings to a csv
int baseline_timings(FILE *outfile, int n) {
    srand(time(NULL));

    fprintf(outfile, "c_value,timing\n");

    for (int i = 0; i < 3000; i++) {
        uint64_t c = rand_ciphertext();
        uint64_t holder = timed_square_multiply(c, target_key, MODULUS);
    }

    uint64_t *ciphertexts = malloc(n * sizeof(uint64_t));
    uint64_t *timings     = malloc(n * sizeof(uint64_t));

    for (int i = 0; i < n; i++) {
        printf("On the %d ciphertext\n", i); 
        ciphertexts[i] = rand_ciphertext();
        uint64_t *temptimings = malloc(REPS * sizeof(uint64_t)); 
        unsigned __int128 intermediate = 0;        
        
        for (int j = 0; j < REPS; j++){
            temptimings[j] = timed_square_multiply(ciphertexts[i], target_key, MODULUS);
        }
        printf("Finished reps for the %d ciphertext\n", i);
        uint64_t *sorted = malloc(REPS * sizeof(uint64_t));
        memcpy(sorted, temptimings, REPS * sizeof(uint64_t));
        qsort(sorted, REPS, sizeof(uint64_t), cmp_u64);

        int lo_idx = (int)(REPS * 0.005);
        int hi_idx = (int)(REPS * 0.995);
        uint64_t lower = sorted[lo_idx];
        uint64_t upper = sorted[hi_idx];

        uint64_t counter = 0; 
        for (int k = 0; k < REPS; k++) {
            if (temptimings[k] >= lower && temptimings[k] <= upper){
                intermediate += temptimings[k]; 
                counter+=1; 
            }
        }
        printf("Had %d clean samples\n", counter);
        timings[i] = (uint64_t)(intermediate / counter);
        free(temptimings); 
        free(sorted); 
    }

    uint64_t *sorted = malloc(n * sizeof(uint64_t));
    memcpy(sorted, timings, n * sizeof(uint64_t));
    qsort(sorted, n, sizeof(uint64_t), cmp_u64);

    int lo_idx = (int)(n * 0.005);
    int hi_idx = (int)(n * 0.995);
    uint64_t lower = sorted[lo_idx];
    uint64_t upper = sorted[hi_idx];

    free(sorted);

    for (int i = 0; i < n; i++) {
        if (timings[i] >= lower && timings[i] <= upper)
            fprintf(outfile, "%" PRIu64 ",%" PRIu64 "\n", ciphertexts[i], timings[i]);
    }

    free(ciphertexts);
    free(timings);
    return 0;
}

// the actual attack — reads baseline timings from csv and tries to recover the secret
// exponent bit by bit using kocher's variance method. for each bit position, constructs
// two candidate exponents (guess0 and guess1), times them against each ciphertext,
// and picks whichever guess produces lower residual variance against the baseline
uint64_t compute_bit(FILE *f, int n) {
    FILE *attack_stats = fopen("attack_stats.csv", "w");
    if (!attack_stats) { perror("attack_stats"); return 0; }
    fprintf(attack_stats, "0var,1var,guessedbit\n");

    uint64_t *ciphertexts = malloc(n * sizeof(uint64_t));
    uint64_t *timings     = malloc(n * sizeof(uint64_t));
    int count = 0;

    char header[256];
    fgets(header, sizeof(header), f);

    uint64_t c_val, timing;
    while (fscanf(f, "%" SCNu64 ",%" SCNu64 "\n", &c_val, &timing) == 2 && count < n) {
        ciphertexts[count] = c_val;
        timings[count]     = timing;
        count++;
    }
    printf("Count is %d, N was %d\n", count, n);

    uint64_t *samples0 = malloc(REPS * sizeof(uint64_t));
    uint64_t *samples1 = malloc(REPS * sizeof(uint64_t));
    double *adjusted_guess0 = malloc(count * sizeof(double));
    double *adjusted_guess1 = malloc(count * sizeof(double));

    srand(time(NULL) + 1);
    for (int i = 0; i < 3000; i++){
        uint64_t dummyresult = 0; 
        dummyresult = timed_square_multiply(rand_ciphertext(), target_key, MODULUS);
    }

    uint64_t curr_exp = 1;

    for (int bit = 0; bit < 32; bit++) { 
        uint64_t guess0 = (curr_exp << 1);
        uint64_t guess1 = (curr_exp << 1) + 1;

        for (int i = 0; i < count; i++) {
            if (i % 2 == 0) {
                for (int r = 0; r < REPS; r++){
                    __asm__ __volatile__("lfence" ::: "memory");
                    samples0[r] = timed_square_multiply(ciphertexts[i], guess0, MODULUS);
                }
                adjusted_guess0[i] = mad_median(samples0, REPS, 3.0);

                for (int r = 0; r < REPS; r++){
                    __asm__ __volatile__("lfence" ::: "memory"); 
                    samples1[r] = timed_square_multiply(ciphertexts[i], guess1, MODULUS);
                }
                adjusted_guess1[i] = mad_median(samples1, REPS, 3.0);
            } else {
                for (int r = 0; r < REPS; r++){
                    __asm__ __volatile__("lfence" ::: "memory");
                    samples1[r] = timed_square_multiply(ciphertexts[i], guess1, MODULUS);
                }
                adjusted_guess1[i] = mad_median(samples1, REPS, 3.0);

                for (int r = 0; r < REPS; r++){
                    __asm__ __volatile__("lfence" ::: "memory");  
                    samples0[r] = timed_square_multiply(ciphertexts[i], guess0, MODULUS);
                }
                adjusted_guess0[i] = mad_median(samples0, REPS, 3.0);
            }
        }

        double *deltas = malloc(count * sizeof(double));
        for (int i = 0; i < count; i++)
            deltas[i] = fabs(adjusted_guess0[i] - adjusted_guess1[i]);

        // only keep ciphertexts where the two guesses produce meaningfully different timings
        // low delta ciphertexts don't help discriminate so they just add noise
        double *sorted_deltas = malloc(count * sizeof(double));
        memcpy(sorted_deltas, deltas, count * sizeof(double));
        qsort(sorted_deltas, count, sizeof(double), cmp_double);
        double cutoff = sorted_deltas[(int)(count * 0.05)];
        free(sorted_deltas);

        long double mean0 = 0, var0 = 0, mean1 = 0, var1 = 0;
        int kept = 0;
        double *residuals_0 = malloc(count * sizeof(double));
        double *residuals_1 = malloc(count * sizeof(double));

        for (int i = 0; i < count; i++) {
            if (deltas[i] >= cutoff) {
                residuals_0[i] = timings[i] - adjusted_guess0[i];
                mean0 += residuals_0[i];
                residuals_1[i] = timings[i] - adjusted_guess1[i];
                mean1 += residuals_1[i];
                kept++;
            }
        }
        mean0 /= kept; mean1 /= kept;

        double mean_timings = 0;
        for (int i = 0; i < count; i++)
            if (deltas[i] >= cutoff)
                mean_timings += timings[i];
        mean_timings /= kept;
        printf("bit %d: mean_timing=%.2f, mean_guess0=%.2Lf, mean_guess1=%.2Lf, diff=%.2Lf cycles\n",
            bit, mean_timings, mean0, mean1, mean1 - mean0);

        for (int i = 0; i < count; i++) {
            if (deltas[i] >= cutoff) {
                var0 += (residuals_0[i] - mean0) * (residuals_0[i] - mean0);
                var1 += (residuals_1[i] - mean1) * (residuals_1[i] - mean1);
            }
        }
        var0 /= kept; var1 /= kept;

        fprintf(attack_stats, "%.10Lf,%.10Lf,%d\n", var0, var1, var1 < var0 ? 1 : 0);
        printf("bit %d: var0 = %Lf, var1 = %Lf, guessing %d\n",
               bit, var0, var1, var1 < var0 ? 1 : 0);

        curr_exp = (var1 < var0) ? (curr_exp << 1) + 1 : (curr_exp << 1);

        free(deltas);
        free(residuals_0);
        free(residuals_1);
    }

    fclose(attack_stats);
    printf("Recovered d = %" PRIu64 "\n", curr_exp);

    free(samples0); free(samples1);
    free(adjusted_guess0); free(adjusted_guess1);
    free(ciphertexts); free(timings);
    return curr_exp;
}

// entry point — takes n (number of ciphertexts) as a command line arg,
// runs baseline collection then the attack, and prints how many bits were wrong
int main(int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "Usage: %s <n>\n", argv[0]); return 1; }
    int n = atoi(argv[1]);

    FILE *outfile = fopen("baseline_timings.csv", "w");
    if (!outfile) { perror("baseline_timings.csv"); return 1; }
    baseline_timings(outfile, n);
    fclose(outfile);

    FILE *infile = fopen("baseline_timings.csv", "r");
    if (!infile) { perror("baseline_timings.csv"); return 1; }
    uint64_t recovered = compute_bit(infile, n);
    fclose(infile);

    uint64_t diff = recovered ^ target_key;
    int diffbits = __builtin_popcountll(diff);
    printf("Target:    %" PRIu64 "\nRecovered: %" PRIu64 "\nDiffering bits: %d\n",
           (uint64_t)target_key, recovered, diffbits);

    return 0;
}