#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <gmp.h>
#include "squaremult.h"
#include <time.h>

#define REPS 100  
#define DELAY_SIZE 50 


static void dummy_delay(void) {
    static volatile uint64_t dummy_array[DELAY_SIZE];
    for (int i = 0; i < DELAY_SIZE; i++) {
        dummy_array[i] = (uint64_t)i * 0xDEADBEEF;
    }
}

uint64_t get_process_cpu_time_ns() {
    struct timespec ts;
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) == 0) {
        return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    }
    return 0;
}


uint64_t square_multiply(uint64_t b, uint64_t e, uint64_t n) {
    
    //To store the result 
    uint64_t res = 1;
 
    
    int fixed_bitlen = 16; 
    for (int i = fixed_bitlen; i >= 0; i--) {  
        res = ((__uint128_t)res * res) % n;
        if ((e >> i) & 1) {
            //dummy_delay(); 
            res = ((__uint128_t)res * b) % n;  

        }
    }
   
    return res;
}

uint64_t timed_square_multiply(uint64_t b, uint64_t e, uint64_t n) {

    __asm__ __volatile__("lfence");
    uint64_t start = get_process_cpu_time_ns();

    __asm__ __volatile__("lfence");
    square_multiply(b, e, n);

    __asm__ __volatile__("lfence");
    uint64_t end = get_process_cpu_time_ns();

    __asm__ __volatile__("lfence");
    return (end - start);

}

///Old timing mechanism 

   /* static inline uint64_t rdtsc() {
    uint32_t lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
} */