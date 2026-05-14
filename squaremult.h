#ifndef SQUAREMULT_H
#define SQUAREMULT_H
#include <gmp.h>

//static inline void serialize() {
  //  asm volatile("isb" ::: "memory");
//}

uint64_t square_multiply(uint64_t b, uint64_t e, uint64_t n);
uint64_t timed_square_multiply(uint64_t b, uint64_t e, uint64_t n); 
uint64_t get_process_cpu_time_ns(void);


#endif