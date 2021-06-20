#ifndef POLY_MUL
#define POLY_MUL

#include "params.h"
#include <cstdint>

void print_polystruct(poly &a, int64_t n, uint64_t p);

void cook_karatsuba_mul(poly &a_poly, poly &b_poly, poly &res, uint32_t n, uint32_t p);

void schoolbook_mul(poly &a, poly &b, poly &res, uint32_t n, uint32_t p);

void toom_cook_4way(int32_t* a1, int32_t* b1, uint32_t* result);

void karatsuba_simple(const uint32_t* a_1, const uint32_t* b_1, uint32_t* result_final);

#define MULT_POLYPOLY cook_karatsuba_mul

#endif