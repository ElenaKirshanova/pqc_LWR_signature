#ifndef ARITH_H
#define ARITH_H

#include "params.h"
#include <cstdint>

void mult_MatVecl(polyveck &res, polymatkl A, polyvecl v);
void add_PolyPoly(poly &res, poly p1, poly p2);
void subt_PolyPoly(poly &res, poly p1, poly p2);
void poly_mod (poly &p);

int32_t round(int32_t x);
int32_t modq_neg(int32_t);
int32_t modq(int32_t);

// Defined as macros for efficiency
#define LSB(x,d) ((x) & ((1<<(d)) - 1));
#define MSB(x,d) (((x) & (((1 << (d)) - 1) << (PQS_nu - (d)))) >> (PQS_nu - (d)));

#endif
