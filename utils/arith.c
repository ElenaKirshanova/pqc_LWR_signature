#include "arith.h"
#include "poly_mul.h"
#include <cstring>

// ARITHMETIC FUNCTIONS

// Multiply a k*l matrix by an l-vector, returning a k-vector.
void mult_MatVecl(polyveck &res, polymatkl A, polyvecl v) {
    int i, j;
    poly acc;
    memset(&res, 0, sizeof(polyveck));
    for (i=0; i<PQS_k; i++){
        for (j=0; j<PQS_l; j++){
            MULT_POLYPOLY(A.elem[i][j], v.polynomial[j], acc, PQS_n, PQS_q);
            add_PolyPoly (res.polynomial[i], res.polynomial[i], acc);
        }
    }
}

// Add polynomial p1 to polynomial p2.
void add_PolyPoly(poly &res, poly p1, poly p2) {
    for (int n=0; n<PQS_n; n++)
        res.coeffs[n] = modq(p1.coeffs[n] + p2.coeffs[n]);
}

// Subtract polynomial p2 from polynomial p1.
void subt_PolyPoly(poly &res, poly p1, poly p2) {
    for (uint32_t i=0; i<PQS_n; i++)
        res.coeffs[i] = modq(p1.coeffs[i] - p2.coeffs[i]);
}

// Round an integer PQS_q -> PQS_p
int32_t round(int32_t x) {
    uint32_t h = 1 << (PQS_nu - PQS_mu - 1);
    return (x + h) >> (PQS_nu - PQS_mu);
}

// Reduce x to the range (-q/2, q/2].
int32_t modq_neg(int32_t x) {
    int32_t y = modq(x);
    return y - (y >> (PQS_nu-1)) * PQS_q;
}

// Reduce x to the range [0,q].
int32_t modq(int32_t x) {
    return x & (PQS_q - 1);
}
