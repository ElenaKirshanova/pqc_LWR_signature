#ifndef PARAMS_H
#define PARAMS_H

#include "config.h"

#define PQS_n 256

#define PQS_k 4
#define PQS_l 3

#define PQS_mu 19
#define PQS_nu 23
#define PQS_p (1 << PQS_mu)
#define PQS_q (1 << PQS_nu)

#define PQS_s 4 // GenSecret_s() works with PQS_s <= 7
#define PQS_d 3

#define PQS_gamma 1048096 // GenSecret_y() works with PQS_gamma <= 1048576
#define PQS_omega 60
#define PQS_beta 240

#define CRHBYTES 48
#define SEEDBYTES 32
#define POLW1_SIZE_PACKED ((PQS_n*4)/8)

// A polynomial in R_q, represented by a vector of its coefficients (x^0, x^1, ..., x^(PQS_n-1))
typedef struct{
  uint32_t coeffs[PQS_n];
} poly;

// A vector of length PQS_l of polynomials
typedef struct{
	poly polynomial[PQS_l];
} polyvecl;

// A vector of length PQS_k of polynomials
typedef struct{
	poly polynomial[PQS_k];
} polyveck;

// Rotation matrix of a polynomial
typedef struct{
  poly row[PQS_n];
} polyrot;

// Matrix of size PQS_k*PQS_l of polynomials
typedef struct{
  polyrot elem[PQS_k][PQS_l];
} polymatkl;

// Secret key
typedef struct{
	polyvecl s;
} sk_t;

// Public key
typedef struct{
	unsigned char seedA[SEEDBYTES];
	polyveck t;
} vk_t;

// Signature
typedef struct{
	poly c;
	polyvecl z;
} signat_t;

#endif

