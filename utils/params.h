#ifndef PARAMS_H
#define PARAMS_H

#include <cstdint>

#define PQS_n 256

#define PQS_k 4
#define PQS_l 3

#define PQS_mu 19
#define PQS_nu 23
#define PQS_p (1 << PQS_mu)
#define PQS_q (1 << PQS_nu)

#define PQS_s 4
#define PQS_s_bits 3
#define PQS_d 3

#define PQS_gamma 1048096
#define PQS_gamma_bits 20
#define PQS_omega 60
#define PQS_beta 240

#define CRHBYTES 48
#define SEEDBYTES 32
#define POLW1_SIZE_PACKED ((PQS_n*4)/8)

// Number of bytes needed for rejection sampling, precomputed from Hoeffding's inequality rounded up to nearest multiple of SHAKE_RATE
#define BUFLEN_A 840 
#define BUFLEN_gamma 840
#define BUFLEN_s 336 

#define MAXRANDOM 33554431

// Each element is an int32_t which is 4 bytes
#define SECRETKEYBYTES (4*PQS_n*PQS_l)
#define PUBLICKEYBYTES (4*PQS_n*PQS_k)
#define SIGNATUREBYTES (4*PQS_n + 4*PQS_n*PQS_l)

//#define DEBUG
//#define REGEN_A

// A polynomial in R_q, represented by a vector of coefficients (x^0, x^1, ..., x^(PQS_n-1))
typedef struct{
  int32_t coeffs[PQS_n];
} poly;

// A vector of length PQS_l of polynomials
typedef struct{
	poly polynomial[PQS_l];
} polyvecl;

// A vector of length PQS_k of polynomials
typedef struct{
	poly polynomial[PQS_k];
} polyveck;

// Matrix of size PQS_k*PQS_l of polynomials
typedef struct{
  poly elem[PQS_k][PQS_l];
} polymatkl;

// Secret key
typedef struct{
	polyvecl s;
} sk_t;

// Public key
typedef struct{
	polymatkl A;
	polyveck t;
} vk_t;

// Signature
typedef struct{
	poly c;
	polyvecl z;
} signat_t;

#endif
