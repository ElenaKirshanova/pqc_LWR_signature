#ifndef SIGN_H
#define SIGN_H

#include "params.h"
#include "getCPUTime.c"

void polyw1_pack(uint8_t *r, const poly *a);

void challenge (poly &c, const uint8_t mu[CRHBYTES], polyveck &w1);

void BS2POL(const unsigned char *bytes, poly &data);

void GenSeed(unsigned char *seed);

void fillpolyrot(polyrot &a);

void GenSecret_s(polyvecl &a);

void GenSecret_y(polyvecl &a, const unsigned char *seed);

void GenMatrix(polymatkl &A, const unsigned char *seed);

uint32_t round (uint32_t x);

uint32_t MSB (uint32_t x, uint32_t d);

uint32_t LSB (uint32_t x, uint32_t d);

void matrixpoly(polymatkl &mat, polyvecl &a, polyveck &res);

void PQS_keygen(vk_t &vk, sk_t &sk);

void PQS_sign(signat_t &sig, const unsigned char *m, uint32_t mlen, sk_t &sk, vk_t &vk);

bool PQS_verify(signat_t &sig, const unsigned char *m, uint32_t mlen, vk_t &vk);

#endif
