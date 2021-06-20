#ifndef VERIFY
#define VERIFY

#include "utils/utils.h"

bool verify(vk_t vk, unsigned char *m, unsigned int mlen, signat_t sig);

int verify_from_bytes (unsigned char *m, unsigned long long *mlen, 
                       unsigned char *sm, unsigned long long smlen, unsigned char * pk);

void calculate_c_prime (poly &c_prime, polyveck w, unsigned char *m, unsigned int mlen);
bool verify_signature (poly c, poly c_prime, polyvecl z);

void debug_verify (poly &c_prime, polyveck &w);

#endif