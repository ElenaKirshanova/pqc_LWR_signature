#ifndef PQS_H
#define PQS_H

// Interface of only the elements that we want to externally expose

// util structures, constants, and functions
#include "utils/params.h"
#include "utils/randombytes.h"

// keygen
void keygen(sk_t &sk, vk_t &vk);
int keygen_bytes(unsigned char *pk, unsigned char *sk);

// sign
void sign(sk_t &sk, vk_t &vk, unsigned char *m, unsigned int mlen, signat_t &sig);
int sign_from_keybytes (unsigned char *sm, unsigned long long* smlen,
                        unsigned char *m, unsigned long long mlen,
                        unsigned char *sk, unsigned char *pk);

// verify
bool verify(vk_t vk, unsigned char *m, unsigned int mlen, signat_t sig);
int verify_from_bytes (unsigned char *m, unsigned long long *mlen, 
                        unsigned char *sm, unsigned long long smlen, unsigned char * pk);

#endif
