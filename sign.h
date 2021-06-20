#ifndef SIGN
#define SIGN

#include "utils/utils.h"

void sign (sk_t &sk, vk_t &vk, unsigned char *m, unsigned int mlen, signat_t &sig);
int sign_from_keybytes (unsigned char *sm, unsigned long long* smlen,
                        unsigned char *m, unsigned long long mlen,
                        unsigned char *sk, unsigned char *pk);

void gen_seed (unsigned char *seed, sk_t &sk, unsigned char *m, unsigned int mlen);
void generate_y (polyvecl &y, unsigned char *seed);
void calculate_c (poly &c, polymatkl A, polyvecl y, const unsigned char *m, unsigned int mlen);
void calculate_z (polyvecl &z, polyvecl y, polyvecl s, poly c);
void calculate_w (polyveck &w, polymatkl A, polyvecl z, polyveck t, poly c);
bool validate_sign (polyveck w, polyvecl z);

void debug_sign (sk_t &sk, vk_t &vk, polyvecl &y, signat_t &sig, polyveck &w);

#endif