#ifndef KEYGEN_H
#define KEYGEN_H

#include "utils/utils.h"

void keygen(sk_t &sk, vk_t &vk);
int keygen_bytes (unsigned char *pk, unsigned char *sk);

void generate_A (polymatkl &A);
void generate_s (polyvecl &s);
void calculate_t (polyveck &t, polymatkl &A, polyvecl &s);

void debug_keygen (sk_t &sk, vk_t &vk);

#endif