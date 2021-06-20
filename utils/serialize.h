#ifndef SERIALIZE_H
#define SERIALIZE_H

#include "params.h"

void serialize_poly (poly &p, unsigned char *p_bytes);

void serialize_polyvecl (polyvecl &pv, unsigned char *pv_bytes);
void deserialize_polyvecl (polyvecl &pv, unsigned char *pv_bytes);

void serialize_secret (sk_t &sk, unsigned char *sk_bytes);
void deserialize_secret (sk_t &sk, unsigned char *sk_bytes);

void serialize_verifykey (vk_t &vk, unsigned char *vk_bytes);
void deserialize_verifykey (vk_t &vk, unsigned char *vk_bytes);

unsigned long long pack_signed_message (unsigned char *sm, signat_t &sig, unsigned char *m, unsigned long long mlen);
unsigned long long unpack_signed_message (unsigned char *sm, signat_t &sig, unsigned char *m, unsigned long long smlen);

void printBstr (char *lead, unsigned char* bstr, unsigned int blen);

#endif
