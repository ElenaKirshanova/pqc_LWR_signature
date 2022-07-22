#ifndef COMMON_SERIALIZE_H
#define COMMON_SERIALIZE_H

#include "params.h"

void serialize_polyvecl (polyvecl &pv, unsigned char *pv_bytes, int bits_per_coeff);
void deserialize_polyvecl (polyvecl &pv, unsigned char *pv_bytes, int bits_per_coeff);

void serialize_polyveck (polyveck &pv, unsigned char *pv_bytes, int bits_per_coeff);
void deserialize_polyveck (polyveck &pv, unsigned char *pv_bytes, int bits_per_coeff);

void serialize_poly (poly &p, unsigned char *p_bytes, int bits_per_coeff);
void deserialize_poly (poly &p, unsigned char *p_bytes, int bits_per_coeff, bool sign_extend);

void printBstr (char *lead, unsigned char* bstr, unsigned int blen);

#endif