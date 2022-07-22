#include "serialize.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>

// Serialize and deserialize functions.
// There is no way to verify that arrays are large enough so it is up to the calling function to pass in sufficiently sized arrays.

void serialize_secret (sk_t &sk, unsigned char *sk_bytes) {
    serialize_polyvecl (sk.s, sk_bytes, PQS_s_bits);
}

void deserialize_secret (sk_t &sk, unsigned char *sk_bytes) {
    deserialize_polyvecl (sk.s, sk_bytes, PQS_s_bits);
}

void serialize_verifykey (vk_t &vk, unsigned char *vk_bytes) {
    serialize_polyveck (vk.t, vk_bytes, PQS_mu-PQS_d);
}

void deserialize_verifykey (vk_t &vk, unsigned char *vk_bytes) {
    deserialize_polyveck (vk.t, vk_bytes, PQS_mu-PQS_d);
}

unsigned long long pack_signed_message (unsigned char *sm, signat_t &sig, unsigned char *m, unsigned long long mlen) {
    poly c = sig.c;
    polyvecl z = sig.z;
    int i, j;
    unsigned long long byte_index;

    memset (sm, 0, mlen + SIGNATUREBYTES);
    if (mlen != 0)
        memcpy (sm, m, mlen);
    byte_index = mlen;

    for (i = 0; i < PQS_n; i++) {
        sm[byte_index++] = c.coeffs[i] >> 24;
        sm[byte_index++] = (c.coeffs[i] & 0xff0000) >> 16;
        sm[byte_index++] = (c.coeffs[i] & 0xff00) >> 8;
        sm[byte_index++] = c.coeffs[i] & 0xff;
    }

    for (i = 0; i < PQS_l; i++) {
        poly p = z.polynomial[i];
        for (j = 0; j < PQS_n; j++) {
            sm[byte_index++] = p.coeffs[j] >> 24;
            sm[byte_index++] = (p.coeffs[j] & 0xff0000) >> 16;
            sm[byte_index++] = (p.coeffs[j] & 0xff00) >> 8;
            sm[byte_index++] = p.coeffs[j] & 0xff;
        }
    }

    return byte_index;
}

unsigned long long unpack_signed_message (unsigned char *sm, signat_t &sig, unsigned char *m, unsigned long long smlen) {
    int i, j;
    unsigned long long mlen, byte_index;

    memset (m, 0, smlen);
    mlen = smlen - SIGNATUREBYTES;

    memcpy (m, sm, (size_t) mlen);
    byte_index = mlen;

    for (i = 0; i < PQS_n; i++) {
        sig.c.coeffs[i] = sm[byte_index++] << 24;
        sig.c.coeffs[i] |= sm[byte_index++] << 16;
        sig.c.coeffs[i] |= sm[byte_index++] << 8;
        sig.c.coeffs[i] |= sm[byte_index++];
    }

    for (i = 0; i < PQS_l; i++) {
        for (j = 0; j < PQS_n; j++) {
            sig.z.polynomial[i].coeffs[j] = sm[byte_index++] << 24;
            sig.z.polynomial[i].coeffs[j] |= sm[byte_index++] << 16;
            sig.z.polynomial[i].coeffs[j] |= sm[byte_index++] << 8;
            sig.z.polynomial[i].coeffs[j] |= sm[byte_index++];
        }
    }

    return byte_index - SIGNATUREBYTES;
}
