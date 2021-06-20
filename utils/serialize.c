#include "serialize.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>

// Serialize and deserialize functions. 
// There is no way to verify that arrays are large enough so it is up to the calling function to pass in sufficiently sized arrays.

void serialize_poly (poly &p, unsigned char *p_bytes) {
    int i, array_index = 0;

    for (i = 0; i < PQS_n; i++) {
        p_bytes[array_index++] = (p.coeffs[i] & 0xff000000) >> 24;
        p_bytes[array_index++] = (p.coeffs[i] & 0xff0000) >> 16;
        p_bytes[array_index++] = (p.coeffs[i] & 0xff00) >> 8;
        p_bytes[array_index++] = (p.coeffs[i] & 0xff);
    }
}

void serialize_secret (sk_t &sk, unsigned char *sk_bytes) {
    serialize_polyvecl (sk.s, sk_bytes);
}

void serialize_polyvecl (polyvecl &pv, unsigned char *pv_bytes) {
    int i, j, array_index = 0;

    for (i = 0; i < PQS_l; i++) {
        poly p = pv.polynomial[i];
        for (j = 0; j < PQS_n; j++) {
            pv_bytes[array_index++] = (p.coeffs[j] & 0xff000000) >> 24;
            pv_bytes[array_index++] = (p.coeffs[j] & 0xff0000) >> 16;
            pv_bytes[array_index++] = (p.coeffs[j] & 0xff00) >> 8;
            pv_bytes[array_index++] = (p.coeffs[j] & 0xff);
        }
    }
}

void deserialize_secret (sk_t &sk, unsigned char *sk_bytes) {
    deserialize_polyvecl (sk.s, sk_bytes);
}

void deserialize_polyvecl (polyvecl &pv, unsigned char *pv_bytes) {
    int i, j, array_index = 0;

    for (i = 0; i < PQS_l; i++) {
        for (j = 0; j < PQS_n; j++) {
            pv.polynomial[i].coeffs[j] = pv_bytes[array_index++] << 24;
            pv.polynomial[i].coeffs[j] |= pv_bytes[array_index++] << 16;
            pv.polynomial[i].coeffs[j] |= pv_bytes[array_index++] << 8;
            pv.polynomial[i].coeffs[j] |= pv_bytes[array_index++];
        }
    }
}

void serialize_verifykey (vk_t &vk, unsigned char *vk_bytes) {
    int i, j, array_index = 0;

    for (i = 0; i < PQS_k; i++) {
        poly p = vk.t.polynomial[i];
        for (j = 0; j < PQS_n; j++) {
            vk_bytes[array_index++] = (p.coeffs[j] & 0xff000000) >> 24;
            vk_bytes[array_index++] = (p.coeffs[j] & 0xff0000) >> 16;
            vk_bytes[array_index++] = (p.coeffs[j] & 0xff00) >> 8;
            vk_bytes[array_index++] = (p.coeffs[j] & 0xff); 
        }
    }
}

void deserialize_verifykey (vk_t &vk, unsigned char *vk_bytes) {
    int i, j, array_index = 0;

    memset (&(vk.t), 0, sizeof(vk.t));

    for (i = 0; i < PQS_k; i++) {
        for (j = 0; j < PQS_n; j++) {
            vk.t.polynomial[i].coeffs[j] = vk_bytes[array_index++] << 24;
            vk.t.polynomial[i].coeffs[j] |= vk_bytes[array_index++] << 16;
            vk.t.polynomial[i].coeffs[j] |= vk_bytes[array_index++] << 8;
            vk.t.polynomial[i].coeffs[j] |= vk_bytes[array_index++];
        }
    }
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

void printBstr(char *lead, unsigned char *bstr, unsigned int blen)
{
	unsigned int i;

	printf("%s\n", lead);

	for (i=0; i < blen; i++) {
        if (i != 0 && (i%32) == 0)
            printf ("\n");
        else if (i != 0 && (i%4) == 0)
            printf (" ");

		printf("%02x", bstr[i]);
    }

	printf("\n\n");
}
