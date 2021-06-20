#include <cstring>
#include <cstdlib>

#include "verify.h"
#include "sign.h"
#include <cstdio>

bool verify (vk_t vk, unsigned char *m, unsigned int mlen, signat_t sig) {
    // Calculate w = Az - t(2^(nu-mu))c
    polyveck w;
    calculate_w(w, vk.A, sig.z, vk.t, sig.c);

    // Calculate c_prime = H(MSB(w, d), M)
    poly c_prime;
    memset(&c_prime, 0, sizeof(poly));
    calculate_c_prime(c_prime, w, m, mlen);

    #ifdef DEBUG
    debug_verify (c_prime, w);
    #endif

    // Check acceptance criteria.
    return verify_signature(sig.c, c_prime, sig.z);
}

int verify_from_bytes (unsigned char *m, unsigned long long *mlen, 
                       unsigned char *sm, unsigned long long smlen, unsigned char * pk) 
{
    vk_t vk;
    signat_t sig;

    #ifdef MATRIX_A
    vk.A = matrix_A;
    #else
    fprintf (stderr, "MATRIX_A undefined. Public A must be defined for verifying from key bytes.\n");
    return -1;
    #endif

    deserialize_verifykey (vk, pk);
    *mlen = unpack_signed_message (sm, sig, m, smlen);

    if (verify (vk, m, (unsigned int) *mlen, sig))
        return 0;

    return -3; 
}

// SUBFUNCTIONS

void calculate_c_prime(poly &c_prime, polyveck w, unsigned char *m, unsigned int mlen) {
    // Calculate the first term, MSB(w, d).
    polyveck high_bits;
    uint32_t i, j;
    for (i=0; i<PQS_k; i++){
        for (j=0; j<PQS_n; j++){
            high_bits.polynomial[i].coeffs[j] = MSB(w.polynomial[i].coeffs[j], PQS_d);
        }
    }

    // Pass the first term and the message to H.
    uint8_t M_hash[CRHBYTES];
    shake256(M_hash, CRHBYTES, m, mlen);
    challenge(c_prime, M_hash, high_bits);
}

bool verify_signature(poly c, poly c_prime, polyvecl z){
    // Verify criterion 1: c = c_prime
    uint j;
    for (j=0; j<PQS_n ; j++) {
        if (c.coeffs[j] != c_prime.coeffs[j]) {
            return false;
        }
    }

    // Verify criterion 2: z inf-norm bound
    uint i;
    for (i=0; i<PQS_l; i++) {
        for (j=0; j<PQS_n; j++){
            if (abs(z.polynomial[i].coeffs[j]) > PQS_gamma - PQS_beta){
                return false;
            }
        }
    }

    return true;
}


void debug_verify (poly &cprime, polyveck &w) {
    printf ("Debugging verify...\n");

    unsigned char cp_bytes[PQS_n * 4];
    unsigned char w_bytes[PQS_k * PQS_n * 4];

    char cp_str[] = "cprime = ";
    char w_str[] = "w = ";

    int i;

    serialize_poly (cprime, cp_bytes);
    for (i = 0; i < PQS_k; i++) 
        serialize_poly (w.polynomial[i], &(w_bytes[i * PQS_n * 4]));

    printBstr (cp_str, cp_bytes, PQS_n * 4);
    printBstr (w_str, w_bytes, PQS_k * PQS_n * 4);
}