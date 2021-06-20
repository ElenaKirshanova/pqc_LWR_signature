#include <cstring>
#include <cstdlib>

#include "sign.h"
#include <cstdio>

void sign (sk_t &sk, vk_t &vk, unsigned char *m, unsigned int mlen, signat_t &sig) {
    polyvecl y;
    polyveck w;
    bool val = false;

    unsigned char seed[SEEDBYTES];
    gen_seed (seed, sk, m, mlen);

    while (!val) {
        // Generate y from distribution.
        generate_y (y, seed);

        // Calculate c = H(MSB(Ay, d), m)
        calculate_c (sig.c, vk.A, y, m, mlen);

        // Calculate z = y + sc
        calculate_z (sig.z, y, sk.s, sig.c);

        // Calculate w = Az - t(2^nu-mu)c
        calculate_w (w, vk.A, sig.z, vk.t, sig.c);

        val = validate_sign (w, sig.z);
    }

    #ifdef DEBUG
    debug_sign (sk, vk, y, sig, w);
    #endif 
}

// sign message m using keypair (sk, pk) and return the signed message into sm
int sign_from_keybytes (unsigned char *sm, unsigned long long *smlen, 
                        unsigned char *m, unsigned long long mlen, 
                        unsigned char *sk, unsigned char *pk) 
{
    signat_t sig;
    sk_t sk_obj;
    vk_t vk;

    #ifdef MATRIX_A
    vk.A = matrix_A;
    #else
    fprintf (stderr, "MATRIX_A undefined. Public A must be defined when using byte arrays for keys.\n");
    return -1;
    #endif

    deserialize_secret (sk_obj, sk);
    deserialize_verifykey (vk, pk);

    sign (sk_obj, vk, m, (unsigned int) mlen, sig);

    *smlen = pack_signed_message (sm, sig, m, mlen);

    if (*smlen != (mlen + SIGNATUREBYTES))
        return -2;

    return 0;
}

// SUBFUNCTIONS

// To make known answer tests reproducible, this code generates y from seed = H(sk|m), similar to Dilithium.
void gen_seed (unsigned char *seed, sk_t &sk, unsigned char *m, unsigned int mlen) {
    int material_len = SECRETKEYBYTES + mlen;
    unsigned char material[material_len];

    serialize_secret (sk, material);
    memcpy (material + SECRETKEYBYTES, m, mlen);
    shake128 (seed, SEEDBYTES, material, material_len);
}

void generate_y (polyvecl &y, unsigned char *seed) {
    genVecl (y, PQS_gamma - 1, BUFLEN_gamma, seed);
}

void calculate_c (poly &c, polymatkl A, polyvecl y, const unsigned char *m, unsigned int mlen) {
    uint32_t i, j;

    // Calculate the first term, MSB(Ay, d).
    polyveck high_bits;
    mult_MatVecl (high_bits, A, y);

    for (i=0; i<PQS_k; i++) {
        for (j=0; j<PQS_n; j++) {
            high_bits.polynomial[i].coeffs[j] = MSB(high_bits.polynomial[i].coeffs[j], PQS_d);
        }
    }

    // Pass the first term and the message to H.
    uint8_t M_hash[CRHBYTES];
    shake256 (M_hash, CRHBYTES, m, mlen);
    challenge (c, M_hash, high_bits);
}

void calculate_z (polyvecl &z, polyvecl y, polyvecl s, poly c) {
    uint32_t i, j;

    for (i=0; i<PQS_l; i++) {
        MULT_POLYPOLY (s.polynomial[i], c, z.polynomial[i], PQS_n, PQS_q);
        for (j=0; j<PQS_n; j++) {
            z.polynomial[i].coeffs[j] += y.polynomial[i].coeffs[j];
            z.polynomial[i].coeffs[j] = modq_neg (z.polynomial[i].coeffs[j]);
        }
    }
}

void calculate_w (polyveck &w, polymatkl A, polyvecl z, polyveck t, poly c) {
    uint32_t i;

    // Calculate first term, Az, and store it into w1.
    polyveck w1, w2;
    mult_MatVecl (w1, A, z);

    // Multiply each coefficient in c by 2^(nu-mu-1).
    poly c_2_mu_nu;
    for (i=0; i<PQS_n; i++) {
        c_2_mu_nu.coeffs[i] = c.coeffs[i] << (PQS_nu - PQS_mu);
    }

    // Calculate full second term, t*2^(nu-mu)*c, and subtract it from w1.
    for (i=0; i<PQS_k; i++) {
        MULT_POLYPOLY (t.polynomial[i], c_2_mu_nu, w2.polynomial[i], PQS_n, PQS_q);
        subt_PolyPoly (w.polynomial[i], w1.polynomial[i], w2.polynomial[i]);
    }
}

bool validate_sign (polyveck w, polyvecl z) {
    uint32_t lsb_w, lsb_neg_w;
    uint32_t i, j; 
    int32_t coeff;

    uint32_t bound1 = (1 << (PQS_nu-PQS_d)) - PQS_omega*(1 << (PQS_nu-PQS_mu-1));
    uint32_t bound2 = PQS_gamma - PQS_beta;

    // Validate criterion 1: w inf-norm bound
    for (i=0; i<PQS_k; i++) {
        for (j=0; j<PQS_n; j++) {
            coeff = w.polynomial[i].coeffs[j];

            lsb_w = LSB (coeff, PQS_nu-PQS_d);
            lsb_neg_w = LSB (0xFFFFFFFF - coeff, PQS_nu-PQS_d);

            if ((lsb_w >= bound1) || (lsb_neg_w >= bound1)) {
                //printf ("Criterion 1 failed\n");
                return false;
            }
        }
    }

    // Validate criterion 2: z inf-norm bound
    for (i=0; i<PQS_l; i++) {
        for (j=0; j<PQS_n; j++) {
            if (abs (z.polynomial[i].coeffs[j]) >= bound2) {
                //printf ("Criterion 2 failed\n");
                return false;
            }
        }
    }

    return true;
}

void debug_sign (sk_t &sk, vk_t &vk, polyvecl &y, signat_t &sig, polyveck &w) {
    printf ("Debugging sign...\n");

    unsigned char sig_bytes[SIGNATUREBYTES];
    unsigned char w_bytes[PQS_k * PQS_n * 4];
    unsigned char sk_bytes[SECRETKEYBYTES];
    unsigned char vk_bytes[PUBLICKEYBYTES];
    unsigned char y_bytes[SECRETKEYBYTES];

    char s_str[] = "s = ";
    char v_str[] = "v = ";
    char y_str[] = "y = ";
    char c_str[] = "c = ";
    char z_str[] = "z = ";
    char w_str[] = "w = ";

    int i;

    pack_signed_message (sig_bytes, sig, NULL, 0);

    for (i = 0; i < PQS_k; i++) 
        serialize_poly (w.polynomial[i], &(w_bytes[i * PQS_n * 4]));

    serialize_secret (sk, sk_bytes);
    serialize_verifykey (vk, vk_bytes);
    serialize_polyvecl (y, y_bytes);

    printBstr (s_str, sk_bytes, SECRETKEYBYTES);
    printBstr (y_str, y_bytes, SECRETKEYBYTES);
    printBstr (v_str, vk_bytes, PUBLICKEYBYTES);
    printBstr (c_str, sig_bytes, PQS_n);
    printBstr (z_str, &(sig_bytes[PQS_n*4]), PQS_n * PQS_l * 4);
    printBstr (w_str, w_bytes, PQS_k * PQS_n * 4);
}