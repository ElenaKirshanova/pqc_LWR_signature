#include "api.h"

#include <cstring>
#include <cstdio>

int crypto_sign_keypair (unsigned char *pk, unsigned char *sk)
{
    return keygen_bytes (pk, sk);
}

int crypto_sign (unsigned char *sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk, const unsigned char *pk) 
{
    unsigned char mcopy[mlen];
    memcpy (mcopy, m, mlen);

    unsigned char skcopy[CRYPTO_SECRETKEYBYTES];
    memcpy (skcopy, sk, CRYPTO_SECRETKEYBYTES);

    unsigned char pkcopy[CRYPTO_PUBLICKEYBYTES];
    memcpy (pkcopy, pk, CRYPTO_PUBLICKEYBYTES);

    return sign_from_keybytes (sm, smlen, mcopy, mlen, skcopy, pkcopy);
}

int crypto_sign_open (unsigned char *m, unsigned long long *mlen,
                const unsigned char *sm, unsigned long long smlen,
                const unsigned char *pk)
{
    unsigned char pkcopy[PUBLICKEYBYTES];
    memcpy (pkcopy, pk, PUBLICKEYBYTES);

    unsigned char smcopy[smlen];
    memcpy (smcopy, sm, smlen);

    return verify_from_bytes (m, mlen, smcopy, smlen, pkcopy);
}
