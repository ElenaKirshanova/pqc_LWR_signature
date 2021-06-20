#ifndef api_h
#define api_h

#include "../pqs.h"
#include "../utils/utils.h"

#define CRYPTO_SECRETKEYBYTES SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES PUBLICKEYBYTES
#define CRYPTO_BYTES SIGNATUREBYTES

#define CRYPTO_ALGNAME "signature"

int crypto_sign_keypair (unsigned char *pk, unsigned char *sk);

int crypto_sign (unsigned char *sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk, const unsigned char *pk);

int crypto_sign_open (unsigned char *m, unsigned long long *mlen,
                const unsigned char *sm, unsigned long long smlen,
                const unsigned char *pk);

#endif