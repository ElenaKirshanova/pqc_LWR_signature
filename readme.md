
# PQS
DSA Postquantum standardization candidate reported here: https://crypto-kantiana.com/main_papers/main_Signature.pdf

Brief summary:

* Algorithm 3.1 Key generation
Input: k > l > 1, q > p, s
Output: A, t

1: A ← Rk×lq
2: s ← Sls
3: t = Round ( p/q·As)      Note that :  ∥t - As∥∞ ≤ 2ν − µ
4: return sk = s, vk = (A, t)

* Algorithm 3.2 Signature generation
Input: q = 2ν , p = 2µ , l > 1, M, A, t, s, d, H, β, γ, w
Output: (z, c)

1: y ← Slγ − 1
2: c = H (MSB (Ay, d), M)
3: z = y + sc
4: w = Az - t·2ν − µ ·c
5: if (∥LSB (± w, ν - d) ∥∞ ≥ 2ν − d - w·2ν − µ + 1 ) or (∥z∥∞ ≥ γ - β) then
6: restart
7: return (z, c)

* Algorithm 3.3 Signature verification
Input: M, z, c, A, t, d, H, β, γ
Output: Accept or Reject

1: w = Az - t · 2 ν − µ · c
2: c = H (MSB (w, d)), M)
3: if c == c and ∥z∥∞ ≤ γ - β then
4: return "Accept"
5: else
6: return "Reject"

# Requirements
- gcc compiler >= 9.2.1
- OpenSSL library development package
- NTL library

# Instructions to compile, install, and run tests
To compile the project locally, navigate to the project directory and execute the following:
```sh
make
```

To compile the project and install it as a library, execute the following:
```sh
sudo make install
```

To compile and run the tests, execute the following:
```sh
make test
```

To compile the Known Answer Test (KAT) code and generate KAT files, execute the following:
```sh
make kat
```

Testing configuration can be adjusted in header file `test/test_config.h`.

# Files
* pqs.h: primary header file for use as external library (see section below)
* keygen.c, keygen.h: implementation of the key generation algorithm (p. 4 of paper).
* sign.c, sign.h: implementation of the signing algorithm (p. 4 of paper).
* verify.c, verify.h: implementation of the verifiy algorithm (p. 5 of paper).
* utils/
    * utils.h: contains all utils without having to include each separately.
    * params.h: parameters for the protocol.
    * randombytes.c, randombytes.h: generates random bytes.
    * fips202.c, fips202.h: implementations of SHAKE used in random generation.
    * arith.c arith.h: arithmetic operations.
    * poly_mul.c, poly_mul.h: functions for multiplying polynomials.
    * core.c core.h: sampling, challenge generation, and other supporting functions.
    * matrix_A.h: fixed matrix A used in KAT generation and testing correctness.
    * serialize.c serialize.h: convert between key / signature structures and byte arrays.
* test/
    * cpucycles.c, cpucycles.h: performance benchmarking.
    * getCPUTime.c: returns internal time, used in cpucycles.c.
    * test_config.h: config options for testing.
    * pqs_test.h pqs_test.c: test code.
* KAT/
    * api.h, api.c: api expected by PQCgenKAT_sign.
    * rng.c rng.h: random generation for random messages and random secret bytes.
    * PQCgenKAT_sign: generate req (request) and rsp (response) files for KAT.


# Usage as an external library

In order to use this implementation in external project, it is recommended to install as a library and include the `pqs.h` header file:
```sh
#include "<pqs/pqs.h>"
```

If it is not possible to install as a library, the path to the header file will need to be specified:
```sh
#include "<PATH_TO_SIGNATURE_FOLDER>/pqs.h"
```

To work with keys and signatures as data structures, use the following steps:

1. Allocate memory for verify key (vk), secret key (sk), and signature (sig) by declaring variables having special data types `vk_t`, `sk_t`, `signat_t` respectively.
2. Generate a keypair by calling
```sh
keygen(vk, sk);
```
3. Load the message to be signed to array `unsigned char M[]` and let mlen be the number of bytes in the message.
4. Sign the message by calling
```sh
sign(sk, vk, M, mlen, sig);
```
5. Verify the signature stored in `sig` by calling a verification procedure
```sh
bool success = verify(vk, M, mlen, sig);
```

To work with keys and signatures as byte arrays, use the following steps:

1. Allocate memory for public key and private key:
```sh
unsigned char pk[PUBLICKEYBYTES];
unsigned char sk[SECRETKEYBYTES];
```
2. Generate a keypair (returns 0 on success, non-zero on fail):
```sh
int keygen_success = keygen_bytes(pk, sk);
```
3. Load the message to be signed to array `unsigned char M[]`.
4. Letting mlen be the original message length, allocate memory for signed message:
```sh
unsigned long long smlen = mlen + SIGNATUREBYTES;
unsigned char *sm = (unsigned char *) calloc (smlen, sizeof(unsigned char)); 
```
5. Get signed message (returns 0 on success, non-zero on fail):
```sh
int sign_success = sign (sm, &smlen, M, mlen, sk, pk);
```
6. Verify the signature (returns 0 on success, non-zero on fail):
```sh
unsigned char M2[mlen];
unsigned long mlen2;
int verify_success = verify_from_bytes (M2, &mlen2, sm, smlen, pk);
```
To ensure correctness confirm that verify_success == 0, mlen == mlen2, and M = M2.

Please refer to the following paper for more details: https://crypto-kantiana.com/main_papers/main_Signature.pdf
