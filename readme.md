# PQS
DSA Postquantum standardization candidate reported here: https://crypto-kantiana.com/main_papers/main_Signature.pdf

# Requirements
- gcc compiler >= 9.2.1
- OpenSSL library development package

# Running instructions
Clone the repository files to some folder, e.g. `~/PQS`, then execute the following commands to compile the project:
```sh
cd ~/PQS/Signature/
make
```

Run PQS testing script
```sh
./pqs_test
```
All the desired parameters for testing script as well as the signature parameters itself can be adjusted in header files `config.h`, `params.h`.

# Usage as an external library

In order to use this implementation in external project, include `sign.h` header file into your project and follow the instructions below.
```sh
#include "~/PQS/Signature/sign.h"
```

1. Allocate memory for public key, private key and signature by declaring variables having special data types `vk_t`, `sk_t`, `signat_t` respectively;
2. Generate a keypair by calling
```sh
PQS_keygen(vk, sk);
```
3. Load the message to be signed to array `unsigned char m[]` of length `int mlen` bytes
4. Sign the message by calling
```sh
PQS_sign(sig, &m[0], sizeof(m), sk, vk);
```
5. Verify the signature stored in `sig` by calling a verification procedure
```sh
bool success = PQS_verify(sig, &m[0], sizeof(m), vk);
```

Please refer to the following paper for more details: https://crypto-kantiana.com/main_papers/main_Signature.pdf
