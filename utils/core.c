#include "core.h"
#include "fips202.h"
#include "randombytes.h"

#include <cstring>
#include <cmath>

static uint32_t msb_position (uint32_t x);


/*************************************************
* Name:        polyw1_pack (adapted from CRYSTALS Dilithium)
*
* Description: Bit-pack polynomial w1 with coefficients in [0, 15].
*              Input coefficients are assumed to be standard representatives.
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            POLW1_SIZE_PACKED bytes
*              - const poly *a: pointer to input polynomial
**************************************************/

void polyw1_pack (uint8_t *r, const poly *a) {
  unsigned int i;

  for(i = 0; i < PQS_n/2; ++i)
    r[i] = a->coeffs[2*i+0] | (a->coeffs[2*i+1] << 4);

}

/*************************************************
* Name:        challenge (adapted from CRYSTALS Dilithium)
*
* Description: Implementation of H. Samples polynomial with 60 nonzero
*              coefficients in {-1,1} using the output stream of
*              SHAKE256(mu|w1).
*
* Arguments:   - poly &c: output polynomial
*              - const uint8_t mu[]: byte array containing mu
*              - const polyveck *w1: pointer to vector w1
**************************************************/

void challenge (poly &c, const uint8_t mu[CRHBYTES], polyveck &w1) {
  unsigned int i, b, pos;
  uint64_t signs;
  uint8_t inbuf[CRHBYTES + PQS_k*POLW1_SIZE_PACKED];
  uint8_t outbuf[SHAKE256_RATE];
  keccak_state state;

  memcpy (inbuf, mu, CRHBYTES);

  for(i = 0; i < PQS_k; ++i)
    polyw1_pack (inbuf + CRHBYTES + i*POLW1_SIZE_PACKED, &w1.polynomial[i]);

  shake256_absorb (&state, inbuf, sizeof(inbuf));
  shake256_squeezeblocks (outbuf, 1, &state);

  signs = 0;
  for(i = 0; i < 8; ++i)
    signs |= (uint64_t) outbuf[i] << 8*i;

  pos = 8;
  memset (c.coeffs, 0, PQS_n * 4);

  for(i = 196; i < 256; ++i) {
    do {
      if (pos >= SHAKE256_RATE) {
        shake256_squeezeblocks (outbuf, 1, &state);
        pos = 0;
      }

      b = outbuf[pos++];
    } while (b > i);

    c.coeffs[i] = c.coeffs[b];
    c.coeffs[b] = 1;
    c.coeffs[b] ^= -((uint32_t)signs & 1) & (1 ^ (PQS_q-1));
    signs >>= 1;
  }
}

/**************************************************
* Name:        genVecl
*
* Description: Generate a vector of polynomials.
*
* Arguments:   - p: output polynomial
*              - bound: range of coefficients
*              - buflen: buffer length for shake
*              - seed: seed for random generation
**************************************************/

void genVecl (polyvecl &vecl, int bound, uint32_t buflen, unsigned char *seed) {
    size_t i;
    poly p;

    for (i=0; i<PQS_l; i++) {
        rej_sample (p, bound, buflen, seed);
        vecl.polynomial[i] = p;
    }

    if (bound == PQS_s) 
        return;
}

/*************************************************
* Name:        rej_sample
*
* Description: Perform rejection sampling to generate polynomial
*              coefficients given a particular bound. The bound
*              is inclusive: coefficients will be in the range
*              [-bound, bound].
*
* Arguments:   - c: output polynomial
*              - bound: range of the coefficients
*              - buflen: buffer length for shake
*              - seed: seed for random generation
**************************************************/

void rej_sample (poly &p, uint32_t bound, uint32_t buflen, unsigned char *seed) {
    int bits_per_coeff = msb_position(bound);
    uint32_t mask = (1 << bits_per_coeff) - 1;

    bits_per_coeff += 1;    // add one for sign bit
    uint32_t bytes_per_coeff = (uint32_t) ceil(bits_per_coeff/8.0);

    // Initialize random data
    shake128 (seed, SEEDBYTES, seed, SEEDBYTES);

    unsigned char buffer[buflen];
    shake128 (buffer, buflen, seed, SEEDBYTES);

    uint32_t data_offset = 0, byte_offset, i, sample;
    int32_t sign;
    for (i=0; i<PQS_n; i++) {
        // Construct the candidate coefficient
        sample = 0;
        for (byte_offset=0; byte_offset<bytes_per_coeff; byte_offset++) {
            sample |= (buffer[data_offset+byte_offset])<<(byte_offset*8);
        }

        sample &= mask;
        if (sample > bound) i--;
        else {
            // Take the highest bit as the sign bit, 0: positive, 1: negative.
            sign = sample >> (bits_per_coeff - 1);
            sign = 1 - 2*sign;
            p.coeffs[i] = sign * sample;
        }

        data_offset += bytes_per_coeff;

        // If we're about to run out of bytes, pull another buffer.
        if (data_offset+bytes_per_coeff > buflen){
            shake128 (seed, SEEDBYTES, seed, SEEDBYTES);
            shake128 (buffer, buflen, seed, SEEDBYTES);
            data_offset = 0;
        }
    }
}

static uint32_t msb_position (uint32_t x) {
    uint32_t n = -(x ==0);
    for (int k = 16; k > 0; k >>= 1) {
        if (x >= (uint32_t) (1 << k)) {
            n += k;
            x >>= k;
        }
    }
    return n+1;
}
