#include "serialize.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>

// Serialize and deserialize functions.
// There is no way to verify that arrays are large enough so it is up to the calling function to pass in sufficiently sized arrays.

void serialize_polyvecl (polyvecl &pv, unsigned char *pv_bytes, int bits_per_coeff) {
    int i, polysize, offset = 0;

    polysize = (bits_per_coeff * PQS_n) / 8;

    for (i = 0; i < PQS_l; i++) {
        serialize_poly (pv.polynomial[i], pv_bytes + offset, bits_per_coeff);
        offset += polysize;
    }
}

void deserialize_polyvecl (polyvecl &pv, unsigned char *pv_bytes, int bits_per_coeff) {
    int i, polysize, offset = 0;

    polysize = (bits_per_coeff * PQS_n) / 8;

    for (i = 0; i < PQS_l; i++) {
        deserialize_poly (pv.polynomial[i], pv_bytes + offset, bits_per_coeff, false);
        offset += polysize;
    }
}

void serialize_polyveck (polyveck &pv, unsigned char *pv_bytes, int bits_per_coeff) {
    int i, polysize, offset = 0;

    polysize = (bits_per_coeff * PQS_n) / 8;

    for (i = 0; i < PQS_k; i++) {
        serialize_poly (pv.polynomial[i], pv_bytes + offset, bits_per_coeff);
        offset += polysize;
    }
}

void deserialize_polyveck (polyveck &pv, unsigned char *pv_bytes, int bits_per_coeff) {
    int i, polysize, offset = 0;

    polysize = (bits_per_coeff * PQS_n) / 8;

    for (i = 0; i < PQS_k; i++) {
        deserialize_poly (pv.polynomial[i], pv_bytes + offset, bits_per_coeff, false);
        offset += polysize;
    }
}

// Pack polynomials as tightly as possible
void serialize_poly (poly &p, unsigned char *p_bytes, int bits_per_coeff) {
    int polysize, poly_index, rshift, lshift, bytes_index = 0;
    int remaining_bits, leftover_space = 8;
    int32_t value, bits, mask = (1 << bits_per_coeff) - 1;

    polysize = (PQS_n * bits_per_coeff) / 8;
    memset (p_bytes, 0, polysize);

    for (poly_index = 0; poly_index < PQS_n; poly_index++) {
        value = p.coeffs[poly_index] & mask;

        remaining_bits = bits_per_coeff;
        while (remaining_bits > 0) {
            if (remaining_bits <= leftover_space) {
                lshift = leftover_space - remaining_bits;

                p_bytes[bytes_index] += value << lshift;

                leftover_space -= remaining_bits;
                remaining_bits = 0;
            }

            else if (leftover_space == 0) {
                bytes_index++;
                leftover_space = 8;
            }

            else {
                rshift = remaining_bits - leftover_space;

                bits = value >> rshift;
                p_bytes[bytes_index] += bits;
                value -= bits << rshift;

                bytes_index++;
                remaining_bits -= leftover_space;
                leftover_space = 8;
            }
        }
    }
}

// Unpack tightly packed polynomials
void deserialize_poly (poly &p, unsigned char *p_bytes, int bits_per_coeff, bool sign_extend) {
    int i, poly_index, rshift, bytes_index = 0;
    int remaining_bits, leftover = 8;
    int32_t mask, sign;

    for (poly_index = 0; poly_index < PQS_n; poly_index++) {
        p.coeffs[poly_index] = 0;
        remaining_bits = bits_per_coeff;

        while (remaining_bits > 0) {
            if (remaining_bits <= leftover) {
                rshift = leftover - remaining_bits;
                mask = (1 << remaining_bits) - 1;

                p.coeffs[poly_index] <<= remaining_bits;
                p.coeffs[poly_index] += (p_bytes[bytes_index] >> rshift) & mask;

                leftover -= remaining_bits;
                remaining_bits = 0;
            }

            else if (leftover == 0) {
                bytes_index++;
                leftover = 8;
            }

            else {
                mask = (1 << leftover) - 1;

                p.coeffs[poly_index] <<= leftover;
                p.coeffs[poly_index] += p_bytes[bytes_index] & mask;

                bytes_index++;
                remaining_bits -= leftover;
                leftover = 8;
            }
        }
    }

    if (sign_extend) {
        mask = 1 << (bits_per_coeff - 1);

        for (i = 0; i < PQS_n; i++) {
            sign = (p.coeffs[i] & mask) >> (bits_per_coeff - 1);
            sign = 1 - 2*sign;
            p.coeffs[i] = sign * (p.coeffs[i] & 1);
        }
    }
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