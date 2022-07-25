#include <iostream>
#include <cstring>
#include "params.h"
#include "poly_mul.h"
#include "randombytes.h"
#include "fips202.h"

using namespace std;
#define crh(OUT, IN, INBYTES) shake256(OUT, CRHBYTES, IN, INBYTES)

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
void polyw1_pack(uint8_t *r, const poly *a) {
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

void challenge (poly &c, const uint8_t mu[CRHBYTES], polyveck &w1)
{
  unsigned int i, b, pos;
  uint64_t signs;
  uint8_t inbuf[CRHBYTES + PQS_k*POLW1_SIZE_PACKED];
  uint8_t outbuf[SHAKE256_RATE];
  keccak_state state;

  for(i = 0; i < CRHBYTES; ++i)
    inbuf[i] = mu[i];
  for(i = 0; i < PQS_k; ++i)
    polyw1_pack(inbuf + CRHBYTES + i*POLW1_SIZE_PACKED, &w1.polynomial[i]); // fixed w1

  shake256_absorb(&state, inbuf, sizeof(inbuf));
  shake256_squeezeblocks(outbuf, 1, &state);

  signs = 0;
  for(i = 0; i < 8; ++i)
    signs |= (uint64_t)outbuf[i] << 8*i;

  pos = 8;

  for(i = 0; i < PQS_n; ++i)
    c.coeffs[i] = 0;

  for(i = 196; i < 256; ++i) {
    do {
      if(pos >= SHAKE256_RATE) {
        shake256_squeezeblocks(outbuf, 1, &state);
        pos = 0;
      }

      b = outbuf[pos++];
    } while(b > i);

    c.coeffs[i] = c.coeffs[b];
    c.coeffs[b] = 1;
    c.coeffs[b] ^= -((uint32_t)signs & 1) & (1 ^ (PQS_q-1));
    signs >>= 1;
  }
}


// *********************************
// Arithmetic and auxiliary routines
// *********************************

// Make a polynomial (PQS_n 23-bit coefficients) from an array of random bytes
void BS2POL(const unsigned char *bytes, poly &data){
	
	uint32_t j;
	uint32_t offset_data=0,offset_byte=0;	

		for(j=0;j<PQS_n/8;j++){
			offset_byte=23*j;
			offset_data=8*j;
			data.coeffs[offset_data + 0]= ( bytes[ offset_byte + 0 ] & (0xff)) | ((bytes[offset_byte + 1] & 0xff)<<8) | ((bytes[ offset_byte + 2 ] & 0x7f)<<16);
			data.coeffs[offset_data + 1]= ( bytes[ offset_byte + 2 ]>>7 & (0x01)) | ((bytes[offset_byte + 3] & 0xff)<<1) | ((bytes[offset_byte + 4] & 0xff)<<9) | ((bytes[offset_byte + 5] & 0x3f)<<17);
			data.coeffs[offset_data + 2]= ( bytes[ offset_byte + 5 ]>>6 & (0x03)) | ((bytes[offset_byte + 6] & 0xff)<<2) | ((bytes[offset_byte + 7] & 0xff)<<10) | ((bytes[offset_byte + 8] & 0x1F)<<18);
			data.coeffs[offset_data + 3]= ( bytes[ offset_byte + 8 ]>>5 & (0x07)) | ((bytes[offset_byte + 9] & 0xff)<<3) | ((bytes[offset_byte + 10] & 0xff)<<11) | ((bytes[offset_byte + 11] & 0x0F)<<19);
			data.coeffs[offset_data + 4]= ( bytes[ offset_byte + 11 ]>>4 & (0x0f)) | ((bytes[offset_byte + 12] & 0xff)<<4) | ((bytes[offset_byte + 13] & 0xff)<<12) | ((bytes[offset_byte + 14] & 0x07)<<20);
			data.coeffs[offset_data + 5]= ( bytes[ offset_byte + 14]>>3 & (0x1f)) | ((bytes[offset_byte + 15] & 0xff)<<5) | ((bytes[offset_byte + 16] & 0xff)<<13) | ((bytes[offset_byte + 17] & 0x03)<<21);
			data.coeffs[offset_data + 6]= ( bytes[ offset_byte + 17]>>2 & (0x3f)) | ((bytes[offset_byte + 18] & 0xff)<<6) | ((bytes[offset_byte + 19] & 0xff)<<14) | ((bytes[offset_byte + 20] & 0x01)<<22);
			data.coeffs[offset_data + 7]= ( bytes[ offset_byte + 20]>>1 & (0x7f)) | ((bytes[offset_byte + 21] & 0xff)<<7) | ((bytes[offset_byte + 22] & 0xff)<<15);
		}

}

// Generates SEEDBYTES random bytes
void GenSeed(unsigned char *seed){
	randombytes(seed, SEEDBYTES);
	shake128(seed, SEEDBYTES, seed, SEEDBYTES); // for not revealing system RNG state
}

// Fill in a rotation matrix (polymatkl.elem[][].row[1..PQS_n-1])
void fillpolyrot(polyrot &a){
	int i,j;
	for(i=1; i<PQS_n; i++){
			a.row[i].coeffs[0] = PQS_q - a.row[i-1].coeffs[PQS_n-1];
			for(j=1;j<PQS_n;j++){ // Fill in vec[u] - lines of the matrix rot(vec[0])
				a.row[i].coeffs[j] = a.row[i-1].coeffs[j-1];
			}
		}
}

// Generate a secret vector s of length l of polynomials with coefficients in [-s..s] uniformly distributed.
// Performs rejection sampling on output stream of shake128()
void GenSecret_s(polyvecl &a) 
{
	unsigned char seed[SEEDBYTES];
	GenSeed(seed);
	
	unsigned int one_vector = PQS_n;
	unsigned int byte_bank_length=PQS_l*one_vector;
	// Note: buffer size of 748 bytes guarantees successful rejection sampling with probability >=0.999
	// following the Hoeffding's inequality (this bound is calculated for default parameters PQS_s=4, PQS_n=256, PQS_l=3)
	unsigned char buf[byte_bank_length];
	shake128(buf,byte_bank_length,seed,SEEDBYTES);

	uint32_t coef=0;
	unsigned int ncoeffs=0;
	unsigned int pos = 0;
	int j=0;
	
	for(j=0; j<PQS_l; j++){
		ncoeffs = 0;
		while(ncoeffs<PQS_n && pos <= 2*byte_bank_length-2){
			coef = buf[pos >> 1] & 0x0F;
			if(coef <= PQS_s){ // Accept as a non-negative coefficient
				a.polynomial[j].coeffs[ncoeffs] = coef;
				ncoeffs++;
			} else if(coef <= 2*PQS_s){ // Accept as a negative coefficient
				a.polynomial[j].coeffs[ncoeffs] = PQS_q - coef + PQS_s;
				ncoeffs++;
			} // Else reject
			buf[pos >> 1] >>= 4;
			++pos;
		}
	}  
	
	if(ncoeffs < PQS_n){
		cerr << "ERROR :: Too short buffer in GenSecret_s(), restarting...";
		GenSecret_s(a);
	}
}

// Generate a vector of length l of polynomials with coefficients in [-PQS_gamma+1..PQS_gamma-1].
// Performs rejection sampling on output stream of shake128()
void GenSecret_y(polyvecl &a, unsigned char *seed) 
{
	unsigned int one_vector=32*PQS_n/10;
	unsigned int byte_bank_length=PQS_l*one_vector+10;
  	// Note: buffer size of 2465 bytes guarantees successful rejection sampling with probability >=0.999
	// following the Hoeffding's inequality (this bound is calculated for default parameters PQS_gamma=1048096, PQS_n=256, PQS_l=3)
	unsigned char buf[byte_bank_length+3];

	shake128(buf,byte_bank_length+3,seed,SEEDBYTES);

	uint32_t coef=0;
	unsigned int ncoeffs=0;
	unsigned int pos = 0;
	int j=0;
	
	for(j=0; j<PQS_l; j++){
		ncoeffs = 0;
		while(ncoeffs<PQS_n && pos <= byte_bank_length){
			coef  = buf[pos++];
			coef |= (uint32_t)buf[pos++] << 8;
			coef |= (uint32_t)buf[pos++] << 16;
			coef &= 0x1FFFFF;

			if(coef <= PQS_gamma-1){ // Accept as a non-negative coefficient
				a.polynomial[j].coeffs[ncoeffs] = coef;
				ncoeffs++;
			} else if(coef <= 2*(PQS_gamma-1)){ // Accept as a negative coefficient
				a.polynomial[j].coeffs[ncoeffs] = PQS_q - coef + (PQS_gamma - 1);
				ncoeffs++;
			} // Else reject
		
		}
	}  
	
	if(ncoeffs < PQS_n){
		cerr << "ERROR :: Too short buffer in GenSecret_y(), restarting...";
		GenSeed(seed);
		GenSecret_y(a, seed);
	}
}

// Generate a matrix polyrot (of size k*l) at random
void GenMatrix(polymatkl &A, const unsigned char *seed) 
{
  unsigned int one_vector=23*PQS_n/8; // Number of bytes for one polynomial with 23-bit coefficients
  unsigned int byte_bank_length=PQS_k*PQS_l*one_vector;
  unsigned char buf[byte_bank_length];

  int i,j,k;

  shake128(buf,byte_bank_length,seed,SEEDBYTES);
  
  for(i=0;i<PQS_k;i++)
  {
    for(j=0;j<PQS_l;j++)
    {
		BS2POL(buf+(i*PQS_l+j)*one_vector, A.elem[i][j].row[0]);
		if(i+j == 0){ // make a[0,0] invertible, i.e. force all coefficients but coeffs[0] to be even
			for(k=1; k<PQS_n; k++){
				A.elem[0][0].row[0].coeffs[k] &= 0xFFFFFFFE;
			}
			A.elem[0][0].row[0].coeffs[0] |= 1;
		}
		// We do not use a rotation matrix in this implementation, though computing rot(A) is implemented
		//fillpolyrot(A.elem[i][j]);
		
    }
  }
}

// Round an integer PQS_q -> PQS_p
uint32_t round (uint32_t x){
	uint32_t h = (1 << (PQS_nu - PQS_mu - 1));
	uint32_t mod = PQS_q-1;
	return ((x + h) & (mod)) >> (PQS_nu - PQS_mu);
}

// Take d high bits from Z_q integer
uint32_t MSB (uint32_t x, uint32_t d){
	uint32_t h = ((1 << d) - 1) << (PQS_nu - d);
	return (x & h) >> (PQS_nu - d);
}

// Take d low bits from Z_q integer
uint32_t LSB (uint32_t x, uint32_t d){
	uint32_t mod = (1 << d) - 1;
	return (x & mod);
}

// Multiply a matrix (of size k*l) by a vector (of size l), result = vector(of size k) 
void matrixpoly(polymatkl &mat, polyvecl &a, polyveck &res){
	int i, j, k;
	uint64_t int_acc;
	poly acc;
	memset(&res, 0, sizeof(polyveck));
	for(j=0; j<PQS_k; j++){
		for(k=0; k<PQS_l; k++){
			memset(&acc, 0, sizeof(poly));
			POLYMUL_MODE(mat.elem[j][k].row[0], a.polynomial[k], acc, PQS_n, PQS_q);
			// Add accumulator to res[j]
			for(i=0; i<PQS_n; i++){
				int_acc = res.polynomial[j].coeffs[i] + acc.coeffs[i];
				res.polynomial[j].coeffs[i] = int_acc & (PQS_q-1);
			}
		}
	}
}


// ********************************
// Keypair generation, Sign, Verify PROCEDURES
// ********************************

/*************************************************
* Name:        PQS_keygen
*
* Description: Generates a keypair
* Output:      A secret key (sk.s), public key (vk.seedA, vk.t)
*
* Arguments:   - vk_t &vk
*              - sk_t &sk
**************************************************/

void PQS_keygen(vk_t &vk, sk_t &sk){
	int i,j;
	GenSeed(vk.seedA); // Generate a seed for matrix A
	
	polymatkl matA;
	GenMatrix(matA, vk.seedA);	//sample matrix A
	#ifdef DEBUG_MODE
	// Show matrix matA (k*l random polynomials)
	cerr << "------------ PUBLIC KEY :: MATRIX A -------------" << endl;
	for(i=0; i<PQS_k; i++){
		for(j=0; j<PQS_l; j++){
			cerr << "A[" << i << "][" << j << "] = ";
			print_polystruct(matA.elem[i][j].row[0], PQS_n, PQS_q);
			//cerr << "Invertible: " << poly_invertible(matA[k].vec[0], PQS_n, PQS_q) << endl;
		}
	}
	#endif
	
	// Generate vector s
	GenSecret_s(sk.s);
	#ifdef DEBUG_MODE
	// Show vector s (l random polynomials)
	cerr << "------------ SECRET KEY :: VECTOR s ------------" << endl;
	for(i=0; i<PQS_l; i++){
		cerr << "s[" << i << "] = ";
		print_polystruct(sk.s.polynomial[i], PQS_n, PQS_q);
	}
	#endif
	
	// Calculate vector t
	matrixpoly(matA, sk.s, vk.t);
	// Round t[j]
	for(j=0; j<PQS_k; j++){
		for(i=0; i<PQS_n; i++){
			vk.t.polynomial[j].coeffs[i] = round(vk.t.polynomial[j].coeffs[i]);
		}
	}
	#ifdef DEBUG_MODE
	// Show vector t (k polynomials)
	cerr << "------------ PUBLIC KEY :: VECTOR t -------------" << endl;
	for(i=0; i<PQS_k; i++){
		cerr << "t[" << i << "] = ";
		print_polystruct(vk.t.polynomial[i], PQS_n, PQS_q);
	}
	#endif
}


/*************************************************
* Name:        PQS_sign
*
* Description: Signs a message (m) with a secret key (sk), public key (vk)
* Output:      A signature (sig) = (sig.z, sig.c)
*
* Arguments:   - signat_t &sig: Output signature
*              - const unsigned char *m: message to be signed
*              - uint32_t mlen: message length
*              - sk_t &sk: a secret key
*              - vk_t &vk: a public key
**************************************************/

void PQS_sign(signat_t &sig, const unsigned char *m, uint32_t mlen, sk_t &sk, vk_t &vk){
	int i, j;
	unsigned char seed[SEEDBYTES];
	uint8_t mu[CRHBYTES];
	
	polymatkl matA;
	GenMatrix(matA, vk.seedA);	//sample matrix A
	
	uint32_t mod = (1 << (PQS_nu - PQS_mu));
	uint32_t delta1 = (1 << (PQS_nu-PQS_mu+1))*PQS_omega;
	uint32_t bound1 = (1 << (PQS_nu-PQS_d)) - 2*delta1 - 1;
	uint32_t bound2 = PQS_gamma - PQS_beta;
	uint32_t w1, z1;
	
	sgn:
	GenSeed(seed);
	// Generate intermediate vector y
	polyvecl y;
	GenSecret_y(y, seed);
	
	#ifdef DEBUG_MODE
	// Show vector y (l polynomials)
	cerr << "------------ SIGNING PROCEDURE :: VECTOR y -------------" << endl;
	for(int k=0; k<PQS_l; k++){
		cerr << "y[" << k << "] = ";
		print_polystruct(y.polynomial[k], PQS_n, PQS_q);
	}
	#endif
	
	// Prepare w=MSB(A*y, d)
	polyveck w;
	matrixpoly(matA, y, w);
	
	#ifdef DEBUG_MODE
	// Show vector w (k polynomials)
	cerr << "------------ SIGNING PROCEDURE :: VECTOR A*y -------------" << endl;
	for(int k=0; k<PQS_k; k++){
		cerr << "A*y[" << k << "] = ";
		print_polystruct(w.polynomial[k], PQS_n, PQS_q);
	}
	#endif
	
	for(j=0; j<PQS_k; j++)
		for(i=0; i<PQS_n; i++){
			w.polynomial[j].coeffs[i] = MSB(w.polynomial[j].coeffs[i], PQS_d);
		}
	
	#ifdef DEBUG_MODE
	// Show vector w (k polynomials)
	cerr << "------------ SIGNING PROCEDURE :: VECTOR MSB(A*y) -------------" << endl;
	for(int k=0; k<PQS_k; k++){
		cerr << "w[" << k << "] = ";
		print_polystruct(w.polynomial[k], PQS_n, PQS_q);
	}
	#endif
	
	// CRH(m) -> mu
	memset(mu, 0, sizeof(uint8_t)*CRHBYTES);
	crh(mu, m, mlen);
	#ifdef DEBUG_MODE
	// Show a hash mu
	cerr << "------------ SIGNING PROCEDURE :: CRH(Message) -------------" << endl;
	for(int k=0; k<CRHBYTES; k++){
		cerr << mu[k] << " ";
	}
	cerr << endl;
	#endif	
	
	// Generate polynomial c
	challenge(sig.c, &mu[0], w);
	
	#ifdef DEBUG_MODE
	// Show polynomial c (challenge)
	cerr << "------------ SIGNING PROCEDURE :: POLYNOMIAL c -------------" << endl;
		print_polystruct(sig.c, PQS_n, PQS_q);
	#endif
	
	// Calculate z
	for(i=0; i<PQS_l; i++){
		POLYMUL_MODE(sk.s.polynomial[i], sig.c, sig.z.polynomial[i], PQS_n, PQS_q);
		// add y[i] to z[i]
		for(j=0; j<PQS_n; j++){
			sig.z.polynomial[i].coeffs[j] += y.polynomial[i].coeffs[j];
			sig.z.polynomial[i].coeffs[j] &= (PQS_q - 1); // Reduce modulo q
		}
	}
	
	#ifdef DEBUG_MODE
	// Show vector z (l polynomials)
	cerr << "------------ SIGNING PROCEDURE :: VECTOR z -------------" << endl;
	for(int k=0; k<PQS_l; k++){
		cerr << "z[" << k << "] = ";
		print_polystruct(sig.z.polynomial[k], PQS_n, PQS_q);
	}
	#endif
	
	// Calculate w (memory is already allocated, we don't need old w anymore
	matrixpoly(matA, sig.z, w);
	
	poly subpoly;
	for(i=0; i<PQS_k; i++){
		POLYMUL_MODE(vk.t.polynomial[i], sig.c, subpoly, PQS_n, PQS_q);
		for(j=0; j<PQS_n; j++){
			subpoly.coeffs[j] *= mod;
			w.polynomial[i].coeffs[j] -= subpoly.coeffs[j];
			w.polynomial[i].coeffs[j] &= (PQS_q-1);
		}
	}
	
	#ifdef DEBUG_MODE
	// Show vector w (k polynomials)
	cerr << "------------ SIGNING PROCEDURE :: VECTOR w -------------" << endl;
	for(int k=0; k<PQS_k; k++){
		cerr << "w[" << k << "] = ";
		print_polystruct(w.polynomial[k], PQS_n, PQS_q);
	}
	#endif
	
	for(i=0; i<PQS_k; i++){ // Check w norm bound
		for(j=0; j<PQS_n; j++){
			w1 = LSB(w.polynomial[i].coeffs[j], PQS_nu-PQS_d);
			w1 -= (delta1 + 1);
			if(w1 >= bound1){
				//cerr << "PQS_sign() RESTARTING (bad w) ... " << endl;
				goto sgn;
			}
		}
	}
	
	for(i=0; i<PQS_l; i++){ // Check z norm bound
		for(j=0; j<PQS_n; j++){
			z1 = sig.z.polynomial[i].coeffs[j] - bound2;
			if(z1 <= PQS_q - 2*bound2 - 1){
				//cerr << "PQS_sign() RESTARTING (bad z) ... " << endl;
				goto sgn;
			}
		}
	}
}

/*************************************************
* Name:        PQS_verify
*
* Description: Verifies a signature (sig) of a message (m) using a public key (vk)
* Return value:  true (accept) or false (reject)
*
* Arguments:   - signat_t &sig: input signature to be verified
*              - const unsigned char *m: input message
*              - uint32_t mlen: message length
*              - vk_t &vk: A public key
**************************************************/

bool PQS_verify(signat_t &sig, const unsigned char *m, uint32_t mlen, vk_t &vk){
	int i,j;
	
	polymatkl matA;
	GenMatrix(matA, vk.seedA);	//sample matrix A
	
	// Calculate MSB(w, d)
	polyveck w;
	matrixpoly(matA, sig.z, w);
	uint32_t mod = (1 << (PQS_nu - PQS_mu));
	poly subpoly;
	for(i=0; i<PQS_k; i++){
		POLYMUL_MODE(vk.t.polynomial[i], sig.c, subpoly, PQS_n, PQS_q);
		for(j=0; j<PQS_n; j++){
			subpoly.coeffs[j] *= mod;
			w.polynomial[i].coeffs[j] -= subpoly.coeffs[j];
			w.polynomial[i].coeffs[j] = MSB(w.polynomial[i].coeffs[j] & (PQS_q-1), PQS_d);
		}
	}
	
	// CRH(m) -> mu
	uint8_t mu[CRHBYTES];
	memset(mu, 0, sizeof(uint8_t)*CRHBYTES);
	crh(mu, m, mlen);
	#ifdef DEBUG_MODE
	// Show a hash mu
	cerr << "------------ VERIFYING PROCEDURE :: CRH(Message) -------------" << endl;
	for(int k=0; k<CRHBYTES; k++){
		cerr << mu[k] << " ";
	}
	cerr << endl;
	#endif	
	
	// Generate polynomial cprime
	poly cprime;
	memset(&cprime, 0, sizeof(poly));
	challenge(cprime, &mu[0], w);
	
	#ifdef DEBUG_MODE
	// Show polynomial cprime (challenge)
	cerr << "------------ VERIFYING PROCEDURE :: POLYNOMIAL c' -------------" << endl;
		print_polystruct(cprime, PQS_n, PQS_q);
	#endif
	
	// Check z infinity norm
	uint32_t bound2 = PQS_gamma - PQS_beta;
	uint32_t z1;
	for(i=0; i<PQS_l; i++){
		for(j=0; j<PQS_n; j++){
			z1 = sig.z.polynomial[i].coeffs[j] - bound2 - 1;
			if(z1 < PQS_q - 2*bound2 - 2) return false;
		}
	}
	
	if(memcmp(&sig.c, &cprime, sizeof(poly)) != 0) return false;
	return true;
}
