// ---------------------------------------
// --- poly_mul.c ------------------------
// --- This file has been adapted from SABER KEM implementation
// ---------------------------------------

#include "poly_mul.h"
#include <NTL/ZZ_pEX.h>

#define N_RES (PQS_n << 1)
#define N_SB (PQS_n >> 2)
#define N_SB_RES (2*N_SB-1)

//using namespace NTL;

/**
 * Polynomial multiplication using the schoolbook method, c[x] = a[x]*b[x] 
 * SECURITY NOTE: TO BE USED FOR TESTING ONLY.  
 * Source code: SABERONESP32
 * https://github.com/SABERONESP32/SABERONESP32/blob/master/SABERONESP32/src/polymul_hw_common.c
 * 
**/

void print_polystruct(poly &a, int64_t n, uint64_t p){

    int i;
    for (i = n - 1; i >= 0; i--){
        if (a.coeffs[i] != 0){
                if(i!=0){
                    #if DEBUG_OUTPUTMODE == 1
                    printf("  %u*x^%d + ", a.coeffs[i],i); // Output for SAGE
                    #elif DEBUG_OUTPUTMODE == 2
                    printf("  Mod(%d,%u)*x^%d + ", a.coeffs[i], p, i); // Output for PARIGP
                    #endif
                } else {
                    #if DEBUG_OUTPUTMODE == 1
                    printf("  %u*x^%d ", a.coeffs[i], i); // Outout for SAGE
                    #elif DEBUG_OUTPUTMODE == 2
                    printf("  Mod(%d,%u)*x^%d ", a.coeffs[i], p, i); // Outout for PARIGP
                    #endif
                }
            }
    }

    printf("\n-----------------------\n");
}

/**
 * Polynomial multiplication using the schoolbook method, c[x] = a[x]*b[x] 
 * SECURITY NOTE: TO BE USED FOR TESTING ONLY.  
 * Source code: SABERONESP32
 * https://github.com/SABERONESP32/SABERONESP32/blob/master/SABERONESP32/src/polymul_hw_common.c
 * 
**/

void schoolbook_mul(poly &a, poly &b, poly &res, uint32_t n, uint32_t p) {
    uint32_t i;
    uint32_t j, mask = 2 * n;
    //-------------------normal multiplication-----------------
    int64_t c[2 * n];

    memset (c, 0, mask * 64);
    for (i = 0; i < n; i++) {
        for (j = 0; j < n; j++) {
            c[i + j] += (int64_t) (a.coeffs[i] * b.coeffs[j]);
        }
    }
    //---------------reduction-------
    int64_t t;
    for (i = n; i < 2 * n; i++) {
        //c[i - n] = (c[i - n] - c[i]);    // % KYBER_Q;//& (p - 1);
        t = (c[i - n] - c[i]) % p;
        if (t < 0) {
            t += p;
        }
        res.coeffs[i - n] = t;
    }
}


/**
 * Polynomial multiplication using SABER hybrid method (toom-cook 4-way + Karatsuba + Schoolbook), c[x] = a[x]*b[x] 
 * See the following paper for details: https://eprint.iacr.org/2020/268.pdf
 * 
**/

void cook_karatsuba_mul(poly &a_poly, poly &b_poly, poly &res, uint32_t n, uint32_t p){ 

    uint32_t i;

//-------------------normal multiplication-----------------

    uint32_t c[512];
    int32_t *a = a_poly.coeffs;
    int32_t *b = b_poly.coeffs;

    memset(c, 0, 2048);  // number of bytes = 512 * sizeof (int32_t) = 2048

    toom_cook_4way(a, b, c);

    //---------------reduction-------
    for(i=n;i<2*n;i++){
        res.coeffs[i-n]=(c[i-n]-c[i])&(p-1);
    }

}

void karatsuba_simple(const uint32_t* a_1, const uint32_t* b_1, uint32_t* result_final){//uses 10 registers

    uint32_t N=64;
    uint32_t d01[N/2-1];
    uint32_t d0123[N/2-1];
    uint32_t d23[N/2-1];
    uint32_t result_d01[N-1];    

    uint32_t i,j;

    memset(result_d01,0,(N-1)*sizeof(uint32_t));
    memset(d01,0,(N/2-1)*sizeof(uint32_t));
    memset(d0123,0,(N/2-1)*sizeof(uint32_t));
    memset(d23,0,(N/2-1)*sizeof(uint32_t));
    memset(result_final,0,(2*N-1)*sizeof(uint32_t));

    uint32_t acc1,acc2,acc3,acc4,acc5,acc6,acc7,acc8,acc9,acc10;


    for (i = 0; i < N/4; i++) {
        acc1=a_1[i];//a0
        acc2=a_1[i+N/4];//a1
        acc3=a_1[i+2*N/4];//a2
        acc4=a_1[i+3*N/4];//a3    
        for (j = 0; j < N/4; j++) {

            acc5=b_1[j];//b0
            acc6=b_1[j+N/4];//b1

            result_final[i+j+0*N/4]=result_final[i+j+0*N/4]+acc1*acc5;
            result_final[i+j+2*N/4]=result_final[i+j+2*N/4]+acc2*acc6;

            acc7=acc5+acc6;//b01
            acc8=acc1+acc2;//a01
            d01[i+j]=d01[i+j] + acc7*acc8;
    //--------------------------------------------------------

            acc7=b_1[j+2*N/4];//b2
            acc8=b_1[j+3*N/4];//b3            
            result_final[i+j+4*N/4]=result_final[i+j+4*N/4]+acc7*acc3;

            result_final[i+j+6*N/4]=result_final[i+j+6*N/4]+acc8*acc4;

            acc9=acc3+acc4;
            acc10=acc7+acc8;
            d23[i+j]=d23[i+j] + acc9*acc10;
    //--------------------------------------------------------

            acc5=acc5+acc7;//b02
            acc7=acc1+acc3;//a02
            result_d01[i+j+0*N/4]=result_d01[i+j+0*N/4]+acc5*acc7;

            acc6=acc6+acc8;//b13
            acc8=acc2+acc4;            
            result_d01[i+j+ 2*N/4]=result_d01[i+j+ 2*N/4]+acc6*acc8;

            acc5=acc5+acc6;
            acc7=acc7+acc8;
            d0123[i+j]=d0123[i+j] + acc5*acc7;
        }
    }

//------------------2nd last stage-------------------------

    for(i=0;i<N/2-1;i++){
        d0123[i]=d0123[i]-result_d01[i+0*N/4]-result_d01[i+2*N/4];
        d01[i]=d01[i]-result_final[i+0*N/4]-result_final[i+2*N/4];
        d23[i]=d23[i]-result_final[i+4*N/4]-result_final[i+6*N/4];
    }

    for(i=0;i<N/2-1;i++){
        result_d01[i+1*N/4]=result_d01[i+1*N/4]+d0123[i];
        result_final[i+1*N/4]=result_final[i+1*N/4]+d01[i];
        result_final[i+5*N/4]=result_final[i+5*N/4]+d23[i];
    }

//------------Last stage---------------------------
    for(i=0;i<N-1;i++){
        result_d01[i]=result_d01[i]-result_final[i]-result_final[i+N];
    }
    
    for(i=0;i<N-1;i++){
        result_final[i+1*N/2]=result_final[i+1*N/2]+result_d01[i];//-result_d0[i]-result_d1[i];        
    }

}



void toom_cook_4way(int32_t* a1, int32_t* b1, uint32_t* result)
{
    uint32_t inv3 = 2796203, inv9 = 6524473, inv15 = 7270127;

    uint32_t aw1[N_SB], aw2[N_SB], aw3[N_SB], aw4[N_SB], aw5[N_SB], aw6[N_SB], aw7[N_SB];
    uint32_t bw1[N_SB], bw2[N_SB], bw3[N_SB], bw4[N_SB], bw5[N_SB], bw6[N_SB], bw7[N_SB];
    uint32_t w1[N_SB_RES] = {0}, w2[N_SB_RES] = {0}, w3[N_SB_RES] = {0}, w4[N_SB_RES] = {0},
             w5[N_SB_RES] = {0}, w6[N_SB_RES] = {0}, w7[N_SB_RES] = {0};
    uint32_t r0, r1, r2, r3, r4, r5, r6, r7;
    uint32_t *A0, *A1, *A2, *A3, *B0, *B1, *B2, *B3;
    A0 = (uint32_t*)a1;
    A1 = (uint32_t*)&a1[N_SB];
    A2 = (uint32_t*)&a1[2*N_SB];
    A3 = (uint32_t*)&a1[3*N_SB];
    B0 = (uint32_t*)b1;
    B1 = (uint32_t*)&b1[N_SB];
    B2 = (uint32_t*)&b1[2*N_SB];
    B3 = (uint32_t*)&b1[3*N_SB];

    uint32_t * C;
    C = result;

    int i,j;

// EVALUATION
    for (j = 0; j < N_SB; ++j) {
        r0 = A0[j];
        r1 = A1[j];
        r2 = A2[j];
        r3 = A3[j];
        r4 = r0 + r2;
        r5 = r1 + r3;
        r6 = r4 + r5;  r7 = r4 - r5;  
        aw3[j] = r6;
        aw4[j] = r7;
        r4 = ((r0 << 2)+r2) << 1;
        r5 = (r1 << 2) + r3;
        r6 = r4 + r5; r7 = r4 - r5; 
        aw5[j] = r6;
        aw6[j] = r7;
        r4 = (r3 << 3) + (r2 << 2) + (r1 << 1) + r0;
        aw2[j] = r4; aw7[j] = r0;
        aw1[j] = r3;
    }
    for (j = 0; j < N_SB; ++j) {
        r0 = B0[j];
        r1 = B1[j];
        r2 = B2[j];
        r3 = B3[j];
        r4 = r0 + r2;
        r5 = r1 + r3;
        r6 = r4 + r5; r7 = r4 - r5;
        bw3[j] = r6;
        bw4[j] = r7;
        r4 = ((r0 << 2)+r2) << 1;
        r5 = (r1 << 2) + r3;
        r6 = r4 + r5; r7 = r4 - r5;
        bw5[j] = r6;
        bw6[j] = r7;
        r4 = (r3 << 3) + (r2 << 2) + (r1 << 1) + r0;
        bw2[j] = r4; bw7[j] = r0;
        bw1[j] = r3;
    }

// MULTIPLICATION

    karatsuba_simple(aw1, bw1, w1);
    karatsuba_simple(aw2, bw2, w2);
    karatsuba_simple(aw3, bw3, w3);
    karatsuba_simple(aw4, bw4, w4);
    karatsuba_simple(aw5, bw5, w5);
    karatsuba_simple(aw6, bw6, w6);
    karatsuba_simple(aw7, bw7, w7);



// INTERPOLATION
    for (i = 0; i < N_SB_RES; ++i) {
        r0 = w1[i];
        r1 = w2[i];
        r2 = w3[i];
        r3 = w4[i];
        r4 = w5[i];
        r5 = w6[i];
        r6 = w7[i];

        r1 = r1 + r4;
        r5 = r5 - r4;
        r3 = ((r3-r2) >> 1);
        r4 = r4 - r0;
        r4 = r4 - (r6 << 6);
        r4 = (r4 << 1) + r5;
        r2 = r2 + r3;
        r1 = r1 - (r2 << 6) - r2;
        r2 = r2 - r6;
        r2 = r2 - r0;
        r1 = r1 + 45*r2;
        r4 = (((r4 - (r2 << 3))*inv3) >> 3);
        r5 = r5 + r1;
        r1 = (((r1 + (r3 << 4))*inv9) >> 1);
        r3 = -(r3 + r1);
        r5 = (((30*r1 - r5)*inv15) >> 2);
        r2 = r2 - r4;
        r1 = r1 - r5;
 
        C[i]     += r6;
        C[i+64]  += r5;
        C[i+128] += r4;
        C[i+192] += r3;
        C[i+256] += r2;
        C[i+320] += r1;
        C[i+384] += r0;
    }
}
