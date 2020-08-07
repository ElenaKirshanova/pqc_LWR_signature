#ifndef CONFIG_H
#define CONFIG_H

// Show all intermediate calculations in a console
//#define DEBUG_MODE

#define DEBUG_OUTPUTMODE 1 // Output polynomials in SAGE style (if DEBUG_MODE is enabled)
//#define DEBUG_OUTPUTMODE 2 // Output polynomials in PARI/GP style (if DEBUG_MODE is enabled)

// Polynomial multiplication algorithm
//#define POLYMUL_MODE schoolbook_mul
#define POLYMUL_MODE cook_karatsuba_mul

#define NTESTS 1000
#define MLEN_TEST 20

#define TEST_MODE 1 // Detailed timing output for each test, small number of tests
//#define TEST_MODE 2 // For large number of tests
//#define TEST_MODE 3 // Test PQS performance as dilithium does

#endif
