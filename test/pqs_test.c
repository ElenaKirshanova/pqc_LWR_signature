#include <cstdio>
#include <cstdlib>

#include "pqs_test.h"
//#include <pqs/pqs.h>    // can be used once lib has been installed, edit makefile to use -lpqs
#include "../pqs.h"       // can be used if lib is not installed

#include "cpucycles.h"
#include "getCPUTime.c"

#define TEST 1

int main (int argc, char **argv) {
    // Detailed output for each test, small number of tests.
    #if TEST_MODE == 1
    mode_1();

    // For large number of tests.
    #elif TEST_MODE == 2
    mode_2();

    // Test PQS performance as dilithium does.
    #elif TEST_MODE == 3
    mode_3();

    #endif

    return 0;
}

void mode_1() {
	double tm;

	tm = getCPUTime();
	for(int loop=0; loop<NTESTS; ++loop){

		vk_t vk; // Public key
		sk_t sk; // Secret key
        memset(&sk, 0, sizeof(sk_t));

        fprintf (stderr, "Generating keypair ... ");
		tm = getCPUTime();
		keygen (sk, vk);
        fprintf (stderr, "Ok\n");
        fprintf (stderr, "keypair is generated in %f sec.\n", getCPUTime() - tm);

		// A message to be signed
		// ToDo: Add input from a file
		unsigned char m[] = "My test message";
        unsigned int mlen = strlen ((char*) m);
		signat_t sig; // Signature
		tm = getCPUTime();
		sign (sk, vk, m, mlen, sig);
        fprintf (stderr, "Signed Ok\n");
        fprintf (stderr, "Signing is complete in %f sec.\n", getCPUTime() - tm);

		tm = getCPUTime();
		bool success = verify (vk, m, mlen, sig);
		if (success){
            fprintf (stderr, "Verify Ok\n");
		} else {
            fprintf (stderr, "Verify Fail\n");
			exit(-1);
		}

        fprintf (stderr, "Verification is completed in %f sec.\n", getCPUTime() - tm);
	}
}


void mode_2() {
	double tm;
	int failures = 0;

	vk_t vk; // Public key
	sk_t sk; // Secret key

	unsigned char m[] = "My test message is longer than forty-eight bytes...";
    unsigned int mlen = strlen ((char*) m);

	tm = getCPUTime( );
	for (int loop=0; loop<NTESTS; ++loop) {
        memset (&sk, 0, sizeof(sk_t));

		keygen (sk, vk);

		signat_t sig; // Signature
        sign (sk, vk, m, (unsigned int) mlen, sig);

		bool success = verify (vk, m, mlen, sig);
		if (!success) {
            fprintf (stderr, "Verify fail\n");
            failures += 1;
			//exit(-1);
		}

		if (loop % 10000 == 9999){
            fprintf (stderr, "%dk tests ok in %f sec.\n", (loop+1)/1000, getCPUTime() - tm);
			tm = getCPUTime();
		}
	}

    fprintf (stderr, "%d total verification failures.\n", failures);
}

static int cmp_llu (const void *a, const void *b) {
  if (*(unsigned long long *)a < *(unsigned long long *)b) return -1;
  if (*(unsigned long long *)a > *(unsigned long long *)b) return 1;
  return 0;
}

static unsigned long long median (unsigned long long *l, size_t llen) {
  qsort (l,llen,sizeof(unsigned long long),cmp_llu);

  if (llen%2) return l[llen/2];
  else return (l[llen/2-1]+l[llen/2])/2;
}

static unsigned long long average (unsigned long long *t, size_t tlen) {
  unsigned long long acc=0;
  size_t i;

  for (i=0;i<tlen;i++)
    acc += t[i];

  return acc/(tlen);
}

void print_results (const char *s, unsigned long long *t, size_t tlen) {
  unsigned long long tmp;

  printf ("%s\n", s);

  tmp = median (t, tlen);
  printf("median: %llu ticks @ 2.6 GHz (%.4g msecs)\n", tmp, MSECS (tmp));

  tmp = average(t, tlen);
  printf("average: %llu ticks @ 2.6 GHz (%.4g msecs)\n", tmp, MSECS (tmp));

  printf ("\n");
}


void mode_3() {
	unsigned long long tkeygen[NTESTS], tsign[NTESTS], tverify[NTESTS];
	unsigned char m[MLEN_TEST];
	unsigned int i;
	bool ret;
	vk_t vk;      // Public key
	sk_t sk;      // Secret key
	signat_t sig; // Signature
	timing_overhead = cpucycles_overhead();

	for (i=0; i<NTESTS; ++i){
        memset (&sk, 0, sizeof(sk_t));

		randombytes (m, MLEN_TEST);
		tkeygen[i] = cpucycles_start();
		keygen (sk, vk);
		tkeygen[i] = cpucycles_stop() - tkeygen[i] - timing_overhead;

		tsign[i] = cpucycles_start();
		sign (sk, vk, m, MLEN_TEST, sig);
		tsign[i] = cpucycles_stop() - tsign[i] - timing_overhead;
		//printf("%llu \n", tsign[i]);

		tverify[i] = cpucycles_start();
		ret = verify (vk, m, MLEN_TEST, sig);
		tverify[i] = cpucycles_stop() - tverify[i] - timing_overhead;

		if (!ret) {
			printf ("Verification failed\n");
			exit (-1);
		}

	}
  print_results ("keygen:", tkeygen, NTESTS);
  print_results ("sign: ", tsign, NTESTS);
  print_results ("verify: ", tverify, NTESTS);
}
