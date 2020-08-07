CC=g++ -std=c++11
CFLAGS=-c -Wall
CFLAGS2  = -Wall -Wextra -O3 -fomit-frame-pointer -march=native
INC = -I.

all: poly_mul.o randombytes.o fips202.o speed.o cpucycles.o sign.o pqs_test.o pqs_test

poly_mul.o: poly_mul.c
	$(CC) $(CFLAGS) $(INC) -c $< 

randombytes.o: randombytes.c
	$(CC) $(CFLAGS2) -c randombytes.c -lcrypto -o $@
	
fips202.o: fips202.c
	$(CC) $(CFLAGS) -c fips202.c -lcrypto -o $@

speed.o: speed.c
	$(CC) $(CFLAGS) $(INC) -c $< -lcrypto -o $@
	
cpucycles.o: cpucycles.c
	$(CC) $(CFLAGS) $(INC) -c $< -lcrypto -o $@
	
sign.o: sign.c
	$(CC) $(CFLAGS) $(INC) -c $< -lcrypto -o $@
	
pqs_test.o: pqs_test.c
	$(CC) $(CFLAGS) $(INC) -c $< -lcrypto -o $@

pqs_test: poly_mul.o randombytes.o fips202.o speed.o cpucycles.o sign.o pqs_test.o cpucycles.c
	$(CC) poly_mul.o randombytes.o fips202.o sign.o cpucycles.c pqs_test.o -lcrypto -o pqs_test

clean:
	rm -rf *.o pqs_test
