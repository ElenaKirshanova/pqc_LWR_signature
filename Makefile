CC       = g++
CFLAGS   = -c -Wall -O3
LDLIBS   = -lcrypto

OBJS     = keygen.o sign.o verify.o
TEST_OBJ = test/cpucycles.o
KAT_OBJ  = KAT/rng.o KAT/api.o
UTIL_OBJ = utils/arith.o utils/core.o utils/fips202.o utils/poly_mul.o utils/randombytes.o utils/serialize_common.o utils/serialize.o
UTIL_HDR = utils/params.h utils/matrix_A.h utils/utils.h

INSTALL_PATH?=/usr/local

# GENERAL

all: $(OBJS) $(UTIL_OBJ)

kat: $(KAT_OBJ) KAT/PQCgenKAT_sign
	cd KAT; ./PQCgenKAT_sign

test: $(TEST_OBJ) test/pqs_test
	./test/pqs_test

# if library has been installed this version can be used
#test: $(TEST_OBJ) test/pqs_test -lpqs
#	./test/pqs_test

install: $(OBJS)
	ar rcs libpqs.a $(OBJS); 
	@mkdir -p $(INSTALL_PATH);
	@cp -p libpqs.a $(INSTALL_PATH)/lib/;
	@mkdir -p $(INSTALL_PATH)/include/pqs; 
	@cp -p pqs.h $(INSTALL_PATH)/include/pqs;
	@mkdir -p $(INSTALL_PATH)/include/pqs/utils;
	@chmod 664 utils/*.h
	@cp -p utils/params.h $(INSTALL_PATH)/include/pqs/utils/;
	@cp -p utils/randombytes.h $(INSTALL_PATH)/include/pqs/utils/;

# MODULES

keygen.o: keygen.c keygen.h pqs.h $(UTIL_OBJ)
	$(CC) $(CFLAGS) -c $< -o $@ 

sign.o: sign.c sign.h pqs.h $(UTIL_OBJ)
	$(CC) $(CFLAGS) -c $< -o $@

verify.o: verify.c verify.h pqs.h sign.o $(UTIL_OBJ)
	$(CC) $(CFLAGS) -c $< -o $@

# UTILITIES

utils/%.o: utils/%.c utils/%.h $(UTIL_HDR)
	$(CC) $(CFLAGS) -c $< -o $@

# TESTS

test/pqs_test: $(OBJS) $(UTIL_OBJ) $(TEST_OBJ) test/pqs_test.c test/pqs_test.h test/test_config.h
	$(CC) $(OBJS) $(UTIL_OBJ) $(TEST_OBJ) test/pqs_test.c -o test/pqs_test

# KAT

KAT/rng.o: KAT/rng.c KAT/rng.h 
	$(CC) $(CFLAGS) -c $< -o $@

KAT/api.o: KAT/api.c KAT/api.h
	$(CC) $(CFLAGS) -c $< -o $@

KAT/PQCgenKAT_sign: $(OBJS) $(UTIL_OBJ) $(KAT_OBJ) KAT/PQCgenKAT_sign.c
	$(CC) $(OBJS) $(UTIL_OBJ) $(KAT_OBJ) KAT/PQCgenKAT_sign.c -o KAT/PQCgenKAT_sign $(LDLIBS)


# Clean

clean:
	rm -rf *.o utils/*.o test/pqs_test *.a

clean_kat:
	rm -rf KAT/rng.o KAT/PQCgenKAT_sign

clean_test:
	rm -rf test/*.o test/pqs_test
