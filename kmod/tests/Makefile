# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
#
# Userspace lifecycle tests for the sstp kmod.
#
#     make            # build test_sstp
#     make run        # build, ensure module loaded, run as root
#     make clean
#
# Requires libssl-dev (OpenSSL 3.x for SSL_OP_ENABLE_KTLS).

CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
LDFLAGS ?=
LDLIBS  := -lssl -lcrypto -lpthread

TESTS := test_sstp

.PHONY: all clean run

all: $(TESTS)

test_sstp: test_sstp.c ../../kernel-abi/sstp.h
	$(CC) $(CFLAGS) -o $@ test_sstp.c $(LDFLAGS) $(LDLIBS)

run: all
	@bash ./run-tests.sh

clean:
	rm -f $(TESTS)
