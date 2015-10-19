#!/usr/bin/make -f

CFLAGS = -O2 -Wall -Wextra -std=c11 -ggdb
LDLIBS = -lcrypto

TARGETS := \
	calc_crc32 \
	extract_fwupd \
	extract_secrets \
	extract_testkeys \
	lz77

all: $(TARGETS)

calc_crc32: crc32.o
extract_fwupd: crc32.o secrets.o
extract_secrets extract_testkeys: secrets.o

clean:
	$(RM) $(TARGETS) $(wildcard *.o)
