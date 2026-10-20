CC ?= cc
CFLAGS := -std=c11 -Wall -Wextra -Werror -O2 -g
UNAME_S := $(shell uname -s)

.PHONY: host test
host: build/mcd2-native

build/mcd2-native: runtime/image.c runtime/loader.c runtime/image.h runtime/gate.S Makefile
	mkdir -p build
ifeq ($(UNAME_S),Darwin)
	xcrun clang $(CFLAGS) -arch arm64 runtime/image.c runtime/loader.c runtime/gate.S -o $@
else
	$(CC) $(CFLAGS) runtime/image.c runtime/loader.c -o $@
endif

build/image_check: runtime/image.c runtime/image_check.c runtime/image.h Makefile
	mkdir -p build
	$(CC) $(CFLAGS) runtime/image.c runtime/image_check.c -o $@

test: build/mcd2-native build/image_check
	cd ../.. && python3 -m unittest tests.test_mcd2_probe tests.test_mcd2_load -v
