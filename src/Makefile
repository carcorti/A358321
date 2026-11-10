# Canonical A358321 build. Copyright (c) 2026 Carlo Corti.
CC = gcc-13
CFLAGS = -O3 -march=native -mtune=native -flto -funroll-loops -fomit-frame-pointer -std=c17 -fopenmp -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wdouble-promotion -Wformat=2
LDLIBS = -lm

.PHONY: all test clean
all: a358321

a358321: a358321.c Makefile
	$(CC) $(CFLAGS) -DBUILD_FLAGS='"$(CFLAGS)"' a358321.c -o $@ $(LDFLAGS) $(LDLIBS)

test: a358321
	./a358321 selftest
	python3 -I -B ../check/verify.py --test-build ./a358321 --cc "$(CC)"

clean:
	rm -f a358321
