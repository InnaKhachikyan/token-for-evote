CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto

all: rsa

rsa: rsa.c rsa_core.c rsa.h
	$(CC) $(CFLAGS) -o rsa rsa.c rsa_core.c $(LDFLAGS)

run: rsa
	./rsa

clean:
	rm -f rsa *.o

.PHONY: all run clean
