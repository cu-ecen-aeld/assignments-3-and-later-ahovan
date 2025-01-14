# Makefile for aesdsocket (Assignment 5 part 1)

CC=$(CROSS_COMPILE)gcc
CFLAGS=-Wall -Werror

aesdsocket: aesdsocket.c
	$(CC) $(CFLAGS) aesdsocket.c -o aesdsocket

all:	aesdsocket

.PHONY: clean

clean:
	@rm -f aesdsocket

run:	all
	./aesdsocket
