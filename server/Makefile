# Makefile for aesdsocket (Assignment 5 part 1)

CC?=$(CROSS_COMPILE)gcc
CFLAGS?=-Wall -Werror
LDFLAGS?=-lpthread -lrt

USE_AESD_CHAR_DEVICE=y
ifeq ($(USE_AESD_CHAR_DEVICE),y)
EXTRA_CFLAGS += -DUSE_AESD_CHAR_DEVICE
endif

aesdsocket: aesdsocket.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) aesdsocket.c -o aesdsocket

all:	aesdsocket

.PHONY: clean

clean:
	@rm -f aesdsocket *.o valgrind-*.txt

run:	all
	./aesdsocket

daemon:	all
	./aesdsocket -d

memcheck: all
	valgrind  --error-exitcode=1 --leak-check=full --show-leak-kinds=all \
	--track-origins=yes --errors-for-leak-kinds=definite --verbose \
	--log-file=valgrind-aesdsocket.txt ./aesdsocket