
CC = gcc
CFLAGS = -Wall -Werror -O2 -pedantic  -funroll-loops
LIBFLAGS= -lpcap 
SRC = mySniffer.c
HEADER = mySniffer.h
BIN = sniffer

sniffer: $(SRC) $(HEADER)
	$(CC) $(CFLAGS) $(LIBFLAGS) -o $(BIN) *.c

bsd: $(SRC) $(HEADER)
	$(CC) $(CFLAGS) $(LIBFLAGS) -ansi -o $(BIN) *.c	

linux: $(SRC) $(HEADER)
	$(CC) $(CFLAGS) $(LIBFLAGS) -DLINUX -o $(BIN) *.c

clean:
	rm -rf $(BIN)

