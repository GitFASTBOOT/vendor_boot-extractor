APP = unpack_vendor_boot
CC = gcc
CFLAGS = -Wall -O2
LIBS = -lz  # Link with zlib library
SOURCES = main.c

all: $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $(APP) $(LIBS)  # Make sure LIBS is passed here

clean:
	-rm -f $(APP)

.PHONY: all clean

