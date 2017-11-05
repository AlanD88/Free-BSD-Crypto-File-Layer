#
# Makefile for protectfile.c program.
#
# $Id: Makefile,v 1.2 2003/04/15 00:26:33 elm Exp elm $
# NOTE: has GNU make specific stuff

SRCS = protectfile.c rijndael.c setkey.c getkey.c
INCS = rijndael.h
PROGS = protectfile setkey getkey
OTHERS = testfile Makefile
DIR = $(notdir $(PWD))
TAR = tar
TARFILE = aes.tgz

COBJS = rijndael.o
CFLAGS = -O3

all: $(PROGS)

protectfile: protectfile.o $(COBJS) $(INCS)
	$(CC) $(CFLAGS) -o $@ protectfile.o $(COBJS)

setkey: setkey.o $(COBJS) $(INCS)
	$(CC) $(CFLAGS) -o $@ setkey.o $(COBJS)

getkey: getkey.o $(COBJS) $(INCS)
	$(CC) $(CFLAGS) -o $@ getkey.o $(COBJS)

rijndael.o: rijndael.h

tarball:
	cd .. ; $(TAR) cvf - $(addprefix $(DIR)/, $(SRCS) $(INCS) $(OTHERS)) | gzip - > $(TARFILE)

test: all
	cp testfile testfile.orig~
	./protectfile 0x1234 0x5678 testfile
	./protectfile 0x1234 0x5678 testfile
	diff testfile testfile.orig~

clean:
	rm -f *.o $(objects)

spotless: clean
	rm -f $(PROGS)