CC?=gcc
CFLAGS?=-O -g -fstack-protector-all
LIBS=`[ \`uname\` = "SunOS" ] && echo -lsocket -lnsl`

all: dawnhttpd

dawnhttpd: dawnhttpd.c
	$(CC) $(CFLAGS) -g $(LIBS) dawnhttpd.c -o $@

clean:
	rm -f dawnhttpd core dawnhttpd.core

install:
	-cp dawnhttpd /usr/sbin

.PHONY: all clean
