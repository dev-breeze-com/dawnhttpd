CC?=gcc
CFLAGS?=-O -g -fstack-protector-all -DENABLE_IPV6 -DENABLE_PASSWORD
SUNLIBS=`[ \`uname\` = "SunOS" ] && echo -lsocket -lnsl`
LIBS=${SUNLIBS} -lcrypt

all: dawnhttpd

dawnhttpd: dawnhttpd.c cdecode.c
	$(CC) $(CFLAGS) -g $(LIBS) dawnhttpd.c cdecode.c -o $@

clean:
	rm -f dawnhttpd core dawnhttpd.core

install:
	-cp dawnhttpd /usr/sbin

.PHONY: all clean
