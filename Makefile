CC=gcc
CFLAGS?=-O -g -fstack-protector-all -DENABLE_SERVER -DENABLE_SSL_TLS -I/usr/local/include -I/usr/local/include/openssl
#SUNLIBS=`[ \`uname\` = "SunOS" ] && echo -lsocket -lnsl`
LIBS=${SUNLIBS} -Wl,-rpath=/usr/local/lib:/usr/lib -lcrypt -lpthread -lresolv -ltls -ldl

all: dawnhttpd

dawnhttpd: dawnhttpd.c cdecode.c
	$(CC) $(CFLAGS) $(LIBS) dawnhttpd.c cdecode.c -o $@

clean:
	rm -f dawnhttpd core dawnhttpd.core

install:
	-cp dawnhttpd /usr/sbin

.PHONY: all clean
