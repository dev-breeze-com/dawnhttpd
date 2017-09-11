README
======

   1. Introduction
   2. Features
   3. Building
   4. Configuraton
   5. Bugs
   6. Fun facts
   7. Authors


INTRODUCTION
============

   dawnhttpd (Dawn HTTP deamon), derived from darkhttpd, is a simple web
   server written in portable ANSI C. It supports static pages, and MIME
   type based handlers. It can drop privileges before accepting connections;
   and, it can log received requests. It can log POST request data in a
   guestbook. It can, easily, be used in conjunction with Lighttpd as proxy.
   It supports basic throttling and basic http authentication. It compiles
   and runs on 32 and 64 bits computers.


FEATURES
========

   - INI-style configuration.
   - MIME type based handlers.
   - Support for guestboooks.
   - Support for basic memory cache.
   - Support for slocate requests.
   - Support for basic throttling (size in KB).
   - Support for basic authentication.


BUILDING
========

   Enable ipv6 by including -DENABLE_IPV6 in the Makefile CFLAGS.  
   Enable slocate by including -DENABLE_SLOCATE in the Makefile CFLAGS.  
   Enable guestbook by including -DENABLE_GUESTBOOK in the Makefile CFLAGS.  
   Enable pidfile by including -DENABLE_PIDFILE in the Makefile CFLAGS.  
   Enable password by including -DENABLE_PASSWORD in the Makefile CFLAGS.  

   Install dawnhttpd by running the following commands, as root:  
	   make && make install  

   Copy settings.ini to /etc/dawnhttpd/


CONFIGURATION
=============

   INI-style configuration was added for settings, passwords, and mimetypes.  
   Passwords must be in the format of the password entry in /etc/shadow (crypt).  
   Invoke the command *dawnhttpd --help* for help information.  
   See README.cmd.txt for additional command information.  
   Guestbook entry keys should be encased by '<%' and '%>'.


BUGS
====

   Strange bug in the tuple_cmp function.  
   Debug to see if it occurs on your computer, where the  const parameter o2 gets reset to NULL.  
   Bug reports, patches and suggestions are much appreciated.  
   See GitHub account https://www.github.com/dev-breeze-com/dawnhttpd


FUN FACTS
========= 

   On an AMD Athlon64 X2 (Mem 1G) running Linux 3.10.104-amd64, we get  
   weighttp -n 100000 -c 375 -k -H 'User-Agent: Weighttp' 127.0.0.1:8 0  
   weighttp - a lightweight and simple webserver benchmarking tool  
   starting benchmark...  
   spawning thread #1: 375 concurrent requests, 100000 total requests  
   progress: 10% done  
   ...  
   progress: 100% done  
   finished in 10 sec, 919 millisec and 115 microsec, 9158 req/s, 79580 kbyte/s  
   requests: 100000 total, 100000 started, 100000 done, 100000 succeeded, 0 failed, 0 errored  
   status codes: 100000 2xx, 0 3xx, 0 4xx, 0 5xx  
   traffic: 889800000 bytes total, 22000000 bytes http, 867800000 bytes data  


AUTHORS
=======

   Pierre Innocent ( dev@breezeos.com )  
   The Breeze::OS website: http://www.breezeos.com

