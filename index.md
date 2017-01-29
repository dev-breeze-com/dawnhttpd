README
======

   1. Introduction
   2. Building
   3. Configuraton
   4. Bugs
   5. Fun facts
   6. Authors


INTRODUCTION
============

   dawnhttpd (Dawn HTTP deamon), derived from darkhttpd, is a simple web
   server written in portable ANSI C. It supports static pages, and MIME
   type based handlers. It can drop privileges before accepting connections;
   and, it can log received requests. It can log POST request data in a
   guestbook. It can, easily, be used in conjunction with Lighttpd as proxy.
   It compiles and runs on 32 and 64 bits computers.


BUILDING
========

   Install dawnhttpd by running the following commands, as root:
   make && make install
   copy settings.ini to /etc/dawnhttpd/


CONFIGURATION
=============

   INI-style configuration was added, in the updated version.
   See README.cmd.txt for commands.
   Guestbook entry keys should be encased by '<%' and '%>'.


BUGS
====

   Strange bug in the tuple_cmp function. Debug to see if it occurs 
   on your computer, where the const parameter o2 gets reset to NULL.
   Bug reports, patches and suggestions are much appreciated.  
   See the GitHub account https://www.github.com/dev-breeze-com/dawnhttpd


Fun Facts
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

