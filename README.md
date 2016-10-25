README

   1. Introduction
   2. Building
   3. Configuraton
   4. Bugs
   5. Authors


INTRODUCTION

   dawnhttpd (Dawn HTTP deamon), derived from darkhttpd, is a simple web
   server written in portable ANSI C. It supports static pages, and MIME
   type based handlers. It can drop privileges before accepting connections;
   and, it can log received requests. It can log POST request data in a
   guestbook. It can, easily, be used in conjunction with Lighttpd as proxy.
   It compiles and runs on 32 and 64 bits computers.


BUILDING

   Install dawnhttpd by running the following commands, as root:
   make && make install


CONFIGURATION

   No configuration, see README.cmd.txt for commands.


BUGS

   Strange bug in the tuple_cmp function. Debug to see if it occurs 
   on your computer, where the const parameter o2 gets reset to NULL.

   Bug reports, patches and suggestions are much appreciated.  
   See the GitHub account https://www.github.com/dev-breeze-com/dawnhttpd

AUTHORS

   Pierre Innocent ( dev@breezeos.com )  
   The Breeze::OS website: http://www.breezeos.com

