How to run dawnhttpd
--------------------

Serve /var/www/htdocs on the default port (80 if running as root, else 8080):
  $ ./dawnhttpd

Serve on port 8081:
  $ ./dawnhttpd --port 8081

Only bind to one IP address (useful on multi-homed systems):
  $ ./dawnhttpd --addr 192.168.0.1

Serve at most 4 simultaneous connections:
  $ ./dawnhttpd --maxconn 4

Log accesses to console, otherwise log goes to /var/log/dawnhttpd.log
  $ ./dawnhttpd --stdout

Chroot for extra security (you need root privs for chroot):
  $ ./dawnhttpd --chroot

Use default.htm instead of index.html:
  $ ./dawnhttpd --index default.htm

Add mimetypes - in this case, serve .dat files as text/plain:
  $ cat extramime
  text/plain  dat
  $ ./dawnhttpd --mimetypes extramime

Drop privileges:
  $ ./dawnhttpd --uid www --gid www

Use acceptfilter (FreeBSD only):
  $ kldload accf_http
  $ ./dawnhttpd --accf

Run in the background and create a pidfile:
  $ ./dawnhttpd --pidfile /var/run/httpd.pid --daemon

Guestbook entries through POST requests:
  $ ./dawnhttpd --guestbook guestbook_template guestbook_file

Web forward (301) requests for all hosts:
  $ ./dawnhttpd --forward-all http://catchall.example.com

Commandline options can be combined:
  $ ./dawnhttpd --port 8080 --addr 127.0.0.1

To see a full list of commandline options:
  $ ./dawnhttpd --help

vim:set ts=2 sw=2 et tw=80:
