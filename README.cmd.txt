How to run dawnhttpd
--------------------

Serve /var/www/htdocs on the default port (80 if running as root, else 8080):
  $ ./dawnhttpd /var/www/htdocs

Serve ~/public_html on port 8081:
  $ ./dawnhttpd ~/public_html --port 8081

Only bind to one IP address (useful on multi-homed systems):
  $ ./dawnhttpd ~/public_html --addr 192.168.0.1

Serve at most 4 simultaneous connections:
  $ ./dawnhttpd ~/public_html --maxconn 4

Log accesses to console, otherwise log goes to /var/log/dawnhttpd.log
  $ ./dawnhttpd ~/public_html --stdout

Chroot for extra security (you need root privs for chroot):
  $ ./dawnhttpd /var/www/htdocs --chroot

Use default.htm instead of index.html:
  $ ./dawnhttpd /var/www/htdocs --index default.htm

Add mimetypes - in this case, serve .dat files as text/plain:
  $ cat extramime
  text/plain  dat
  $ ./dawnhttpd /var/www/htdocs --mimetypes extramime

Drop privileges:
  $ ./dawnhttpd /var/www/htdocs --uid www --gid www

Use acceptfilter (FreeBSD only):
  $ kldload accf_http
  $ ./dawnhttpd /var/www/htdocs --accf

Run in the background and create a pidfile:
  $ ./dawnhttpd /var/www/htdocs --pidfile /var/run/httpd.pid --daemon

Guestbook entries through POST requests:
  $ ./dawnhttpd /var/www/htdocs --guestbook guestbook_template guestbook_file

Web forward (301) requests for some hosts:
  $ ./dawnhttpd /var/www/htdocs --forward example.com http://www.example.com \
    --forward secure.example.com https://www.example.com/secure

Web forward (301) requests for all hosts:
  $ ./dawnhttpd /var/www/htdocs --forward example.com http://www.example.com \
    --forward-all http://catchall.example.com

Commandline options can be combined:
  $ ./dawnhttpd ~/public_html --port 8080 --addr 127.0.0.1

To see a full list of commandline options,
run dawnhttpd without any arguments:
  $ ./dawnhttpd

vim:set ts=2 sw=2 et tw=80:
