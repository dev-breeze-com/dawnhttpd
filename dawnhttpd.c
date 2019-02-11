/* dawnhttpd - a simple, single-threaded webserver.
 *
 * https://www.gitgub.com/dev-breeze-os/dawnhttpd.git
 * Copyright (c) 2016 dev@breezeos.com <dev@breezeos.com>
 *
 * https://unix4lyfe.org/darkhttpd/
 * Copyright (c) 2003-2016 Emil Mikulic <emikulic@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

static const char pkgname[] = "dawnhttpd/1.5.0";
static const char copyright[] = "copyright (c) 2017 Tsert inc.";

#ifdef ENABLE_SERVER
#define ENABLE_PROXY
#define ENABLE_PASSWORD
#endif

#define DEBUG
#ifndef DEBUG
#define NDEBUG
#define DBG( s1, args...)
#define DBG_FLUSH()
static const int debug = 0;
#else
#define DBG( s1, args...)   fprintf( logfile, s1, ## args, NULL)
#define DBG_FLUSH()     fflush( logfile)
static const int debug = 1;
#endif

#if defined( DEBUG ) && defined( TRACE )
#define DBG_2( s1, args...) fprintf( logfile, s1, ## args, NULL);
#else
#define DBG_2( s1, args...);
#endif

#ifdef __linux
# define _GNU_SOURCE /* for strsignal() and vasprintf() */
# define _FILE_OFFSET_BITS 64 /* stat() files bigger than 2GB */
# include <sys/sendfile.h>
#endif

#ifdef __sun__
# include <sys/sendfile.h>
#endif

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/param.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <uuid/uuid.h>
#include <assert.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined( ENABLE_SSL_S2N )
#define ENABLE_SSL
#include <pthread.h>
#include <s2n.h>
#elif defined( ENABLE_SSL_TLS )
#define ENABLE_SSL
#include <pthread.h>
#include <ssl.h>
#include <tls.h>
#endif

#include "cdecode.h"

#ifdef __sun__
# ifndef INADDR_NONE
#  define INADDR_NONE -1
# endif
#endif

#ifndef MAXNAMLEN
# ifdef NAME_MAX
#  define MAXNAMLEN NAME_MAX
# else
#  define MAXNAMLEN	255
# endif
#endif

/* To prevent a malformed request from eating up too much memory, die once the
 * request exceeds this many bytes:
 */
#define MAX_REQUEST_LENGTH	4000
#define MAX_POST_LENGTH 	16384
#define MAX_HEADERS	50
#define MAX_TUPLES	250
#define MAX_SERVERS	17
#define MAX_CACHE	17

#ifndef MAX_BUFSZ
# define MAX_BUFSZ 4096
#endif

#if defined(O_EXCL) && !defined(O_EXLOCK)
# define O_EXLOCK O_EXCL
#endif

#ifndef __printflike
# ifdef __GNUC__
/* [->] borrowed from FreeBSD's src/sys/sys/cdefs.h,v 1.102.2.2.2.1 */
#  define __printflike(fmtarg, firstvararg) \
			 __attribute__((__format__(__printf__, fmtarg, firstvararg)))
/* [<-] */
# else
#  define __printflike(fmtarg, firstvararg)
# endif
#endif

#if defined(__GNUC__) || defined(__INTEL_COMPILER)
# define unused __attribute__((__unused__))
#else
# define unused
#endif

/* [->] borrowed from FreeBSD's src/sys/sys/systm.h,v 1.276.2.7.4.1 */
#ifndef CTASSERT				/* Allow lint to override */
# define CTASSERT(x)			 _CTASSERT(x, __LINE__)
# define _CTASSERT(x, y)		 __CTASSERT(x, y)
# define __CTASSERT(x, y)		typedef char __assert ## y[(x) ? 1 : -1]
#endif
/* [<-] */

CTASSERT(sizeof(unsigned long long) >= sizeof(off_t));
#define llu(x) ((unsigned long long)(x))

//#include <sys/queue.h>

/* [->] LIST_* macros taken from FreeBSD's src/sys/sys/queue.h,v 1.56
 * Copyright (c) 1991, 1993
 *	  The Regents of the University of California.  All rights reserved.
 *
 * Under a BSD license.
 */
#undef LIST_HEAD
#define LIST_HEAD(name, type)	\
struct name {		\
		struct type *lh_first;  /* first element */	\
}

#undef LIST_HEAD_INITIALIZER
#define LIST_HEAD_INITIALIZER(head)		{NULL}

#undef LIST_ENTRY
#define LIST_ENTRY(type)	\
struct {					\
		struct type *le_next;	/* next element */					  \
		struct type **le_prev;  /* address of previous next element */  \
}

#undef LIST_FIRST
#define LIST_FIRST(head)		((head)->lh_first)

#undef LIST_FOREACH_SAFE
#define LIST_FOREACH_SAFE(var, head, field, tvar)		\
	for ((var) = LIST_FIRST((head));					\
		(var) && ((tvar) = LIST_NEXT((var), field), 1);	\
		(var) = (tvar))

#undef LIST_INSERT_HEAD
#define LIST_INSERT_HEAD(head, elm, field) do {						 \
		if ((LIST_NEXT((elm), field) = LIST_FIRST((head))) != NULL)	 \
				LIST_FIRST((head))->field.le_prev = &LIST_NEXT((elm), field);\
		LIST_FIRST((head)) = (elm);						\
		(elm)->field.le_prev = &LIST_FIRST((head));		\
} while (0)

#undef LIST_NEXT
#define LIST_NEXT(elm, field)	((elm)->field.le_next)

#undef LIST_REMOVE
#define LIST_REMOVE(elm, field) do {					\
		if (LIST_NEXT((elm), field) != NULL)			\
				LIST_NEXT((elm), field)->field.le_prev =\
					(elm)->field.le_prev;				\
		*(elm)->field.le_prev = LIST_NEXT((elm), field);\
} while (0)
/* [<-] */

static LIST_HEAD(conn_list_head, connection) connlist = LIST_HEAD_INITIALIZER(conn_list_head);

static LIST_HEAD(freeconn_list_head, connection) freeconnlist = LIST_HEAD_INITIALIZER(freeconn_list_head);

struct dlent {
	char* name;
	int is_dir;
	off_t size;
};

struct data_tuple {
	char* key;
	char* value;
	void* datum;
};

struct data_bucket {
	char* key;
	char* value;
	off_t size;
	off_t written;
	time_t lastmod;
	time_t lifespan; /* Time to keep ~ 1 hour */
	struct data_bucket *next;
};

struct data_bucket_list {
	struct data_bucket *head;
	struct data_bucket *tail;
};

typedef enum { REPLY_GENERATED=0, REPLY_CACHED, REPLY_FROMFILE, REPLY_REDIRECT } ReplyType;

typedef enum {
	RECV_REQUEST=0, /* receiving request */
	SEND_HEADER,	/* sending generated header */
	SEND_REPLY,		/* sending reply */
	FORWARD_REQUEST, /* forward request */
	FORWARD_REPLY,	/* forward reply */
	SSL_ACCEPT,		/* ssl handshake */
	SSL_DONE,		/* ssl shutdown */
	DONE			/* connection closed, remove from queue */
} ConnState;

struct connection {

	LIST_ENTRY(connection) entries;

	struct data_bucket_list buckets;

	int socket, passthru;

#ifdef ENABLE_INET6
	struct in6_addr client;
#else
	in_addr_t client;
#endif

	time_t lasttime;

	ConnState state;

	struct timeval chrono;

	/* Session ID */
	uuid_t sessid;

#if defined( ENABLE_SSL_S2N )
	struct s2n_connection *ssl;
#elif defined( ENABLE_SSL_TLS )
	struct tls *ssl;
#else
	void *ssl;
#endif

	size_t request_length;
	size_t content_len;
	size_t urllen,decoded_urllen;

	//struct Headers {
		/* char request[request_length+1] is null-terminated */
		char *request;

		/* request fields */
		char *method, *suffix;
		char *url, *decoded_url;
		char *referer, *user_agent;
		char *host, *fqdn;
		char *auth, *cookies;
		char *auth_header;
		char *header;
		char *body;
		char *passthru_req;
		char *reply;

	//} hdrs;

	off_t payload_size;
	time_t payload_lastmod;

	off_t range_begin, range_end;
	off_t range_begin_given, range_end_given;

	size_t header_length, header_sent;
	int header_only, conn_close;
	int http_code, http_error, logged;
	size_t headers_total;

	struct data_tuple* headers[MAX_HEADERS];
	struct data_tuple* tuples[MAX_TUPLES];
	size_t tuples_total, body_length;

	//enum { REPLY_GENERATED=0, REPLY_CACHED, REPLY_FROMFILE } reply_type;
	ReplyType reply_type;

	int reply_fd, reply_blksz, reply_burst;
	float reply_msecs, reply_usecs;
	off_t reply_start, reply_length, reply_sent;
	off_t total_sent; /* header + body = total, for logging */

};

#ifdef ENABLE_SLOCATE
static const char* locate_dbpath = NULL;
static const char* locate_maxhits = NULL;
#endif

#ifdef ENABLE_PASSWORD
static char *passwdbuf = NULL;
static const char *password_salt = NULL;
static const char* password_file = NULL;
static struct data_tuple* passwords[MAX_TUPLES];
static int password_saltlen = 0;
static int passwords_total = 0;
static int use_password = 0;
#endif

#ifdef ENABLE_SSL
static struct data_tuple* ssl_configs[MAX_SERVERS];
static int ssl_configs_total = 0;
#endif

static char *mimebuf = NULL;
static const char* mimefile_name = NULL;
static struct data_tuple* mimetypes[MAX_TUPLES];
static int mimetypes_total = 0;

static char *inibuf = NULL;
static struct data_tuple* inifile[MAX_TUPLES];
static int inifile_total = 0;

static struct data_bucket* staticcache[MAX_CACHE];
static int staticcache_total = 0;

static size_t longest_ext = 0;

static int idletime = 30;
static struct timeval timeout;
static char* keep_alive_field = NULL;

/* Time is cached in the event loop to avoid making an excessive number of
 * gettimeofday() calls.
 */
static int CHRONO_SZ = sizeof(struct timeval);
static struct timeval chrono;
static int video_burstsize = 0;
static int audio_burstsize = 0;
static time_t lasttime = 0;
static time_t now;

/* Defaults can be overridden on the command-line */
static const char* bindaddr = NULL;
static uint16_t bindport = 8080; /* or 80 if running as root */
static uint16_t bindport_ssl = 443; /* or 443 if running as root */
static int max_connections = -1; /* kern.ipc.somaxconn */

#ifdef ENABLE_GUESTBOOK
static char* guestbook_reply = NULL;
static char* guestbook_template = NULL;
static FILE* guestbook_file = NULL;
#endif

static char* pidfile_name = NULL;
static FILE* logfile = NULL;
static FILE* errfile = NULL;

static int sockin = -1;	/* socket to accept connections */
static int sockin_ssl = -1;	/* socket to accept SSL connections */

static char* baseroot = NULL;
static char* wwwrealm = NULL;
static char* hostname = NULL;
static char* pubroot = NULL;

static char* server_hdr = NULL;
static char* index_name = NULL;

static int want_ssl = 0;
static int want_cache = 0;
static int want_drop = 0;
static int want_chroot = 0;
static int want_pidfile = 0;
static int want_logging = 1;
static int want_redirect = 0;

static int want_proxy = 0;
static int want_indexname = 0;

static int want_throttling = 0;
static int want_throttling_in_msecs = 0;

static int want_accf = 0;
static int want_daemon = 0;
static int want_server_id = 1;

static int want_listing = 0;
static int want_slocate = 0;

static int baserootlen = 0;
static int pubrootlen = 0;
static int index_name_len = 0;

static uint64_t total_in = 0;
static uint64_t total_out = 0;

static uint32_t num_servers = 0;
static uint32_t num_ssl_servers = 0;

static uint64_t num_requests = 0;

static uint32_t num_buckets = 0;
static uint32_t num_connections = 0;
static uint32_t num_freeconnections = 0;

static volatile int running = 1; /* signal handler sets this to false */

#define INVALID_UID ((uid_t) -1)
#define INVALID_GID ((gid_t) -1)

#define TIMERCMP(x,y) ((x.tv_sec > y.tv_sec) ? 1 : \
		((x.tv_sec == y.tv_sec && x.tv_usec > y.tv_usec) ? 1 : 0))

static uid_t drop_uid = INVALID_UID;
static gid_t drop_gid = INVALID_GID;

/* Default mimetype mappings - make sure this array is NULL terminated. */
static struct data_tuple default_extension_map[] = {
	{ "application/emg", "emg" },
	{ "application/pdf", "pdf" },
	{ "application/xml", "xsl" },
	{ "application/xml", "xml" },
	{ "application/xml-dtd", "dtd" },
	{ "application/xslt+xml", "xslt" },
	{ "application/zip", "zip" },
	{ "audio/flac", "flac" },
	{ "audio/mpeg", "mp2" },
	{ "audio/mpeg", "mp3" },
	{ "audio/mpeg", "mpga" },
	{ "audio/ogg", "ogg" },
	{ "audio/opus", "opus" },
	{ "image/gif", "gif" },
	{ "image/jpeg", "jpeg" },
	{ "image/jpeg", "jpe" },
	{ "image/jpeg", "jpg" },
	{ "image/png", "png" },
	{ "text/css", "css" },
	{ "text/html", "html" },
	{ "text/html", "htm" },
	{ "text/javascript", "js" },
	{ "text/plain", "txt" },
	{ "text/plain", "asc" },
	{ "video/mpeg", "mpeg" },
	{ "video/mpeg", "mpe" },
	{ "video/mpeg", "mpg" },
	{ "video/ogg", "daala" },
	{ "video/ogg", "ogv" },
	{ "video/divx", "divx" },
	{ "video/quicktime", "qt" },
	{ "video/quicktime", "mov" },
	{ "video/x-matroska", "mkv" },
	{ "video/x-msvideo", "avi" },
	{ NULL, NULL }
};

static const char* config_file = "/etc/dawnhttpd/settings.ini";
static const char octet_stream[] = "application/octet-stream";
static const char* default_mimetype = octet_stream;

static char base64_buffer[MAXNAMLEN]; 
static char* base64_buf = base64_buffer;

/* Prototypes. */
static void poll_recv_request(struct connection*);
static void poll_send_header(struct connection*);
static void poll_send_reply(struct connection*);
static void log_connection(struct connection*, int);

//static void forward_request(struct connection*);
//static void forward_reply(struct connection*);

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__linux__)
#include <err.h>
#include <stdarg.h>
#else
/* err - prints "error: format: strerror(errno)" to stderr and exit()s with
 * the given code.
 */
static void err(const int code, const char* format, ...) __printflike(2, 3);
static void err(const int code, const char* format, ...)
{
	va_list va;
	va_start(va, format);
	fprintf(stderr, "error: ");
	vfprintf(stderr, format, va);
	fprintf(stderr, ": %s\n", strerror(errno));
	va_end(va);
	exit(code);
}

/* errx - err() without the strerror */
static void errx(const int code, const char* format, ...) __printflike(2, 3);
static void errx(const int code, const char* format, ...)
{
	va_list va;
	va_start(va, format);
	fprintf(stderr, "error: ");
	vfprintf(stderr, format, va);
	fprintf(stderr, "\n");
	va_end(va);
	exit(code);
}

/* warn - err() without the exit */
static void warn(const char* format, ...) __printflike(1, 2);
static void warn(const char* format, ...)
{
	va_list va;
	va_start(va, format);
	fprintf(errfile, "warning: ");
	vfprintf(errfile, format, va);
	fprintf(errfile, ": %s\n", strerror(errno));
	//fflush(errfile);
	va_end(va);
}
#endif

/* close() that dies on error.  */
static void xclose(const int fd)
{
	//{ err(1, "close()"); }
	if (close(fd) == -1) { warn( "close()"); }
}

/* malloc that dies if it can't allocate. */
static void* xmalloc(const size_t size)
{
	void* ptr = malloc(size);

	if (ptr == NULL)
	{ errx(1, "can't allocate %zu bytes", size); }

	return ptr;
}

/* realloc() that dies if it can't reallocate. */
static void* xrealloc(void* original, const size_t size)
{
	void* ptr = realloc(original, size);

	if (ptr == NULL)
	{ errx(1, "can't reallocate %zu bytes", size); }

	return ptr;
}

/* strdup() that dies if it can't allocate.
 * Implement this ourselves since regular strdup() isn't C89.
 */
static char* xstrduplen(const char* src, size_t len)
{
	len = len > 0 ? len : strlen(src) + 1;
	char* dest = xmalloc(len);
	memcpy(dest, src, len);
	return dest;
}

static char* xstrdup(const char* src)
{
	 size_t len = strlen(src) + 1;
	char* dest = xmalloc(len);
	memcpy(dest, src, len);
	return dest;
}

/* Returns 1 if string is a number, 0 otherwise.  Set num to NULL if
 * disinterested in value.
 */
static int str_to_num(const char* str, long long* num)
{
	char* endptr;
	long long n;
	errno = 0;
	n = strtoll(str, &endptr, 10);

	if (*endptr != '\0')
	{ return 0; }

	if (n == LLONG_MIN && errno == ERANGE)
	{ return 0; }

	if (n == LLONG_MAX && errno == ERANGE)
	{ return 0; }

	if (num != NULL)
	{ *num = n; }

	return 1;
}

/* Returns a valid number or dies. */
static long long xstr_to_num(const char* str)
{
	long long ret;

	if (!str_to_num(str, &ret)) {
		errx(1, "number \"%s\" is invalid", str);
	}

	return ret;
}

#ifdef __sun /* unimpressed by Solaris */
static int vasprintf(char** strp, const char* fmt, va_list ap)
{
	char tmp;
	int result = vsnprintf(&tmp, 1, fmt, ap);
	*strp = xmalloc(result + 1);
	result = vsnprintf(*strp, result + 1, fmt, ap);
	return result;
}
#endif

/* vasprintf() that dies if it fails. */
static unsigned int xvasprintf(char** ret, const char* format, va_list ap) __printflike(2, 0);
static unsigned int xvasprintf(char** ret, const char* format, va_list ap)
{
	int len = vasprintf(ret, format, ap);

	if (ret == NULL || len == -1)
	{ errx(1, "out of memory in vasprintf()"); }

	return (unsigned int)len;
}

/* asprintf() that dies if it fails. */
static unsigned int xasprintf(char** ret, const char* format, ...) __printflike(2, 3);
static unsigned int xasprintf(char** ret, const char* format, ...)
{
	va_list va;
	unsigned int len;
	va_start(va, format);
	len = xvasprintf(ret, format, va);
	va_end(va);
	return len;
}

/* Append buffer code.  A somewhat efficient string buffer with pool-based
 * reallocation.
 */
#ifndef APBUF_INIT
# define APBUF_INIT 4096
#endif
#define APBUF_GROW APBUF_INIT
struct apbuf {
	size_t length, pool;
	char* str;
};

static struct apbuf* make_apbuf(void)
{
	struct apbuf* buf = xmalloc(sizeof(struct apbuf));
	buf->length = 0;
	buf->pool = APBUF_INIT;
	buf->str = xmalloc(buf->pool);
	return buf;
}

/* Append s (of length len) to buf. */
static void appendl(struct apbuf* buf, const char* s, const size_t len)
{
	size_t need = buf->length + len;

	if (buf->pool < need) {
		/* pool has dried up */
		while (buf->pool < need)
		{ buf->pool += APBUF_GROW; }

		buf->str = xrealloc(buf->str, buf->pool);
	}

	memcpy(buf->str + buf->length, s, len);
	buf->length += len;
}


#ifdef __GNUC__
#define append(buf, s) appendl(buf, s, \
	(__builtin_constant_p(s) ? sizeof(s)-1 : strlen(s)) )
#else
static void append(struct apbuf* buf, const char* s)
{
	appendl(buf, s, strlen(s));
}
#endif

static void appendf(struct apbuf* buf, const char* format, ...) __printflike(2, 3);
static void appendf(struct apbuf* buf, const char* format, ...)
{
	char* tmp;
	va_list va;
	size_t len;
	va_start(va, format);
	len = xvasprintf(&tmp, format, va);
	va_end(va);
	appendl(buf, tmp, len);
	free(tmp);
}

/* Make the specified socket non-blocking. */
static void nonblock_socket(const int sock)
{
	int flags = fcntl(sock, F_GETFL);

	if (flags == -1)
	{ err(1, "fcntl(F_GETFL)"); }

	flags |= O_NONBLOCK;

	if (fcntl(sock, F_SETFL, flags) == -1)
	{ err(1, "fcntl() to set O_NONBLOCK"); }
}

static int maxstrlen(const char* str, int max)
{
	int len = strlen( str );
	return len > max ? len : max;
}

/* Split string out of src with range [left:right-1] */
static char* split_string(const char* src, const size_t left, const size_t right)
{
	char* dest;

	assert(left <= right);
	//assert(left < strlen(src));	/* [left means must be smaller */
	//assert(right <= strlen(src)); /* right) means can be equal or smaller */

	dest = xmalloc(right - left + 1);
	memcpy( dest, src + left, right - left );
	dest[right-left] = '\0';

	return dest;
}

/* Consolidate slashes in-place by shifting parts of the string over
 * repeated slashes.
 */
static void consolidate_slashes(char* s, size_t *urllen)
{
	size_t left = 0, right = 0;
	int saw_slash = 0;

	assert(s != NULL);

	while (s[right] != '\0') {
		if (saw_slash) {
			if (s[right] == '/')
			{ right++; }
			else {
				saw_slash = 0;
				s[left++] = s[right++];
			}
		} else if (s[right] == '\\' && s[right+1] == ' ') {
			++right;
			s[left++] = s[right++];
		} else {
			if (s[right] == '/')
			{ saw_slash++; }

			s[left++] = s[right++];
		}
	}

	s[left] = '\0';
	(*urllen) = left;
}

/* Resolve /./ and /../ in a URL, in-place.  Also strip out query params.
 * Returns NULL if the URL is invalid/unsafe, or the original buffer if
 * successful.
 */
//-----------------------------------------------------------------------------
static int make_safe_url(struct connection* conn)
//-----------------------------------------------------------------------------
{
	struct {
		char* start;
		size_t len;
	} *chunks;

	unsigned int num_slashes, num_chunks;
	size_t urllen, i, j, pos;
	char *url = conn->decoded_url;
	int ends_in_slash;

	/* strip query params */
	for (pos = 0; url[pos] != '\0'; pos++) {
		if (url[pos] == '?') {
			url[pos] = '\0';
			break;
		}
	}

	if (url[0] != '/')
	{ return (0); }

	consolidate_slashes(url, &urllen);

	if (urllen > 0)
	{ ends_in_slash = (url[urllen - 1] == '/'); }
	else
	{ ends_in_slash = 1; }

	/* count the slashes */
	for (i = 0, num_slashes = 0; i < urllen; i++) {
		if (url[i] == '/') {
			num_slashes++;
		}
	}

	/* make an array for the URL elements */
	assert(num_slashes > 0);
	chunks = xmalloc(sizeof(*chunks) * num_slashes);

	/* split by slashes and build chunks array */
	num_chunks = 0;

	for (i = 1; i < urllen;) {
		/* look for the next slash */
		for (j = i; j < urllen && url[j] != '/'; j++)
			;

		/* process url[i,j) */
		if ((j == i + 1) && (url[i] == '.'))
			/* "." */;
		else if ((j == i + 2) && (url[i] == '.') && (url[i + 1] == '.')) {
			/* ".." */
			if (num_chunks == 0) {
				/* unsafe string so free chunks */
				free(chunks);
				return (0);
				//return (NULL);
			}
			else
			{ num_chunks--; }
		}
		else {
			chunks[num_chunks].start = url + i;
			chunks[num_chunks].len = j - i;
			num_chunks++;
		}

		i = j + 1; /* url[j] is a slash - move along one */
	}

	/* reassemble in-place */
	pos = 0;

	for (i = 0; i < num_chunks; i++) {
		assert(pos <= urllen);
		url[pos++] = '/';
		assert(pos + chunks[i].len <= urllen);
		assert(url + pos <= chunks[i].start);

		if (url + pos < chunks[i].start)
		{ memmove(url + pos, chunks[i].start, chunks[i].len); }

		pos += chunks[i].len;
	}

	free(chunks);

	if ((num_chunks == 0) || ends_in_slash)
		url[pos++] = '/';

	assert(pos <= urllen);

	url[pos] = '\0';

	conn->decoded_urllen = pos;

	return (1);
}

//-----------------------------------------------------------------------------
static const char* get_address_text(const void* addr)
//-----------------------------------------------------------------------------
{
#ifdef ENABLE_INET6
	static char text_addr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, (const struct in6_addr*)addr, text_addr, INET6_ADDRSTRLEN);
	return text_addr;
#else
	return inet_ntoa(*(const struct in_addr*)addr);
#endif
}

//-----------------------------------------------------------------------------
static void update_clock(struct connection *conn)
//-----------------------------------------------------------------------------
{
	int usecs = 0;

	conn->lasttime = now;

	if (want_throttling_in_msecs && TIMERCMP( chrono, conn->chrono ) > 0) {

		memcpy( &(conn->chrono), &chrono, CHRONO_SZ );

		usecs = chrono.tv_usec + conn->reply_usecs;

		if (usecs < 999999) {
			conn->chrono.tv_usec = usecs;
		} else {
			conn->chrono.tv_sec += 1;
			conn->chrono.tv_usec = usecs - 1000000;
		}
	}
}

//-----------------------------------------------------------------------------
static int bucket_sortcmp(const void* key, const void* item)
//-----------------------------------------------------------------------------
{
	struct data_bucket** i1 = (struct data_bucket**) key;
	struct data_bucket** i2 = (struct data_bucket**) item;
	return strcasecmp( (*i1)->key, (*i2)->key );
}

//-----------------------------------------------------------------------------
static int bucket_cmp(const void* o1, const void* const o2)
//-----------------------------------------------------------------------------
{
	struct data_bucket* i1 = (struct data_bucket*) o1;
	struct data_bucket** i2 = (struct data_bucket**) o2;
	return strcasecmp( i1->key, (*i2)->key );
}

//-----------------------------------------------------------------------------
static int tuple_sortcmp(const void* key, const void* item)
//-----------------------------------------------------------------------------
{
	struct data_tuple** i1 = (struct data_tuple**) key;
	struct data_tuple** i2 = (struct data_tuple**) item;
	return strcasecmp( (*i1)->key, (*i2)->key );
}

//-----------------------------------------------------------------------------
static int tuple_cmp(const void* o1, const void* const o2)
//-----------------------------------------------------------------------------
{
	struct data_tuple* i1 = (struct data_tuple*) o1;
	struct data_tuple** i2 = (struct data_tuple**) o2;

#ifdef DEBUG
	// To check out a problem I encountered, where the parameter 'o2'
	// get re-assigned a null value, after the second assignment;
	DBG_2( "tuple_cmp[1]: 0x%x 0x%x 0x%x 0x%x\n", i1, i2, (*i2), o2 );
	struct data_tuple* i3 = (struct data_tuple*) o2; /* BUG HERE */
	DBG_2( "tuple_cmp[2]: 0x%x 0x%x 0x%x 0x%x\n", i1, i3, (*i3), o2 );
	//printf( "tuple_cmp[3]: '%s' '%s'\n", i1->key, (*i2)->key );
#endif

	return strcasecmp( i1->key, (*i2)->key );
}

//-----------------------------------------------------------------------------
static void bucket_sort()
//-----------------------------------------------------------------------------
{
	qsort(
		staticcache,
		staticcache_total,
		sizeof(struct data_bucket*),
		bucket_sortcmp
	);
}

//-----------------------------------------------------------------------------
static void tuple_sort(struct data_tuple* tuples[], int total)
//-----------------------------------------------------------------------------
{
	qsort( tuples, total, sizeof(struct data_tuple*), tuple_sortcmp );
}

//-----------------------------------------------------------------------------
static char* tuple_search(struct data_tuple* tuples[], int total, const char* arg)
//-----------------------------------------------------------------------------
{
	struct data_tuple key={ (char*) arg, NULL };
	struct data_tuple** found = bsearch(
		&key, tuples, total,
		sizeof(struct data_tuple*),
		tuple_cmp
	);
	return (char*) (found ? (*found)->value : NULL);
}

//-----------------------------------------------------------------------------
static void* ssl_config_search(struct connection* conn)
//-----------------------------------------------------------------------------
{
#ifdef ENABLE_SSL
	if ( !num_ssl_servers || !conn->fqdn )
		return ssl_configs[0]->datum;

	struct data_tuple key={ conn->fqdn, NULL };
	struct data_tuple** found = bsearch(
		&key, ssl_configs, ssl_configs_total,
		sizeof(struct data_tuple*),
		tuple_cmp
	);

	if ( !found )
		return ssl_configs[0]->datum;

	return (*found)->datum;
#endif
}

//-----------------------------------------------------------------------------
static char* hdrsearch(struct connection* conn, const char* arg)
//-----------------------------------------------------------------------------
{
	return tuple_search( conn->headers, conn->headers_total, arg );
}

//-----------------------------------------------------------------------------
static int ini_evaluate(const char* key, const char* eqvalue, const char* deflt)
//-----------------------------------------------------------------------------
{
	char *value = tuple_search( inifile, inifile_total, key );
	if (!value)
		return deflt ? !strcasecmp(deflt,eqvalue) : 0;
	return value ? !strcasecmp(value,eqvalue) : 0;
}

//-----------------------------------------------------------------------------
static char* inisearch(const char* key, const char* deflt)
//-----------------------------------------------------------------------------
{
	char *value = tuple_search( inifile, inifile_total, key );
	return value ? value : (char*) deflt;
}

#ifdef ENABLE_PASSWORD
//-----------------------------------------------------------------------------
static int htpasswd(const char* user, const char* password)
//-----------------------------------------------------------------------------
{
	char *value = tuple_search( passwords, passwords_total, user );
	return value ? !strcasecmp(value,password) : 0;
}
#endif

//-----------------------------------------------------------------------------
static int connect_sockin(const char* host, const char* port)
//-----------------------------------------------------------------------------
{
	struct addrinfo hints, *res;
	int fd = (-1);
	int rc = 0;

	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	hints.ai_protocol = IPPROTO_TCP;
	/*
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;
	*/

	if ((rc = getaddrinfo( host, port, &hints, &res )) < 0) {
		warn("%s", gai_strerror(rc));
		return (-1);
	}

  //  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	if ((fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
		warn("socket failed");
		return (-1);
	}

	if (connect( fd, res->ai_addr, res->ai_addrlen) < 0) {
		warn("connect failed");
		return (-1);
	}

	nonblock_socket(fd);

	return fd;
}

//-----------------------------------------------------------------------------
static int init_sockin(int lasttry, int bindport, int ssl_on)
//-----------------------------------------------------------------------------
{
	struct sockaddr_in addrin;
	struct sockaddr_in addrin_ssl;

#ifdef ENABLE_INET6
	struct sockaddr_in6 addrin6;
	struct sockaddr_in6 addrin6_ssl;
#endif

	socklen_t addrin_len;
	char *value = NULL;
	int sockopt = 0;
	int sockin = -1;
	int i = 0;

#ifdef ENABLE_INET6
	memset(&addrin6, 0, sizeof(addrin6));
	if (inet_pton(AF_INET6, bindaddr ? bindaddr : "::", &addrin6.sin6_addr) == -1)
		errx(1, "malformed --addr argument");
	sockin = socket(PF_INET6, SOCK_STREAM, 0);
#else
	memset(&addrin, 0, sizeof(addrin));
	addrin.sin_addr.s_addr = bindaddr ? inet_addr(bindaddr) : INADDR_ANY;
	if (addrin.sin_addr.s_addr == (in_addr_t)INADDR_NONE)
		errx(1, "malformed --addr argument");
	sockin = socket(PF_INET, SOCK_STREAM, 0);
#endif

	if (sockin == -1) { 
		if (lasttry) { err(1, "socket()"); }
		warn( "socket()");
		return 0;
	}

	/* reuse address */
	sockopt = 1;

	if (setsockopt(sockin, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) == -1)
		err(1, "setsockopt(SO_REUSEADDR)");

#if DISABLE_NAGLE
	/* disable Nagle since we buffer everything ourselves */
	sockopt = 1;

	if (setsockopt(sockin, IPPROTO_TCP, TCP_NODELAY, &sockopt, sizeof(sockopt)) == -1)
		err(1, "setsockopt(TCP_NODELAY)");
#endif

#ifdef TORTURE
	/* torture: cripple the kernel-side send buffer so we can only squeeze out
	 * one byte at a time (this is for debugging)
	 */
	sockopt = 1;
	if (setsockopt(sockin, SOL_SOCKET, SO_SNDBUF, &sockopt, sizeof(sockopt)) == -1)
		err(1, "setsockopt(SO_SNDBUF)");
#endif

#ifdef ENABLE_INET6
	addrin6.sin6_family = AF_INET6;
	addrin6.sin6_port = htons(bindport);

	if (bind(sockin, (struct sockaddr*)&addrin6, sizeof(struct sockaddr_in6)) == -1)
		err(1, "bind(port %u)", bindport);

	addrin_len = sizeof(addrin6);

	if (getsockname(sockin, (struct sockaddr*)&addrin6, &addrin_len) == -1)
		err(1, "getsockname()");

	fprintf( logfile, "Listening on: http://[%s]:%u/\n",
		get_address_text(&addrin6.sin6_addr), bindport);
#else
	addrin.sin_family = (u_char)PF_INET;
	addrin.sin_port = htons(bindport);

	if (bind(sockin, (struct sockaddr*)&addrin, sizeof(struct sockaddr_in)) == -1)
	{ err(1, "bind(port %u)", bindport); }

	addrin_len = sizeof(addrin);

	if (getsockname(sockin, (struct sockaddr*)&addrin, &addrin_len) == -1)
		err(1, "getsockname()");

	fprintf( logfile, "Listening on: http://%s:%u/\n",
		get_address_text(&addrin.sin_addr), bindport);
#endif

	if (listen(sockin, max_connections) == -1) { err(1, "listen()"); }

	/* enable acceptfilter (this is only available on FreeBSD) */
	if (want_accf) {
#if defined(__FreeBSD__)
		struct accept_filter_arg filt = {"httpready", ""};

		if (setsockopt(sockin, SOL_SOCKET, SO_ACCEPTFILTER, &filt, sizeof(filt)) == -1) {
			warn("cannot enable acceptfilter: %s", strerror(errno));
		} else {
			printf("enabled acceptfilter\n");
		}
#else
		printf("this platform doesn't support acceptfilter\n");
#endif
	}

	return sockin;
}

//-----------------------------------------------------------------------------
static void usage(const char* argv0)
//-----------------------------------------------------------------------------
{
	printf("Usage:\t%s [options]\n\n", argv0);
	printf("  --no-log (override settings file)\n"
			"    Outputs log info to stdout.\n"
			"    Outputs warn/error info to stderr.\n\n");
	printf("  --config (override the default settings file)\n"
			"    Use specified settings file.\n\n");
	printf("  --no-daemon (override settings file)\n"
			"    Do not detach from the controlling terminal to run in the background.\n\n");
#ifdef __FreeBSD__
	printf("  --accf (default: don't use acceptfilter)\n"
			"    Use acceptfilter.  Needs the accf_http module loaded.\n\n");
#endif
#ifndef ENABLE_INET6
	printf("  (This binary was built without IPv6 support)\n");
#endif
#ifndef ENABLE_PIDFILE
	printf("  (This binary was built without PID file support)\n");
#endif
#ifndef ENABLE_GUESTBOOK
	printf("  (This binary was built without guestbook support)\n");
#endif
#ifndef ENABLE_PROXY
	printf("  (This binary was built without proxy connection support)\n");
#endif
#ifndef ENABLE_SSL
	printf("  (This binary was built without SSL connection support)\n");
#endif
#ifndef ENABLE_SLOCATE
	printf("  (This binary was built without Gnu locate support)\n");
#endif
#ifndef ENABLE_PASSWORD
	printf("  (This binary was built without password support)\n");
#endif
}

/* Allocate and initialize an empty connection. */
//-----------------------------------------------------------------------------
static struct connection* new_connection(void)
//-----------------------------------------------------------------------------
{
	struct connection* conn = xmalloc(sizeof(struct connection));

	memset( conn, 0, sizeof(struct connection));

	num_connections += 1;

	conn->ssl = NULL;
	conn->socket = -1;
	conn->passthru = -1;
	conn->lasttime = now;

	conn->reply_fd = -1;
	conn->reply_msecs = 0.1;
	conn->reply_usecs = 100000;
	conn->reply_burst = 1 << 20;
	conn->reply_type = REPLY_GENERATED;

	/* Make it harmless so it gets garbage-collected if it should, for some
	 * reason, fail to be correctly filled out.
	 */
	conn->conn_close = 1;
	conn->state = DONE;

	return conn;
}

//-----------------------------------------------------------------------------
static void free_tuples(struct data_tuple *tuples[])
//-----------------------------------------------------------------------------
{
	int i;

	for (i=0; tuples[i]; i++) {
		free(tuples[i]);
	}
}

/* Log a connection, then cleanly deallocate its internals. */
//-----------------------------------------------------------------------------
static void free_conn_tuples(struct connection* conn)
//-----------------------------------------------------------------------------
{
	free_tuples( conn->tuples );
	free_tuples( conn->headers );
}

//-----------------------------------------------------------------------------
static void free_conn_malloc(struct connection* conn)
//-----------------------------------------------------------------------------
{
	DBG_2("free_conn_malloc(%d)\n", conn->socket);

	if (conn->socket > 0) {
#ifdef ENABLE_SSL
		if (conn->ssl != NULL) {
#if defined( ENABLE_SSL_S2N )
			s2n_connection_wipe(conn->ssl);
#elif defined( ENABLE_SSL_TLS )
			tls_reset(conn->ssl);
#endif
		}
#endif
		//warn("free_conn_malloc shutdown(%d)", conn->socket);
		xclose(conn->socket);
		//shutdown(conn->socket, SHUT_RDWR);
	}

#ifdef ENABLE_PROXY
	if (conn->passthru > 0) {
		struct data_bucket *bucket = conn->buckets.head;

		//xclose(conn->passthru);
		shutdown(conn->passthru, SHUT_RDWR);
		conn->passthru = -1;

		for (; bucket; bucket = bucket->next) {
			free(bucket->value);
			free(bucket);
		}

        conn->buckets.head = NULL;
	}
#endif

	//if (conn->method != NULL) { free(conn->method); }
	if (conn->url != NULL) { free(conn->url); }
	if (conn->fqdn != NULL) { free(conn->fqdn); }
	if (conn->request != NULL) { free(conn->request); }
	if (conn->decoded_url != NULL) { free( conn->decoded_url ); }
	if (conn->header != NULL) { free(conn->header); }
	if (conn->reply != NULL && conn->reply_type != REPLY_CACHED) { free(conn->reply); }
	if (conn->reply_fd > 0) { xclose(conn->reply_fd); }
}

//-----------------------------------------------------------------------------
static void recycle_connection(struct connection* conn)
//-----------------------------------------------------------------------------
{
	int socket_tmp = conn->socket;
	int proxy_tmp = conn->passthru;

	DBG_2("recycle_connection(%d)\n", socket_tmp);

	log_connection( conn, 1 );

	/* don't reset conn->client */
	conn->socket = -1;
	conn->passthru = -1;

	free_conn_malloc(conn);

	conn->socket = socket_tmp;
	conn->passthru = proxy_tmp;

	conn->request = NULL;
	conn->request_length = 0;

	conn->method = NULL;
	conn->url = NULL;
	conn->host = NULL;
	conn->fqdn = NULL;
	conn->referer = NULL;
	conn->user_agent = NULL;
	conn->decoded_url = NULL;

	conn->content_len = 0;
	conn->range_begin = 0;
	conn->range_end = 0;
	conn->range_begin_given = 0;
	conn->range_end_given = 0;

	conn->auth = NULL;
	conn->cookies = NULL;
	conn->auth_header = NULL;

	conn->header = NULL;
	conn->header_length = 0;
	conn->header_sent = 0;
	conn->header_only = 0;
	conn->http_code = 0;
	conn->http_error = 0;

	conn->conn_close = 1;
	conn->reply = NULL;
	conn->reply_fd = -1;
	conn->reply_start = 0;
	conn->reply_length = 0;
	conn->reply_blksz = 0;
	conn->reply_msecs = 0.1;
	conn->reply_usecs = 100000;
	conn->reply_burst = 1 << 20;
	conn->reply_sent = 0;
	conn->total_sent = 0;
	conn->reply_type = REPLY_GENERATED;
	conn->state = RECV_REQUEST; /* ready for another */

	if ( conn->tuples[0] ) { conn->tuples[0]->key = NULL; }
	if ( conn->headers[0] ) { conn->headers[0]->key = NULL; }
}

//-----------------------------------------------------------------------------
static void release_resources(struct connection* conn)
//-----------------------------------------------------------------------------
{
	num_connections -= 1;
	log_connection( conn, 0 );

	free_conn_malloc(conn);
	free_conn_tuples(conn);

#if defined( ENABLE_SSL_S2N )
	if (conn->ssl) { s2n_connection_free(conn->ssl); }
#elif defined( ENABLE_SSL_TLS )
	if (conn->ssl) { tls_free(conn->ssl); }
#endif

	free(conn);
}

/* Recycle a finished connection for HTTP/1.1 Keep-Alive. */
#ifdef ENABLE_SSL
//-----------------------------------------------------------------------------
static void ssl_new(struct connection* conn)
//-----------------------------------------------------------------------------
{
#if defined(ENABLE_SSL_S2N)
	conn->ssl = s2n_connection_new(S2N_SERVER);
#else
	conn->ssl = (struct tls*) ssl_config_search( conn );
#endif
}

#ifdef ENABLE_SSL_S2N
//-----------------------------------------------------------------------------
static int ssl_configure(struct connection* conn)
//-----------------------------------------------------------------------------
{
	//s2n_connection_set_recv_cb(server_conn, &buffer_read);
	//s2n_connection_set_send_cb(server_conn, &buffer_write);
	//s2n_connection_set_recv_ctx(conn->ssl, &in);

	struct s2n_config *config_ssl =
		(struct s2n_config*) ssl_config_search( conn );

	if ( !config_ssl )
		return (-1);

	if (s2n_connection_set_config(conn->ssl, config_ssl) < 0) {
		warn("ssl_set_config SSL socket %d", conn->socket);
		return (-1);
	}

	if (s2n_connection_set_blinding(conn->ssl, S2N_SELF_SERVICE_BLINDING) < 0) {
		warn("ssl_set_blinding SSL socket %d", conn->socket);
		return (-1);
	}

  //  conn->ssl->delay = 0;

	if (s2n_connection_set_fd(conn->ssl, conn->socket) < 0) {
		warn("ssl_accept fd FAIL SSL socket %d", conn->socket);
		return (-1);
	}

	return 0;
}

//-----------------------------------------------------------------------------
static int ssl_send(struct connection* conn, char *buf, ssize_t sent)
//-----------------------------------------------------------------------------
{
	s2n_blocked_status blocked;

	errno = 0;
	s2n_errno = S2N_ERR_T_OK;

	sent = s2n_send(conn->ssl, buf, sent, &blocked);
 //	warn("ssl_send %d %s", sent, buf);

	if (sent < 0) {
		switch (s2n_error_get_type(s2n_errno)) {
			case S2N_ERR_T_BLOCKED:
				errno=EAGAIN;
	//		warn("ssl_send Blocked, come back later");
				return -1;
			case S2N_ERR_T_CLOSED:
				conn->state = SSL_DONE;
				warn("ssl_send S2N_ERR_T_CLOSED, come back later");
				return 0;
			case S2N_ERR_T_IO:
				conn->state = SSL_DONE;
				warn("ssl_send handle_io_err");
				return -1;
			case S2N_ERR_T_PROTO:
				conn->state = SSL_DONE;
				warn("ssl_send handle_proto_err");
				return -1;
			case S2N_ERR_T_ALERT:
				conn->state = SSL_DONE;
				warn("ssl_send s2n_connection_get_alert");
				s2n_connection_get_alert(conn->ssl);
				return -1;
			default:
				conn->state = SSL_DONE;
				warn("ssl_send log_other_error");
				return -1;
		}
	}

	return sent;
}

//-----------------------------------------------------------------------------
static int ssl_recv(struct connection* conn, char *buf, ssize_t recvd)
//-----------------------------------------------------------------------------
{
	s2n_blocked_status blocked;

	errno = 0;
	s2n_errno = S2N_ERR_T_OK;

	recvd = s2n_recv(conn->ssl, buf, recvd, &blocked);
	// warn("ssl_recv RECV %d", recvd);

	if (recvd < 0) {
		switch (s2n_error_get_type(s2n_errno)) {
			case S2N_ERR_T_BLOCKED:
				errno=EAGAIN;
	 //		warn("ssl_recv Blocked, come back later");
				return -1;
			case S2N_ERR_T_CLOSED:
				conn->state = SSL_DONE;
				warn("ssl_recv Closed, come back later");
				return 0;
			case S2N_ERR_T_IO:
				warn("ssl_recv handle_io_err");
				conn->state = SSL_DONE;
				return -1;
			case S2N_ERR_T_PROTO:
				warn("ssl_recv handle_proto_err");
				conn->state = SSL_DONE;
				return -1;
			case S2N_ERR_T_ALERT:
				s2n_connection_get_alert(conn->ssl);
				conn->state = SSL_DONE;
				warn("ssl_recv s2n_connection_get_alert, come back later");
				return -1;
			default:
				conn->state = SSL_DONE;
				warn("ssl_recv log_other_error");
				return -1;
		}
	}

	return recvd;
}

//-----------------------------------------------------------------------------
static int ssl_shutdown(struct connection* conn)
//-----------------------------------------------------------------------------
{
	s2n_blocked_status blocked;

	errno = 0;
	s2n_errno = S2N_ERR_T_OK;

 // warn("ssl_shutdown s2n_shutdown");

	if (s2n_shutdown(conn->ssl, &blocked) < 0) {
		switch (s2n_error_get_type(s2n_errno)) {
			case S2N_ERR_T_BLOCKED:
				errno=EAGAIN;
//				warn("ssl_shutdown Blocked, come back later");
				return -1;
			case S2N_ERR_T_CLOSED:
				conn->state = DONE;
				warn("ssl_shutdown S2N_ERR_T_CLOSED");
				return 0;
			case S2N_ERR_T_IO:
				conn->state = DONE;
				warn("ssl_shutdown handle_io_err");
				return -1;
			case S2N_ERR_T_PROTO:
				conn->state = DONE;
				warn("ssl_shutdown handle_proto_err");
				return -1;
			case S2N_ERR_T_ALERT:
				conn->state = DONE;
				s2n_connection_get_alert(conn->ssl);
				warn("ssl_shutdown s2n_connection_get_alert");
				return -1;
			default:
				conn->state = DONE;
				warn("ssl_shutdown log_other_error");
				return -1;
		}
	}

	if (blocked == S2N_NOT_BLOCKED) {
		conn->state = DONE;
		return 1;
	}

	return -1;
}

//-----------------------------------------------------------------------------
static int ssl_handshake(struct connection* conn)
//-----------------------------------------------------------------------------
{
	s2n_blocked_status blocked;

	errno = 0;
	s2n_errno = S2N_ERR_T_OK;

//	warn("ssl_handshake s2n_negotiate");

	if (s2n_negotiate(conn->ssl, &blocked) < 0) {
		switch (s2n_error_get_type(s2n_errno)) {
			case S2N_ERR_T_BLOCKED:
				errno=EAGAIN;
//  				warn("ssl_handshake Blocked, come back later");
				return -1;
			case S2N_ERR_T_CLOSED:
				conn->state = DONE;
				warn("ssl_handshake S2N_ERR_T_CLOSED");
				return 0;
			case S2N_ERR_T_IO:
				conn->state = DONE;
				warn("ssl_handshake handle_io_err");
				return -1;
			case S2N_ERR_T_PROTO:
				conn->state = DONE;
				warn("ssl_handshake handle_proto_err");
				return -1;
			case S2N_ERR_T_ALERT:
				conn->state = DONE;
				s2n_connection_get_alert(conn->ssl);
				warn("ssl_handshake s2n_connection_get_alert");
				return -1;
			default:
				conn->state = DONE;
				warn("ssl_handshake log_other_error");
				return -1;
		}
	}

	if (blocked == S2N_NOT_BLOCKED) {
        conn->state = RECV_REQUEST;
		return 1;
    }

	return -1;
}
#elif defined(ENABLE_SSL_TLS)
//-----------------------------------------------------------------------------
static int ssl_configure(struct connection* conn)
//-----------------------------------------------------------------------------
{
	struct tls *ssl = 0L;

	if (tls_accept_socket( conn->ssl, &ssl, conn->socket) < 0) {
		conn->ssl = NULL;
		DBG("ssl_configure FAIL SSL socket %d\n", conn->socket);
		return (-1);
	}

	conn->ssl = ssl;
	DBG("ssl_configure SSL socket %d\n", conn->socket);
	return 0;
}

//-----------------------------------------------------------------------------
static int ssl_send(struct connection* conn, char *buf, ssize_t sent)
//-----------------------------------------------------------------------------
{
	errno = 0;

	sent = tls_write(conn->ssl, buf, sent);

	if (sent < 0) {
		switch (sent) {
			case TLS_WANT_POLLIN:
			case TLS_WANT_POLLOUT:
				errno=EAGAIN;
				return (-1);

			case (-1):
				conn->state = SSL_DONE;
				warn("ssl_send connection_get_alert %s", tls_error(conn->ssl));
				return -1;
			default:
			break;
		}
	}

	return sent;
}

//-----------------------------------------------------------------------------
static int ssl_recv(struct connection* conn, char *buf, ssize_t recvd)
//-----------------------------------------------------------------------------
{
	errno = 0;

	recvd = tls_read(conn->ssl, buf, recvd);

	if (recvd < 0) {
		switch (recvd) {
			case TLS_WANT_POLLIN:
			case TLS_WANT_POLLOUT:
				errno=EAGAIN;
				return (-1);

			case (-1):
				conn->state = SSL_DONE;
				warn("ssl_recv connection_get_alert %s", tls_error(conn->ssl));
				return -1;
			default:
			break;
		}
	}

	return recvd;
}

//-----------------------------------------------------------------------------
static int ssl_shutdown(struct connection* conn)
//-----------------------------------------------------------------------------
{
	errno = 0;

	if (tls_close(conn->ssl) < 0) {
		warn("ssl_shutdown: connection_get_alert %s", tls_error(conn->ssl));
		return -1;
	}

	conn->state = DONE;
	return 1;
}

//-----------------------------------------------------------------------------
static int ssl_handshake(struct connection* conn)
//-----------------------------------------------------------------------------
{
	errno = 0;

	switch (tls_handshake(conn->ssl)) {
		case TLS_WANT_POLLIN:
		case TLS_WANT_POLLOUT:
			errno=EAGAIN;
			return (-1);

		case (-1):
			warn("ssl_handshake connection_get_alert %s",tls_error(conn->ssl));
            conn->state = SSL_DONE;
			return -1;
		default:
		break;
	}

    conn->state = RECV_REQUEST;
	return 1;
}
#endif
#endif

/* Accept a connection from sockin and add it to the connection queue. */
//-----------------------------------------------------------------------------
static void accept_connection(int ssl_on)
//-----------------------------------------------------------------------------
{
	struct connection* conn;

#ifdef ENABLE_INET6
	struct sockaddr_in6 addrin6;
	struct sockaddr *addrin = (struct sockaddr*) &addrin6;
	socklen_t sin_size = sizeof(struct sockaddr_in6);
#else
	struct sockaddr_in addrin4;
	struct sockaddr *addrin = (struct sockaddr*) &addrin4;
	socklen_t sin_size = sizeof(struct sockaddr_in);
#endif

	int insock = ssl_on > 0 ? sockin_ssl : sockin;

	errno = 0;

	if (num_freeconnections < 1) {
		conn = new_connection();
	} else {
		conn = LIST_FIRST(&freeconnlist);
		LIST_REMOVE(conn, entries);
		num_freeconnections -= 1;
		//recycle_connection(conn);
		conn->lasttime = now;
	}

	memset( addrin, 0, sin_size );
	conn->socket = accept( insock, addrin, &sin_size );
	if (conn->socket == -1) { err(1, "accept()"); }

	nonblock_socket(conn->socket);
	conn->state = RECV_REQUEST;

#ifdef ENABLE_INET6
	conn->client = addrin6.sin6_addr;
#else
	*(in_addr_t*)&conn->client = addrin4.sin_addr.s_addr;
#endif

	LIST_INSERT_HEAD(&connlist, conn, entries);

	DBG( "accepted connection from %s:%u\n", inet_ntoa(addrin4.sin_addr), ntohs(addrin4.sin_port));

#ifdef ENABLE_SSL
	if ( ssl_on ) {

		errno = 0;

		if ( num_ssl_servers ) {
			char domain[NI_MAXHOST];

			if (!getnameinfo( addrin, sin_size, domain, sizeof(domain), NULL, 0, NI_NAMEREQD)) {
				conn->fqdn = xstrdup( domain );
				DBG( "%s: Connecting on: https://%s:443/\n", __func__, conn->fqdn );
				//fprintf( logfile, "Connecting on: https://%s:443/\n", conn->fqdn );
			}
		}

		ssl_new( conn );

		if (conn->ssl == NULL) {
			conn->state = DONE;
			warn("ssl_accept new FAIL()");

		} else {

			if (ssl_configure( conn ) < 0)
				conn->state = DONE;

			DBG( "accept_connection SSL socket %d\n", conn->socket);
			conn->state = SSL_ACCEPT;
		}
	} else {
		poll_recv_request(conn);
	}
#else
	/* Try to read straight away rather than going through another iteration
	 * of the select() loop.
	 */
		poll_recv_request(conn);
#endif
}

/* Should this character be logencoded?
 */
//-----------------------------------------------------------------------------
static int needs_logencoding(const unsigned char c)
//-----------------------------------------------------------------------------
{
	return ((c <= 0x1F) || (c >= 0x7F) || (c == '"'));
}

/* Encode string for logging.
 */
//-----------------------------------------------------------------------------
static void logencode(const char* src, char* dest)
//-----------------------------------------------------------------------------
{
	static const char hex[] = "0123456789ABCDEF";
	int i, j;

	for (i = j = 0; src[i] != '\0'; i++) {
		if (needs_logencoding((unsigned char)src[i])) {
			dest[j++] = '%';
			dest[j++] = hex[(src[i] >> 4) & 0xF];
			dest[j++] = hex[ src[i]		& 0xF];
		} else {
			dest[j++] = src[i];
		}
	}
	dest[j] = '\0';
}

/* Uppercasify all characters in a string of given length. */
//-----------------------------------------------------------------------------
static void strntoupper(char* str, const size_t length)
//-----------------------------------------------------------------------------
{
	size_t i;

	for (i = 0; i < length; i++)
	{ str[i] = (char)toupper(str[i]); }
}

//-----------------------------------------------------------------------------
static void log_connection(struct connection* conn, int onrequest)
//-----------------------------------------------------------------------------
{
	char* safe_referer, *safe_user_agent;
	char* safe_method, *safe_url;

	if (logfile == NULL) { return; }

	/* invalid - didn't parse - maybe too long */
	if (conn->method == NULL) { return; }

	/* invalid - died in request */
	if (conn->http_code == 0) { return; }

	//if (!onrequest && conn->http_code == 0) { return; }
	//conn->logged = 1;
	//fprintf( logfile, "Len=%d\n", strlen(conn->x));

#define make_safe(x) \
	if (conn->x) { \
		safe_##x = xmalloc(strlen(conn->x)*3 + 1); \
		logencode(conn->x, safe_##x); \
	} else { \
		safe_##x = NULL; \
	}

	make_safe(method);
	make_safe(url);
	make_safe(referer);
	make_safe(user_agent);

#define use_safe(x) safe_##x ? safe_##x : ""
	fprintf(logfile, "%lu %s \"%s %s\" [%d] [conn# %d] %llu \"%s\" \"%s\"\n",
		(unsigned long int)now,
		get_address_text(&conn->client),
		//conn->method,
		use_safe(method),
		use_safe(url),
		conn->http_code,
		num_connections,
		onrequest ? llu(conn->content_len) : llu(conn->total_sent),
		use_safe(referer),
		use_safe(user_agent)
		);
	fflush(logfile);

#define free_safe(x) if (safe_##x) free(safe_##x);
	free_safe(method);
	free_safe(url);
	free_safe(referer);
	free_safe(user_agent);
#undef make_safe
#undef use_safe
#undef free_safe
}

/* If a connection has been idle for more than idletime seconds, it will be
 * marked as DONE and killed off in httpd_poll()
 */
//-----------------------------------------------------------------------------
static void poll_check_timeout(struct connection* conn)
//-----------------------------------------------------------------------------
{
	time_t elapsed = now - conn->lasttime;

	DBG("%s: FD=%d) %ld now=%ld elapsed=%ld\n", __func__, conn->socket, conn->lasttime, now, elapsed);

	if (elapsed >= idletime) {
		fprintf( logfile, "%s: SOCKET=%d caused closure\n", __func__, conn->socket);

#ifdef ENABLE_SSL
		if (conn->ssl && conn->state != SSL_DONE) {
			conn->state = SSL_DONE;
		}
		else
#endif
		{
			conn->state = DONE;
			conn->conn_close = 1;
		}
	}
}

/* Format [when] as an RFC1123 date, stored in the specified buffer.  The same
 * buffer is returned for convenience.
 */
#define DATE_LEN 30 /* strlen("Fri, 28 Feb 2003 00:02:08 GMT")+1 */
//-----------------------------------------------------------------------------
static char* rfc1123_date(char* dest, const time_t when)
//-----------------------------------------------------------------------------
{
	time_t when_copy = when;

	if (strftime(dest, DATE_LEN,
		"%a, %d %b %Y %H:%M:%S GMT", gmtime(&when_copy)) == 0)
	{ errx(1, "strftime() failed [%s]", dest); }

	return dest;
}

/* Decode URL by converting %XX (where XX are hexadecimal digits) to the
 * character it represents.  Don't forget to free the return value.
 */
//-----------------------------------------------------------------------------
static void urldecode(struct connection* conn)
//-----------------------------------------------------------------------------
{
	size_t i, pos;
	size_t len = conn->urllen;
	char* out = xmalloc( len+1 );
	char* url = conn->url;

	for (i = 0, pos = 0; i < len; i++) {
		if ((url[i] == '%') && (i + 2 < len) &&
				isxdigit(url[i + 1]) && isxdigit(url[i + 2])) {
			/* decode %XX */
#define HEX_TO_DIGIT(hex) ( \
	((hex) >= 'A' && (hex) <= 'F') ? ((hex)-'A'+10): \
	((hex) >= 'a' && (hex) <= 'f') ? ((hex)-'a'+10): \
	((hex)-'0') )
			out[pos++] = HEX_TO_DIGIT(url[i + 1]) * 16 + HEX_TO_DIGIT(url[i + 2]);
			i += 2;
#undef HEX_TO_DIGIT
		} else if (url[i] == '/' && url[i+1] == '/') {
			//skip;
		} else {
			/* straight copy */
			out[pos++] = url[i];
		}
	}

	out[pos] = '\0';
	conn->decoded_url = out;
	conn->decoded_urllen = pos;
	//fprintf( logfile, "LEN=%d %d\n", pos, strlen(conn->decoded_url));
}

/* Returns Connection or Keep-Alive header, depending on conn_close. */
//-----------------------------------------------------------------------------
static const char* keep_alive(const struct connection* conn)
//-----------------------------------------------------------------------------
{
	return (conn->conn_close ? "Connection: close\r\n" : keep_alive_field);
}

/* "Generated by " + pkgname + " on " + date + "\n"
 *  1234567890123				1234			2 ('\n' and '\0')
 */
//-----------------------------------------------------------------------------
static char _generated_on_buf[13 + sizeof(pkgname) - 1 + 4 + DATE_LEN + 2];
//-----------------------------------------------------------------------------
static const char* generated_on(const char date[DATE_LEN])
//-----------------------------------------------------------------------------
{
	if (!want_server_id) { return ""; }

	snprintf(_generated_on_buf, sizeof(_generated_on_buf),
			 "Generated by %s on %s\n", pkgname, date);

	return _generated_on_buf;
}

/* A default reply for any (erroneous) occasion. */
//-----------------------------------------------------------------------------
static void default_reply(struct connection* conn, const int errcode, const char* errname, const char* format, ...) __printflike(4, 5);

//-----------------------------------------------------------------------------
static void default_reply(struct connection* conn, const int errcode, const char* errname, const char* format, ...)
//-----------------------------------------------------------------------------
{
	char* reason, date[DATE_LEN];
	va_list va;

	va_start(va, format);
	xvasprintf(&reason, format, va);
	va_end(va);

	/* Only really need to calculate the date once. */
	rfc1123_date(date, now);

	conn->reply_length = xasprintf(&(conn->reply),
		"<html><head><title>%d %s</title></head><body>\n"
		"<h1>%s</h1>\n" /* errname */
		"%s\n" /* reason */
		"<hr>\n"
		"%s" /* generated on */
		"</body></html>\n",
		errcode, errname, errname, reason, generated_on(date));
	free(reason);

	if (conn->auth_header ) {
		conn->header_length = xasprintf(&(conn->header),
			"HTTP/1.1 %d %s\r\n"
			"Date: %s\r\n"
			"%s" /* server */
			"Accept-Ranges: bytes\r\n"
			"%s" /* keep-alive */
			"%s\r\n" /* www-authenticate */
			"Content-Length: %llu\r\n"
			"Content-Type: text/html; charset=UTF-8\r\n"
			"\r\n",
			errcode, errname, date, server_hdr, keep_alive(conn),
			conn->auth_header, llu(conn->reply_length));

			free(conn->auth_header);
			conn->auth_header = NULL;
	}
	else {
		conn->header_length = xasprintf(&(conn->header),
			"HTTP/1.1 %d %s\r\n"
			"Date: %s\r\n"
			"%s" /* server */
			"Accept-Ranges: bytes\r\n"
			"%s" /* keep-alive */
			"Content-Length: %llu\r\n"
			"Content-Type: text/html; charset=UTF-8\r\n"
			"\r\n",
			errcode, errname, date, server_hdr, keep_alive(conn),
			llu(conn->reply_length));
	}

	conn->reply_type = REPLY_GENERATED;
	conn->http_code = errcode;
	conn->http_error = 1;
}

//-----------------------------------------------------------------------------
static void redirect(struct connection* conn, const char* format, ...) __printflike(2, 3);
static void redirect(struct connection* conn, const char* format, ...)
//-----------------------------------------------------------------------------
{
	char* where, date[DATE_LEN];
	va_list va;

	va_start(va, format);
	xvasprintf(&where, format, va);
	va_end(va);

	/* Only really need to calculate the date once. */
	rfc1123_date(date, now);

	conn->reply_length = xasprintf(
		 &(conn->reply),
		 "<html><head><title>301 Moved Permanently</title></head><body>\n"
		 "<h1>Moved Permanently</h1>\n"
		 "Moved to: <a href=\"%s\">%s</a>\n" /* where x 2 */
		 "<hr>\n"
		 "%s" /* generated on */
		 "</body></html>\n",
		 where, where, generated_on(date)
	);

	conn->header_length = xasprintf(
		  &(conn->header),
		  "HTTP/1.1 301 Moved Permanently\r\n"
		  "Date: %s\r\n"
		  "%s" /* server */
		  /* "Accept-Ranges: bytes\r\n" - not relevant here */
		  "Location: %s\r\n"
		  "%s" /* keep-alive */
		  "Content-Length: %llu\r\n"
		  "Content-Type: text/html; charset=UTF-8\r\n"
		  "\r\n",
		  date, server_hdr, where, keep_alive(conn), llu(conn->reply_length)
	);

	free(where);
	conn->reply_type = REPLY_GENERATED;
	conn->http_code = 301;
	conn->http_error = 1;
}

//-----------------------------------------------------------------------------
static char* decode_url(struct connection* conn)
//-----------------------------------------------------------------------------
{
	/* Work out path of file being requested */
	urldecode( conn );

	/* Make sure it's safe */
	if (make_safe_url( conn ))
		return conn->decoded_url;

	default_reply(conn, 400, "Bad Request", "You requested an invalid URL: %s", conn->url);
	return NULL;
}

//-----------------------------------------------------------------------------
static int dir_exists(const char* path)
//-----------------------------------------------------------------------------
{
	struct stat strec;
	if ((stat(path, &strec) == -1) && (errno == ENOENT))
		return 0;
	return S_ISDIR( strec.st_mode ) ? 1 : 0;
}

//-----------------------------------------------------------------------------
static int file_exists(const char* path)
//-----------------------------------------------------------------------------
{
	struct stat strec;
	if ((stat(path, &strec) == -1) && (errno == ENOENT))
		return 0;
	return S_ISREG( strec.st_mode ) ? 1 : 0;
}

//-----------------------------------------------------------------------------
static int file_size(const char* path)
//-----------------------------------------------------------------------------
{
	struct stat strec;

	if ((stat(path, &strec) == -1) && (errno == ENOENT))
		return 0;

	if (S_ISREG( strec.st_mode ))
		return strec.st_size;

	return 0;
}

/* Adds contents of default_extension_map[] to mime_map list.  The array must
 * be NULL terminated.
 */
//-----------------------------------------------------------------------------
static void parse_default_extension_map(void)
//-----------------------------------------------------------------------------
{
	size_t i, j;

	for (i=0; mimetypes[i]; i++) {
		longest_ext = maxstrlen( mimetypes[i]->key, longest_ext );
	}

	i = mimetypes_total;

	for (j=0; default_extension_map[j].key; j++, i++) {

		mimetypes[i] = xmalloc(sizeof(struct data_tuple));
		mimetypes[i]->key = default_extension_map[j].value;
		mimetypes[i]->value = default_extension_map[j].key;

		longest_ext = maxstrlen( mimetypes[i]->key, longest_ext );
	}

	tuple_sort( mimetypes, mimetypes_total=i );
}

/* Parses a single HTTP request field.  Returns string from end of [field] to
 * first \r, \n or end of request string.  Returns NULL if [field] can't be
 * matched.
 *
 * You need to remember to deallocate the result.
 * example: parse_field(conn, "Referer: ");
 */
//-----------------------------------------------------------------------------
static char *parse_field(const struct connection *conn, const char *field) {
//-----------------------------------------------------------------------------

	size_t bound1, bound2;

	/* find start */
	char *pos = strstr( conn->request, field );

	if (pos == NULL)
		return NULL;

	assert(pos >= conn->request);

	bound1 = (size_t)(pos - conn->request) + strlen(field);

	/* find end */
	for (bound2 = bound1;
		 ((bound2 < conn->request_length) &&
		  (conn->request[bound2] != '\r') &&
		  (conn->request[bound2] != '\n'));
		 bound2++)
			;

	/* copy to buffer */
	return split_string(conn->request, bound1, bound2);
}

//-----------------------------------------------------------------------------
static char* skipcr(char *sptr, char **bptr)
//-----------------------------------------------------------------------------
{
	for (; *sptr != '\r' && *sptr != '\n'; sptr++) ;
	for (; *sptr == '\r' || *sptr == '\n'; sptr++) ;
	(*bptr) = sptr;
	sptr--;
	return sptr;
}

//-----------------------------------------------------------------------------
static int parse_tuples(struct connection* conn, struct data_tuple* tuples[],
//-----------------------------------------------------------------------------
	char* buffer, char delim, const char* echrs, int maximum)
{
	int for_hdr = tuples == (conn ? conn->headers : 0);
	int for_body = tuples == (conn ? conn->tuples : 0);
	int for_http = for_hdr || for_body;
	char *sptr = buffer;
	char *bptr = sptr;
	char *inigrp = NULL;
	int begofline = !for_hdr;
	int total, i = 0;
	int seqlen = 0;
	int slen = 0;

	DBG_2( "Buffer: '%s'\n", buffer);

	for (; (*sptr); sptr++) {

		if (i > maximum)
			return 0;

		switch ( *sptr ) {
			case '\\':
				sptr++;
			break;
			case '/':
				begofline = begofline && (*++sptr) == '/' ? 1 : 0;

			case '.':
				begofline = begofline || !strncmp( sptr, ".enc.", 5 ); 

			case '#':
				if ( begofline ) {
					sptr = skipcr( sptr, &bptr );
					/*
					for (; *sptr != '\r' && *sptr != '\n'; sptr++) ;
					for (; *sptr == '\r' || *sptr == '\n'; sptr++) ;
					bptr = sptr;
					sptr--;
					*/
				}
			break;
			case '[':
				DBG_2("begofline=%d\n",begofline);

				if ( begofline ) {
					bptr = ++sptr;
					for (; *sptr != ']'; sptr++) ;
					*sptr = '\0';

					inigrp = bptr;
					sptr = skipcr( sptr, &bptr );
					begofline = 1;

					DBG_2("inigrp='%s'\n",inigrp);
				}

			break;
			case '\r':
			case '\n':

				// Only encoded CR/LF in www.url.encoded
				if ( for_body )
					return 0;

				if (strchr( echrs, *sptr )) {
					tuples[i++]->value = bptr;

					if ( tuples[i] ) {
						tuples[i]->key = NULL;
					}
				}

				if (!strncmp( sptr, "\n\n", 2 ))
					seqlen = 2;
				else if (!strncmp( sptr, "\r\n\r\n", 4 ))
					seqlen = 4;
				else
					seqlen = 0;

				/*
				DBG_2("SEQLEN=%d\n",seqlen);
				*/

				if (for_hdr && seqlen > 0) {
					conn->body = sptr + seqlen;
					*sptr++ = '\0';
					*sptr-- = '\0';

				} else {
					bptr = sptr;

					for (; *bptr == '\r' || *bptr == '\n'; bptr++) ;

					if ( for_hdr ) {
						if ((bptr-sptr) > 2) {
							return 0;
						}
					} else {
						begofline = 1;
					}
					*sptr = '\0';
					sptr = bptr;
					sptr--;
				}

				/*
				DBG_2("VALUE='%s'\n", tuples[i-1]->value);
				DBG_2("KEY='%s'\n", bptr);
				*/
			break;
			case '&':
			case ';':
				if (strchr( echrs, *sptr )) {
					*sptr = '\0';
					tuples[i++]->value = bptr;

					if ( tuples[i] ) {
						tuples[i]->key = NULL;
					}

					//DBG_2("VALUE[%d]=\"%s\"\n", i-1, tuples[i-1]->value);
					bptr = ++sptr;
				}
			break;
			case '=': // www.url.encoded
			case ':': // HTTP header
			case '\t': // TAB separated tuples

				if ( !tuples[i] ) {
					tuples[i] = xmalloc(sizeof(struct data_tuple));
					tuples[i]->key = tuples[i]->value = NULL;
				}

				if (*sptr == delim && tuples[i]->key == NULL) {

					*sptr = '\0';

					if ( inigrp ) {
						slen = strlen(bptr) + strlen(inigrp) + 2;
						tuples[i]->key = xmalloc( slen );
						strcpy( tuples[i]->key, (const char*) inigrp );
						strcat( tuples[i]->key, (const char*) "/" );
						strcat( tuples[i]->key, (const char*) bptr );
					} else {
						tuples[i]->key = bptr;
					}

					tuples[i]->value = NULL;

					DBG_2("KEY[%d]=\"%s\" 0x%x\n", i, tuples[i]->key, (unsigned int) tuples[i]->key);
				/*
				*/

					if (delim == '=') {
						bptr = sptr+1;
					} else {
						for (; (*++sptr) == ' '; );
						bptr = sptr;
					}
				}
			break;
			default:
				begofline = 0;
			break;
		}
	}

	DBG_2("LAST TUPLES[%d]=0x%x\n", i, (unsigned int) tuples[i] ) ;

	if ( tuples[i] ) {

		if ( tuples[i]->key ) {

			DBG_2("LAST TUPLES[%d]='%s'\n", i, tuples[i]->key );

			if (bptr && !tuples[i]->value) {
				//DBG_2("LAST VALUE TUPLES[%d]='%s'\n", i, bptr);
				tuples[i++]->value = bptr;
			}
		}

		if ( tuples[i] ) {
			tuples[i]->key = NULL;
			tuples[i]->value = NULL;
		}
	}

	tuple_sort( tuples, total=i );

#if 0
	DBG_2("TUPLES 0x%x\n", tuples );

	DBG_2("TOTAL %d\n", i );

	for (i=0; i<total; i++) {
		fprintf( logfile,
			"TUPLE[%d][0x%x][%s]='%s'\n",
			i, tuples[i], tuples[i]->key, tuples[i]->value 
		);
	}
#endif

	return total;
}

//-----------------------------------------------------------------------------
static int load_file(const char* filename, char** buffer, int maximum)
//-----------------------------------------------------------------------------
{
	FILE* fp = fopen( filename, "rb" );
	int sz = file_size( filename );
	char *sptr = (*buffer) = NULL;
	size_t nread = 0;
	int total = sz;
	int i = 0;

	DBG_2( "load_file: file size=%d max=%d\n", sz, maximum );

	if (!fp) {
		fprintf( errfile, "load_file: no such file %s\n", filename );
		return 0;
	}

	errno=0;

	if (sz >= maximum) {
		fprintf( errfile, "load_file: file size=%d max=%d\n", sz, maximum );
		return 0;
	}

	sptr = (*buffer) = xmalloc( sz+3 );

	while (sz > 0 && !feof( fp )) {

		nread = fread( sptr, sizeof(char), sz, fp );
		//fprintf(logfile, "load_file: LOADING size=%d nread=%d\n", sz, nread );

		if (nread > 0) {
			sptr += nread;
			sz -= nread;
			//fprintf( logfile, "load_file: INCR size=%d max=%d %d\n", sz, maximum, nread );
		}

		if (ferror(fp)) {
			fclose(fp);
			return sz == 0 ? total : 0;
		}
	}

	fclose(fp);

	sptr = (*buffer);
	sptr += total;
	(*sptr) = '\0';

	return sz == 0 ? total : 0;
}

//-----------------------------------------------------------------------------
static int load_cfgfile(const char* path, char **buffer, struct data_tuple* tuples[], int maxsz)
//-----------------------------------------------------------------------------
{
	static const char* const crnl = "\r\n";
	int total = load_file( path, buffer, 1 << 15 );
	if (total > 0)
		total = parse_tuples( 0L, tuples, (*buffer), '=', crnl, maxsz );
	return total;
}

//-----------------------------------------------------------------------------
static int get_cached_url(struct connection* conn, const char* arg)
//-----------------------------------------------------------------------------
{
	struct data_bucket key;

	 key.key = (char*) arg;

	struct data_bucket** found = bsearch(
		&key, staticcache, staticcache_total,
		sizeof(struct data_bucket*),
		bucket_cmp
	);

	//DBG("TRY get_cached_url %s\n",arg);

	if ( found ) {
	//DBG("FOUND get_cached_url %s\n",arg);
		conn->payload_size = (*found)->size;
		conn->payload_lastmod = (*found)->lastmod;
		conn->reply = (*found)->value;
		conn->reply_type = REPLY_CACHED;
		conn->reply_start = 0;
	}
	return found ? 1 : 0;
}

//-----------------------------------------------------------------------------
static const char* url_content_type(const char* url, int urllen, char** suffix)
//-----------------------------------------------------------------------------
{
	int period = 0;
	//int urllen = urllen; //(int)strlen(url);
	char *mimetype = NULL;

	for (period = urllen - 1;
			(period > 0) && (url[period] != '.') &&
			(urllen - period - 1 <= (int)longest_ext);
			period--)
		;

	if ((period >= 0) && (url[period] == '.')) {
		(*suffix) = (char*) (url+period+1);
		mimetype = tuple_search( mimetypes, mimetypes_total, (*suffix) );
	}
	return mimetype != NULL ? mimetype : default_mimetype;
}

/* Parse a Range: field into range_begin and range_end. Only handles the
 * first range if a list is given.  Sets range_{begin,end}_given to 1 if
 * either part of the range is given.
 */
//-----------------------------------------------------------------------------
static void parse_range_field(struct connection* conn)
//-----------------------------------------------------------------------------
{
	const char* range_header = hdrsearch( conn, "Range" );

	if (range_header == NULL) { return; }

	char *range = xstrdup( range_header );

	if (!strstr( range, "bytes=" ))
		return;

	do {
		size_t len = strlen(range);
		size_t bound1, bound2;

		/* parse number up to hyphen */
		bound1 = 0;

		for (bound2 = 0;
				isdigit((int)range[bound2]) && (bound2 < len);
				bound2++)
			;

		if ((bound2 == len) || (range[bound2] != '-'))
		{ break; } /* there must be a hyphen here */

		if (bound1 != bound2) {
			conn->range_begin_given = 1;
			conn->range_begin = (off_t)strtoll(range + bound1, NULL, 10);
		}

		/* parse number after hyphen */
		bound2++;

		for (bound1 = bound2;
				isdigit((int)range[bound2]) && (bound2 < len);
				bound2++)
			;

		if ((bound2 != len) && (range[bound2] != ','))
		{ break; } /* must be end of string or a list to be valid */

		if (bound1 != bound2) {
			conn->range_end_given = 1;
			conn->range_end = (off_t)strtoll(range + bound1, NULL, 10);
		}
	} while (0);

	free(range);
}

//-----------------------------------------------------------------------------
static int verify_request(struct connection* conn)
//-----------------------------------------------------------------------------
{
	char* bptr = conn->request;

	DBG("REQUEST TEXT %s\n", bptr );

	return bptr && (
		!strncasecmp(bptr, "GET ", 4) ||
		!strncasecmp(bptr, "POST ", 5) ||
		!strncasecmp(bptr, "PUT ", 4) ||
		!strncasecmp(bptr, "HEAD ", 5));
}

/* Parse an HTTP request like "GET / HTTP/1.1" to get the method (GET), the
 * url (/), the referer (if given) and the user-agent (if given).  Remember to
 * deallocate all these buffers.  The method will be returned in uppercase.
 */
//-----------------------------------------------------------------------------
static int parse_request(struct connection* conn)
//-----------------------------------------------------------------------------
{
	static const char* const crnl = "\r\n";
	int reqlen = conn->request_length;
	char* bptr = conn->request;
	//size_t bound1, bound2;
	char* tmp, *sptr;
	int chr = 0;
	int i = 0;

	DBG_2( "%s\n", bptr );

	assert(conn->request_length == strlen(conn->request));

	/* parse method */
	for (sptr = bptr; i < reqlen && (*sptr) != ' '; sptr++, i++)
		chr = (*sptr);

	if (i >= reqlen) { return 0; } /* fail */

	(*sptr) = '\0';
	conn->method = bptr;
	bptr = ++sptr;

	for (sptr = conn->method; (*sptr); sptr++)
		(*sptr) = (char)toupper( *sptr );

	/* parse url */
	sptr = strpbrk( bptr, "\r\n" );

	if ( !sptr ) { return 0; } /* fail */

	for (; (*sptr) != ' '; --sptr)
		;

	(*sptr) = '\0';
	conn->urllen = sptr - bptr;
	conn->url = split_string( bptr, 0, conn->urllen );
	bptr = ++sptr;

	conn->conn_close = 0;

	for (; (*sptr) != '\n' && (*sptr) != '\r'; sptr++);
	for (; (*sptr) == '\n' || (*sptr) == '\r'; sptr++);

	conn->header = sptr;

	conn->headers_total = parse_tuples(
		conn, conn->headers, conn->header, ':', crnl, MAX_HEADERS
	);

	if (conn->headers_total < 1)
		return 0;

	if ((tmp = hdrsearch( conn, "Connection" ))) {
		  if (tmp != NULL && strcasecmp(tmp, "close") == 0)
				conn->conn_close = 1;
	 }

	/* Parse Important Fields */
	conn->referer = hdrsearch( conn, "Referer" );
	conn->user_agent = hdrsearch( conn, "User-Agent" );

	parse_range_field( conn );
	return 1;
}

//-----------------------------------------------------------------------------
static int dlent_cmp(const void* a, const void* b)
//-----------------------------------------------------------------------------
{
	return strcmp((*((const struct dlent * const*)a))->name,
		(*((const struct dlent * const*)b))->name);
}

#ifdef ENABLE_SLOCATE
/* Make sorted list of files in a directory.
 * Returns number of entries, or -1 if error occurs.
 */
//-----------------------------------------------------------------------------
static ssize_t get_locate_listing(const char* path, struct dlent** *output, size_t *maxlen)
//-----------------------------------------------------------------------------
{
	struct dlent** list = NULL;
	struct dirent* ent;
	char cmd[2048]={'\0'};
	size_t entries = 0;
	size_t pool = 128;
	FILE *proc = NULL;

	sprintf(
		cmd,
		"slocate -q -i -d %s -n %s \"%s\"",
		locate_dbpath, 
		locate_maxhits,
		path
	);

	proc = popen( cmd, "r" );

	if ( proc ) {
		char *curname = xmalloc( MAX_BUFSZ+1 );
		size_t chrs = MAX_BUFSZ;
		ssize_t nread = 0;
		struct stat s;

		while ( !feof(proc) && !ferror(proc) ) {

			nread = getline( &curname, &chrs, proc );

			if (nread > 0) {

				if (stat(curname, &s) == -1)
				{ continue; } /* skip un-stat-able files */

				if (*maxlen < nread) { *maxlen = nread; }

				if (entries == pool) {
					pool *= 2;
					list = xrealloc(list, sizeof(struct dlent*) * pool);
				}

				list[entries] = xmalloc(sizeof(struct dlent));
				list[entries]->name = xstrdup( curname );
				list[entries]->is_dir = S_ISDIR(s.st_mode);
				list[entries]->size = s.st_size;

				entries++;
			}
		}
		free(curname);
		pclose( proc );
	}

	qsort(list, entries, sizeof(struct dlent*), dlent_cmp);
	*output = list;

	return (ssize_t)entries;
}
#endif /* _ENABLE_SLOCATE_ */

/* Make sorted list of files in a directory.
 * Returns number of entries, or -1 if error occurs.
 */
//-----------------------------------------------------------------------------
static ssize_t make_sorted_dirlist(const char* path, struct dlent** *output, size_t *maxlen)
//-----------------------------------------------------------------------------
{
	struct dirent* ent;
	size_t entries = 0;
	size_t pool = 128;
	size_t slen = 0;
	char* currname;
	struct dlent** list = NULL;
	DIR* dir = opendir(path);
	size_t rlen = strlen(path);

	if (dir == NULL) { return -1; }

	currname = xmalloc(strlen(path) + MAXNAMLEN + 1);
	list = xmalloc(sizeof(struct dlent*) * pool);

	/* construct list */
	while ((ent = readdir(dir)) != NULL) {

		struct stat s;

		if ((ent->d_name[0] == '.') && (ent->d_name[1] == '\0'))
		{ continue; } /* skip "." */

		slen = strlen(ent->d_name);
		assert(slen <= MAXNAMLEN);
		sprintf(currname, "%s%s", path, ent->d_name);

		if (stat(currname, &s) == -1)
		{ continue; } /* skip un-stat-able files */

		if (*maxlen < slen+rlen) { *maxlen = slen+rlen; }

		if (entries == pool) {
			pool *= 2;
			list = xrealloc(list, sizeof(struct dlent*) * pool);
		}

		list[entries] = xmalloc(sizeof(struct dlent));
		list[entries]->name = xstrdup(ent->d_name);
		list[entries]->is_dir = S_ISDIR(s.st_mode);
		list[entries]->size = s.st_size;

		entries++;
	}

	closedir(dir);
	free(currname);
	qsort(list, entries, sizeof(struct dlent*), dlent_cmp);
	*output = list;

	return (ssize_t)entries;
}

/* Cleanly deallocate a sorted list of directory files. */
//-----------------------------------------------------------------------------
static void cleanup_sorted_dirlist(struct dlent** list, const ssize_t size)
//-----------------------------------------------------------------------------
{
	ssize_t i;

	for (i = 0; i < size; i++) {
		free(list[i]->name);
		free(list[i]);
	}
}

/* Is this an unreserved character according to
 * https://tools.ietf.org/html/rfc3986#section-2.3
 */
//-----------------------------------------------------------------------------
static int is_unreserved(const unsigned char c)
//-----------------------------------------------------------------------------
{
	if (c >= 'a' && c <= 'z') { return 1; }
	if (c >= 'A' && c <= 'Z') { return 1; }
	if (c >= '0' && c <= '9') { return 1; }

	switch (c) {
		case '-':
		case '.':
		case '_':
		case '~':
			return 1;
		break;
	}
	return 0;
}

/* Encode string to be an RFC3986-compliant URL part.
 * Contributed by nf.
 */
//-----------------------------------------------------------------------------
static void urlencode(const char* src, char* dest)
//-----------------------------------------------------------------------------
{
	static const char hex[] = "0123456789ABCDEF";
	int i, j;

	for (i = j = 0; src[i] != '\0'; i++) {
		if (!is_unreserved((unsigned char)src[i])) {
			dest[j++] = '%';
			dest[j++] = hex[(src[i] >> 4) & 0xF];
			dest[j++] = hex[ src[i]		& 0xF];
		}
		else
		{ dest[j++] = src[i]; }
	}

	dest[j] = '\0';
}

//-----------------------------------------------------------------------------
static void generate_dir_listing(struct connection* conn, const char* path)
//-----------------------------------------------------------------------------
{
	char date[DATE_LEN], *spaces;
	//char *hdr = hdrsearch( conn, "Accept" );
	struct dlent** list;
	ssize_t listsize;
	size_t maxlen = 2; /* There has to be ".." */
	struct apbuf* listing;
	int i = 0;

#ifdef ENABLE_SLOCATE
	if (want_listing && want_slocate) {

		if ( !locate_dbpath || !locate_maxhits ) {
			default_reply(conn, 500, "Internal Server Error",
				"Search mode must be enabled");
			return;
		}

		//if (hdr && !strcasecmp( hdr, "text/tsv" ))
		listsize = get_locate_listing(path, &list, &maxlen);

		if (listsize == -1) {
			default_reply(conn, 500, "Internal Server Error",
				"No hits found for %s", path);
			return;
		}
	}
#endif /* ENABLE_SLOCATE */

	if ( want_listing ) {
		listsize = make_sorted_dirlist(path, &list, &maxlen);

		if (listsize == -1) {
			default_reply(conn, 500, "Internal Server Error",
				"Couldn't list directory: %s", strerror(errno));
			return;
		}

		/*
		for (i = 0; i < listsize; i++) {
			size_t tmp = strlen(list[i]->name);
			if (maxlen < tmp) { maxlen = tmp; }
		}
		*/
	}

	listing = make_apbuf();
	append(listing, "<html>\n<head>\n <title>");
	append(listing, conn->url);
	append(listing, "</title>\n</head>\n<body>\n<h1>");
	append(listing, conn->url);
	append(listing, "</h1>\n<tt><pre>\n");

	spaces = xmalloc(maxlen);
	memset(spaces, ' ', maxlen);

	for (i = 0; i < listsize; i++) {
		/* If a filename is made up of entirely unsafe chars,
		 * the url would be three times its original length.
		 */
		char safe_url[MAXNAMLEN * 3 + 1];
		urlencode(list[i]->name, safe_url);

		append(listing, "<a href=\"");
		append(listing, safe_url);
		append(listing, "\">");
		append(listing, list[i]->name);
		append(listing, "</a>");

		if (list[i]->is_dir) {
			append(listing, "/\n");
		} else {
			appendl(listing, spaces, maxlen - strlen(list[i]->name));
			appendf(listing, "%10llu\n", llu(list[i]->size));
		}
	}

	cleanup_sorted_dirlist(list, listsize);
	free(list);
	free(spaces);

	append(listing, "</pre></tt>\n" "<hr>\n");
	rfc1123_date(date, now);
	append(listing, generated_on(date));
	append(listing, "</body>\n</html>\n");

	conn->reply = listing->str;
	conn->reply_length = (off_t)listing->length;
	free(listing); /* don't free inside of listing */

	conn->header_length = xasprintf(&(conn->header),
		"HTTP/1.1 200 OK\r\n"
		"Date: %s\r\n"
		"%s" /* server */
		"Accept-Ranges: bytes\r\n"
		"%s" /* keep-alive */
		"Content-Length: %llu\r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
		"\r\n",
		date, server_hdr, keep_alive(conn), llu(conn->reply_length)
		);
	conn->reply_type = REPLY_GENERATED;
	conn->http_code = 200;
}

#ifdef ENABLE_GUESTBOOK
//-----------------------------------------------------------------------------
static int init_guestbook()
//-----------------------------------------------------------------------------
{
	char* folder;
	char* value;

	if ((value = inisearch( "Guestbook/path", NULL ))) {
	    xasprintf(&path, "%s/guestbook/%s", baseroot, value );
		guestbook_file = fopen( path, "ab");
        free(path);
    }

	if (guestbook_file == NULL)
		errx(1, "failed to open guestbook file");

	if ((value = inisearch( "Guestbook/reply", NULL )))
	    xasprintf(&guestbook_reply, "%s/guestbook/%s", baseroot, value );

	if (guestbook_reply == NULL)
		errx(1, "failed to locate guestbook reply file");

	if ((value = inisearch( "Guestbook/template", NULL ))) {
	    xasprintf(&path, "%s/guestbook/%s", baseroot, value );
		if (load_file( value, &guestbook_template, (1 << 12)) < 1)
			errx(1, "invalid guestbook template file --guestbook");
        free(path);
	}

	if (guestbook_template == NULL)
		errx(1, "failed to open guestbook template file");

	return 1;
}

//-----------------------------------------------------------------------------
static int fill_guestbook(struct connection* conn)
//-----------------------------------------------------------------------------
{
	char *sptr = guestbook_template;
	char *bptr = sptr;
	char *value = NULL;

	while ((sptr = strstr( sptr, "<%" ))) {

		(*sptr) = '\0';
		fprintf( guestbook_file, "%s", bptr );

		bptr = sptr += 2;
		sptr = strstr( sptr, "%>" );

		if ( !sptr ) { return 0; }

		(*sptr) = '\0';

		value = tuple_search( conn->tuples, conn->tuples_total, bptr );

		if (value != NULL && (*value)) {
			fprintf( guestbook_file, "%s", value );
		}
		bptr = sptr += 2;
	}

	fprintf( guestbook_file, "%s", bptr );
	//fflush( guestbook_file );

	return 1;
}
#endif

#ifdef ENABLE_PASSWORD
//-----------------------------------------------------------------------------
static int password_ok(struct connection* conn, const char* user, const char* password)
//-----------------------------------------------------------------------------
{
	char *crypted = crypt( password, password_salt );
	if ( crypted ) {
		if (htpasswd( user, crypted )) {
			//if ((conn->cookies = hdrsearch( conn, "Cookies" ))) {
			//}
			return 1;
		}
	}
	return 0;
}

//-----------------------------------------------------------------------------
static int parse_auth(struct connection* conn)
//-----------------------------------------------------------------------------
{
	char* auth_url = xstrdup( conn->decoded_url );
	int i = conn->decoded_urllen - 1;
	const char* need_password = NULL;
	char* protected_key = NULL;
	char *password = NULL;
	int nwrite = 0;

	for (; i > 0 && auth_url[i] == '/'; --i)
		auth_url[i] = '\0';

	xasprintf(&protected_key, "%s%s", "Protected/", auth_url );
	need_password = inisearch( protected_key, NULL );
	free(auth_url);

//fprintf( logfile, "Authenticate '%s' '%s' '%s'\n", protected_key, conn->url, conn->decoded_url );
//fflush( logfile );

	if ( need_password ) {

		conn->auth = hdrsearch( conn, "Authorization" );

		if (passwords_total < 1 || strcasestr( need_password, "forbidden" )) {
			default_reply(conn, 403, "Forbidden",
				"You sent a request that the server couldn't allow.");
			return 0;
		}

		if ( conn->auth ) {

			if ((password = strstr( conn->auth, "Basic " ))) {
				base64_decodestate b64state={ step_a, '\0' };
				int passwdlen = strlen(password+6);

				base64_buf[passwdlen] = '\0';
				nwrite = base64_decode_block( password+6, passwdlen, base64_buf, &b64state );

//fprintf( logfile, "Authorize '%s' '%s' '%s' '%s' %d %d\n", conn->auth, (password+6), base64_buf, conn->decoded_url, nwrite, passwdlen );
//fflush( logfile );

				if (nwrite < passwdlen) {
					if ((password = strchr( base64_buf, ':' ))) {
						(*password) = '\0';

						if (password_ok( conn, base64_buf, password+1 )) {
							return 1;
						}
					}
				}
			}

			default_reply(conn, 401, "Unauthorized",
				"The URL you requested (%s) requires a password.",
				conn->decoded_url
			);
			return 0;
		}

		xasprintf( &conn->auth_header, "WWW-Authenticate: Basic realm=%s", wwwrealm );

		default_reply(conn, 401, "Unauthorized",
			"The URL you requested (%s) requires a password.", conn->url
		);
		return 0;
	}
	return 1;
}
#endif

/* Process a GET/HEAD request. */
//-----------------------------------------------------------------------------
static void process_get(struct connection* conn)
//-----------------------------------------------------------------------------
{
	/* work out path of file being requested */
	int rootdirlen = pubrootlen;
	char* decoded_url = conn->decoded_url;
	char date[DATE_LEN], lastmod[DATE_LEN];
	char *throttle, *target, *if_mod_since;
	char *index_file = index_name;
	char *redirect_key, *msecs;
	const char* mimetype = NULL;
	const char* blksize = NULL;
	const char* forward_to = NULL;
	struct stat filestat;
	int slash_path = 0;
	float kbps = 0;
	int rc = 0;
	size_t i=0;

	if (want_redirect && conn->host && !conn->ssl) {
		xasprintf(&redirect_key, "%s%s:80", "Redirect/", conn->host);
		//fprintf( logfile, "load_file: %s\n", redirect_key );
		forward_to = inisearch( redirect_key, NULL );
		free(redirect_key);
	}

	if (forward_to) {
		fprintf( logfile, "Redirect: '%s' '%s'\n", forward_to, decoded_url );
		redirect(conn, "%s%s", forward_to, decoded_url);
		return;
	}

	/* does it end in a slash? serve up url/index_name */
	slash_path = decoded_url[ conn->decoded_urllen - 1 ] == '/';
	//slash_path = decoded_url [strlen(decoded_url) - 1] == '/';

	if ( slash_path ) {

		if ( want_indexname ) {
			fprintf( logfile, "Index name %s %s\n", conn->host, wwwrealm );
			const char *domain = conn->host ? conn->host : wwwrealm;
			xasprintf(&redirect_key, "%s/index-name", domain );
			index_file = inisearch( redirect_key, index_name );
			free(redirect_key);
		}

		xasprintf(&target, "%s%s%s", pubroot, decoded_url, index_file);

		if (file_exists(target)) {
			mimetype = url_content_type( index_name, index_name_len, &conn->suffix );

		} else {
			free(target);

			if (!want_listing) {
				/* Return 404 instead of 403 to make --no-listing
				 * indistinguishable from the directory not existing.
				 * i.e.: Don't leak information.
				 */
				default_reply(conn, 404, "Not Found",
					  "The URL you requested (%s) was not found.", conn->url);
				return;
			}

			xasprintf(&target, "%s%s", pubroot, decoded_url);
			generate_dir_listing(conn, target);
			free(target);
			return;
		}
/*	} else if (strstr( decoded_url, ".acme.sh/" )) {
		rootdirlen = baserootlen;
		xasprintf(&target, "%s%s", baseroot, decoded_url);
		mimetype = url_content_type( decoded_url, conn->decoded_urllen, &conn->suffix );
*/

	} else {
		/* points to a file */
		xasprintf(&target, "%s%s", pubroot, decoded_url);
		//mimetype = url_content_type( decoded_url, strlen(decoded_url));
		mimetype = url_content_type( decoded_url, conn->decoded_urllen, &conn->suffix );
	}

	if ( want_throttling ) {

		xasprintf(&throttle, "%s%s", "Throttle/", mimetype);

		if ((blksize = inisearch( throttle, NULL ))) {

			assert( strlen(blksize) < 16 );

			if (strstr(mimetype, "video/")) {
				conn->reply_burst = video_burstsize;
			} else {
				conn->reply_burst = audio_burstsize;
			}

			if (want_throttling_in_msecs && (msecs = strchr( blksize, '/' ))) {

				conn->reply_msecs = atoi( msecs+1 );

				if (conn->reply_msecs < 10) {
					fprintf(
						errfile,
						"Milliseconds value too small for '%s'\n",
						mimetype
					);
					conn->reply_msecs = 100;
				}

				conn->reply_usecs = conn->reply_msecs * 1000;
				conn->reply_msecs /= 1000;

				strncpy( throttle, blksize, msecs-blksize );
				throttle[msecs-blksize] = '\0';

				conn->reply_blksz = atoi( throttle ) * 1024;
			}
			else {
				conn->reply_blksz = atoi( blksize ) * 1024;
			}

			kbps = conn->reply_blksz * 8;

			if ( want_throttling_in_msecs ) {
				kbps /= conn->reply_msecs;
			}

			fprintf(
				logfile,
				"Throttling '%s' at %.2f kbps [%d, %02f]\n",
				mimetype, kbps/1000, conn->reply_burst, conn->reply_msecs
			);

			if (kbps < 4096) {
				fprintf(
					errfile,
					"Throttle value too small for '%s' -- reset to %ld kbps\n",
					mimetype, (long) kbps
				);
			}
			//fflush( logfile );
		}
		free(throttle);
	}

	/* check if url was cached */
	rc = get_cached_url( conn, target+rootdirlen );

	if ( rc ) {
		conn->header_only = 0;
		free(target);
	}
	else {

		/* open file */
		conn->reply_fd = open(target, O_RDONLY|O_NONBLOCK );
		free(target);

		if (conn->reply_fd == -1) {

			/* open() failed */
			if (errno == EACCES) {
				default_reply(conn, 403, "Forbidden",
					"You don't have permission to access (%s).", conn->url);
			}
			else if (errno == ENOENT) {
				default_reply(conn, 404, "Not Found",
					"The URL you requested (%s) was not found.", conn->url);
			}
			else {
				default_reply(conn, 500, "Internal Server Error",
					"The URL you requested (%s) cannot be returned: %s.",
				conn->url, strerror(errno));
			}

			return;
		}

		/* stat the file */
		if (fstat(conn->reply_fd, &filestat) == -1) {
			default_reply(conn, 500, "Internal Server Error",
				"fstat() failed: %s.", strerror(errno));
			return;
		}

		/* make sure it's a regular file */
		if (S_ISDIR(filestat.st_mode)) {
			redirect(conn, "%s/", conn->url);
			return;
		}

		if (!S_ISREG(filestat.st_mode)) {
			default_reply(conn, 403, "Forbidden", "Not a regular file.");
			return;
		}

		conn->content_len = filestat.st_size;
		conn->payload_size = filestat.st_size;
		conn->payload_lastmod = filestat.st_mtime;
		conn->reply_type = REPLY_FROMFILE;
	}

	rfc1123_date(lastmod, conn->payload_lastmod);

	/* check for If-Modified-Since, may not have to send */
	if_mod_since = hdrsearch( conn, "If-Modified-Since" );

	if (if_mod_since != NULL && !strcmp(if_mod_since, lastmod)) {

		conn->http_code = 304;
		conn->header_length = xasprintf(&(conn->header),
			"HTTP/1.1 304 Not Modified\r\n"
			"Date: %s\r\n"
			"%s" /* server */
			"Accept-Ranges: bytes\r\n"
			"%s" /* keep-alive */
			"\r\n",
			rfc1123_date(date, now), server_hdr, keep_alive(conn));

		if (conn->reply_type == REPLY_CACHED) {
			fprintf( logfile, "ASSSERT REPLY_CACHED\n" );
			conn->reply = NULL;
		}

		conn->reply_length = 0;
		conn->reply_type = REPLY_GENERATED;
		conn->header_only = 1;

		return;
	}

	if (conn->range_begin_given || conn->range_end_given) {
		off_t from, to;

		if (conn->range_begin_given && conn->range_end_given) {
			/* 100-200 */
			from = conn->range_begin;
			to = conn->range_end;

			/* clamp end to filestat.st_size-1 */
			if (to > (conn->payload_size - 1))
			{ to = conn->payload_size - 1; }
		}
		else if (conn->range_begin_given && !conn->range_end_given) {
			/* 100- :: yields 100 to end */
			from = conn->range_begin;
			to = conn->payload_size - 1;
		}
		else if (!conn->range_begin_given && conn->range_end_given) {
			/* -200 :: yields last 200 */
			to = conn->payload_size - 1;
			from = to - conn->range_end + 1;

			/* clamp start */
			if (from < 0) {
				from = 0;
			}
		} else {
			errx(1, "internal error - from/to mismatch");
		}

		if (from >= conn->payload_size) {
			default_reply(conn, 416, "Requested Range Not Satisfiable",
				"You requested a range outside of the file.");
			return;
		}

		if (to < from) {
			default_reply(conn, 416, "Requested Range Not Satisfiable",
				"You requested a backward range.");
			return;
		}

		conn->reply_start = from;
		conn->reply_length = to - from + 1;
		conn->header_length = xasprintf(&(conn->header),
			"HTTP/1.1 206 Partial Content\r\n"
			"Date: %s\r\n"
			"%s" /* server */
			"Accept-Ranges: bytes\r\n"
			"%s" /* keep-alive */
			"Content-Length: %llu\r\n"
			"Content-Range: bytes %llu-%llu/%llu\r\n"
			"Content-Type: %s\r\n"
			"Last-Modified: %s\r\n"
			"\r\n"
			,
			rfc1123_date(date, now), server_hdr, keep_alive(conn),
			llu(conn->reply_length), llu(from), llu(to),
			llu(conn->payload_size), mimetype, lastmod
		);

		conn->http_code = 206;

		DBG_2( "sending %llu-%llu/%llu\n", llu(from), llu(to), llu(conn->payload_size));
	} else {
		/* no range stuff */
		conn->reply_length = conn->payload_size;
		conn->header_length = xasprintf(&(conn->header),
			"HTTP/1.1 200 OK\r\n"
			"Date: %s\r\n"
			"%s" /* server */
			"Accept-Ranges: bytes\r\n"
			"%s" /* keep-alive */
			"Content-Length: %llu\r\n"
			"Content-Type: %s\r\n"
			"Last-Modified: %s\r\n"
			"\r\n"
			,
			rfc1123_date(date, now), server_hdr, keep_alive(conn),
			llu(conn->reply_length), mimetype, lastmod
		);
		conn->http_code = 200;
	}
}

/* Process a POST request. */
//-----------------------------------------------------------------------------
static void process_post(struct connection* conn)
//-----------------------------------------------------------------------------
{
	static const char* const delims = "&";

	if (conn->content_len < MAX_POST_LENGTH) {

		conn->tuples_total = parse_tuples(
			conn, conn->tuples, conn->body, '=', delims, MAX_TUPLES
		);

		if (conn->tuples_total > 0) {

#ifdef ENABLE_GUESTBOOK
			if (fill_guestbook( conn )) {
				if ( guestbook_reply ) {
					free(conn->url);
					conn->url = xstrdup( guestbook_reply );

				} else if (strcmp( conn->url, "/" )) {
					//char *sptr = conn->url + strlen(conn->url);
					char *sptr = conn->url + conn->urllen;
					for (; *sptr-- != '/'; );
					(*++sptr) = '\0';
				}
				process_get( conn );

			} else {
				default_reply(conn, 500, "Internal Server Error",
					"Your request was dropped because of a server error.");
				conn->state = SEND_HEADER;
			}
#else
			default_reply(conn, 400, "Bad Request",
				"You sent a request that the server couldn't understand.");
			conn->state = SEND_HEADER;
#endif
		} else {
			default_reply(conn, 400, "Bad Request",
				"You sent a request that the server couldn't understand.");
			conn->state = SEND_HEADER;
		}
	} else {
		default_reply(conn, 413, "Request Entity Too Large",
			"Your request was dropped because it was too long.");
		conn->state = SEND_HEADER;
	}
}

#if 0
//-----------------------------------------------------------------------------
static int check_post_request(struct connection* conn)
//-----------------------------------------------------------------------------
{
	if (memcmp( conn->request, "POST ", 5 ) == 0) {

		if ((sptr = parse_field( conn, "Content-Length: " ))) {
			conn->content_len = atoi( sptr );
			free( sptr );
		}

		if (conn->content_len < 1) {
			default_reply(conn, 400, "Bad Request",
				"Your request is malformed: %s", conn->url);
			conn->state = SEND_HEADER;

		} else {
			if ((sptr = strstr( conn->request, "\n\n" ))) {
				recvd = (sptr - conn->request) + 2;
			} else if ((sptr = strstr( conn->request, "\r\n\r\n" ))) {
				recvd = (sptr - conn->request) + 4;
			}

			recvd = conn->request_length - recvd;

			DBG_2("request %d %d\n", recvd, conn->content_len);

			if (recvd == conn->content_len) {
				process_request(conn);
			} else {
				default_reply(conn, 400, "Bad Request",
					"You requested an invalid URL: %s", conn->url);
				conn->state = SEND_HEADER;
			}
		}
	}
}
#endif

/* Process a request: build the header and reply, advance state. */
//-----------------------------------------------------------------------------
static void process_request(struct connection* conn)
//-----------------------------------------------------------------------------
{
	num_requests++;

	//if (want_connect && want_connect_port == connect_port_is(conn)) {
	//}

	///if (!check_post_request(conn)) { return; }

	if (!parse_request(conn)) {
		default_reply(conn, 400, "Bad Request",
			"You sent a request that the server couldn't understand.");
		/* advance state */
		conn->state = SEND_HEADER;
		return;
	}

	conn->host = hdrsearch( conn, "Host" );

	/* work out path of file being requested */
	if (!decode_url( conn )) { return; }

	//if ( !conn->logged )
	//	log_connection( conn, 1 );

#ifdef ENABLE_PASSWORD
	if (use_password && !parse_auth(conn)) {
		conn->state = SEND_HEADER;
		return;
	}
#endif

	if (strcmp(conn->method, "GET") == 0) {
		process_get(conn);

	} else if (strcmp(conn->method, "HEAD") == 0) {
		process_get(conn);
		conn->header_only = 1;

	} else if (strcmp(conn->method, "POST") == 0) {
		process_post(conn);

	 } else if ((strcmp(conn->method, "OPTIONS") == 0) ||
		(strcmp(conn->method, "TRACE") == 0) ||
		(strcmp(conn->method, "PUT") == 0) ||
		(strcmp(conn->method, "DELETE") == 0) ||
		(strcmp(conn->method, "CONNECT") == 0))
	{
		default_reply(conn, 501, "Not Implemented",
			"The method you specified (%s) is not implemented.",
			conn->method);
	}
	else {
		default_reply(conn, 400, "Bad Request",
			"%s is not a valid HTTP/1.1 method.", conn->method);
	}

	/* advance state */
	conn->state = SEND_HEADER;
}

#ifdef ENABLE_PROXY
//----------------------------------------------------------------------------
static int forward_request(struct connection* conn)
//-----------------------------------------------------------------------------
{
	char *buf = conn->request;
	size_t nbytes = conn->request_length;

	int nwritten = send( conn->passthru, buf, nbytes, 0 );
	if (nwritten >= nbytes) {
		conn->state = FORWARD_REPLY;
		return nwritten;
	}

	if (nwritten > 0) {
		struct data_bucket *bucket = xmalloc(sizeof(struct data_bucket));
		bucket->value = xstrduplen( conn->request, conn->request_length );
		bucket->size = conn->request_length;
		bucket->written = nwritten;
		bucket->key = NULL;
		bucket->next = NULL;

		num_buckets++;

		if (conn->buckets.head) {
			conn->buckets.tail->next = bucket;
			conn->buckets.tail = bucket;
		} else {
			conn->buckets.head = bucket;
			conn->buckets.tail = bucket;
		}
		conn->state = FORWARD_REPLY;
	}

	return nwritten;
}

//----------------------------------------------------------------------------
static void forward_queued_request(struct connection* conn)
//-----------------------------------------------------------------------------
{
	//struct data_bucket *bucket = conn->buckets.tqh_first;
	struct data_bucket *bucket = conn->buckets.head;

	num_buckets--;

	DBG("FORWARD_REQUEST BUCKET=%d FD=%d\n", (unsigned int) bucket, conn->passthru);

	if ( bucket ) {
		size_t nbytes = bucket->size - bucket->written;
		char *buf = bucket->value + bucket->written;

		int written = send( conn->passthru, buf, nbytes, 0 );
		if (written > 0) {
			bucket->written += written;
		}

		conn->buckets.head = bucket->next;

		if (bucket->written >= bucket->size) {
			DBG("FORWARD_REQUEST %d FD=%d\n", written, conn->passthru);
			free(bucket->value);
			free(bucket);
		}

		conn->state = FORWARD_REPLY;
	}
}

//----------------------------------------------------------------------------
static void forward_reply(struct connection* conn)
//-----------------------------------------------------------------------------
{
	char buf[1 << 15];
	char *sptr = buf;
	ssize_t nbytes;
	ssize_t sent;

	errno = 0;
	nbytes = recv(conn->passthru, buf, sizeof(buf), 0);
	DBG("FORWARD_REPLY %d FD=%d\n", nbytes, conn->passthru);

	if (nbytes > 0) {
		ssize_t total = nbytes;

		for (; total > 0; ) {
#ifdef ENABLE_SSL
				if ( conn->ssl ) {
					 sent = ssl_send( conn, sptr, total );
				} else {
					 sent = send(conn->socket, sptr, total, 0 );
				}
#else
				sent = send(conn->socket, sptr, total, 0 );
#endif
				if (sent > 0) {
					 total -= sent;
					 sptr += sent;
				}
		  }
	 } else if (nbytes == -1) {
		if (errno != EAGAIN && errno != EINTR) {
			DBG("FORWARD_REPLY CLOSE FD=%d\n", conn->passthru);
			conn->state = DONE;
		}
	 } else {
		conn->state = DONE;
	 }
}
#endif

/* Receiving request. */
//-----------------------------------------------------------------------------
static void poll_recv_request(struct connection* conn)
//-----------------------------------------------------------------------------
{
	const char* forward_host = NULL;
	const char* forward_port = NULL;
	char *passthru_key = 0L;
	int have_full_request;
	char buf[1 << 15];
	char *fqdn = NULL;
	ssize_t recvd = -1;

	errno = 0;

	assert(conn->state == RECV_REQUEST);

#ifdef ENABLE_SSL
	if (conn->ssl) {
		recvd = ssl_recv( conn, buf, sizeof(buf) );
	} else {
		recvd = recv(conn->socket, buf, sizeof(buf), 0);
	}
#else
	recvd = recv(conn->socket, buf, sizeof(buf), 0);
#endif

	DBG_2("poll_recv_request(%d) got %d bytes\n", conn->socket, (int)recvd);

	if (recvd < 1) {
		if (recvd == -1) {
			if (errno == EAGAIN || errno == EINTR) {
				DBG_2("poll_recv_request would have blocked\n");
				return;
			}

			DBG_2("recv(%d) error: %s\n", conn->socket, strerror(errno));
		}

		if (conn->state != SSL_DONE) {
			conn->conn_close = 1;
			conn->state = DONE;
		}

		return;
	}

	update_clock( conn );

	/* append to conn->request */
	assert(recvd > 0);

	conn->request = xrealloc(
		conn->request, conn->request_length + (size_t)recvd + 1
	);

	memcpy(conn->request + conn->request_length, buf, (size_t)recvd);
	conn->request_length += (size_t)recvd;
	conn->request[conn->request_length] = 0;
	total_in += (size_t)recvd;

	/* process request if we have all of it */
	have_full_request = conn->request_length > 2 &&
		memcmp(conn->request + conn->request_length - 2, "\n\n", 2) == 0;

	have_full_request = have_full_request ||
		(conn->request_length > 4 &&
			memcmp(conn->request + conn->request_length - 4, "\r\n\r\n", 4) == 0);

	/* die if it's too large */
	if (conn->request_length > MAX_REQUEST_LENGTH) {
		default_reply(conn, 413, "Request Entity Too Large",
			"Your request was dropped because it was too long.");
		conn->state = SEND_HEADER;
	}

	if ( have_full_request ) {

#ifdef ENABLE_PROXY
		if (verify_request(conn)) {

			if ( want_proxy ) {
				if ((fqdn = parse_field( conn, "Host: " ))) {
					xasprintf(&passthru_key, "%s/ipv4-addr", fqdn );
					forward_host = inisearch( passthru_key, NULL );
					free(passthru_key);
				}
			}

		DBG("PROXY CONNECT %s ON %s FD %d\n", fqdn, forward_host, conn->passthru);

			if (want_proxy && forward_host) {

				if (conn->passthru > 0) {
					DBG("FORWARD CONNECT PASSTHRU ON FD %d\n", conn->passthru);
					if (forward_request(conn) < 0) {
						default_reply(conn, 500, "Internal Server Error",
							"Your request was dropped because of a server error.");
						conn->state = SEND_HEADER;
					}
				} else {
					xasprintf(&passthru_key, "%s/port", fqdn);
					forward_port = inisearch( passthru_key, NULL );
					free(passthru_key);

					int fd = connect_sockin( forward_host, forward_port );
					if (fd > 0) {
						conn->passthru = fd;
						DBG("CONNECT_SOCKIN ON FD %d\n", fd);

						if (forward_request(conn) < 0) {
							default_reply(conn, 500, "Internal Server Error",
								"Your request was dropped because of a server error.");
							conn->state = SEND_HEADER;
						}
					} else {
						default_reply(conn, 403, "Forbidden",
							"You sent a request that the server couldn't allow.");
						conn->state = SEND_HEADER;
					}
				}
			} else {
				process_request(conn);
			}
		} else {
			default_reply(
				conn, 400, "Bad Request",
				"You sent a request that the server couldn't understand."
			);
			conn->state = SEND_HEADER;
		}

		free( fqdn );
#else
		process_request(conn);
#endif
	}

	/* if we've moved on to the next state, try to send right away, instead of
	 * going through another iteration of the select() loop.
	 */
	if (conn->state == SEND_HEADER) {
		poll_send_header(conn);
	}
}

/* Sending header.  Assumes conn->header is not NULL. */
//-----------------------------------------------------------------------------
static void poll_send_header(struct connection* conn)
//-----------------------------------------------------------------------------
{
	assert(conn->state == SEND_HEADER);
	assert(conn->header_length == strlen(conn->header));

	char *buf = conn->header + conn->header_sent;
	ssize_t nbytes = conn->header_length - conn->header_sent;
	ssize_t sent;

#ifdef ENABLE_SSL
	if ( conn->ssl ) {
		sent = ssl_send( conn, buf, nbytes );
	} else {
		sent = send(conn->socket, buf, nbytes, 0 );
	}
#else
	sent = send(conn->socket, buf, nbytes, 0 );
#endif

	DBG_2( "poll_send_header(%d) sent %d bytes (buffer %d bytes)\n", conn->socket, (int)sent, nbytes);

	/* handle any errors (-1) or closure (0) in send() */
	if (sent < 1) {
		if (sent == -1) {
			if (errno == EAGAIN || errno == EINTR) {
				DBG_2("poll_send_header would have blocked\n");
				return;
			}

			DBG_2("send(%d) error: %s\n", conn->socket, strerror(errno));
		}

		if (conn->state != SSL_DONE) {
			conn->conn_close = 1;
			conn->state = DONE;
		}

		return;
	}

	update_clock( conn );

	assert(sent > 0);
	conn->header_sent += (size_t)sent;
	conn->total_sent += (size_t)sent;
	total_out += (size_t)sent;

	/* check if we're done sending header */
	if (conn->header_sent == conn->header_length) {
		if (conn->header_only) {
			conn->state = DONE;
		} else {
			conn->state = SEND_REPLY;
			/* go straight on to body, don't go through another iteration of
			 * the select() loop.
			 */
			poll_send_reply(conn);
		}
	}
}

//-----------------------------------------------------------------------------
static ssize_t fake_send_from_file(struct connection* conn, size_t nbytes)
//-----------------------------------------------------------------------------
{
	const int s = conn->socket;
	const int fd = conn->reply_fd;
	off_t ofs = conn->reply_start + conn->reply_sent;
	//(size_t)(conn->reply_length - conn->reply_sent));

#ifndef min
#  define min(a,b) ( ((a)<(b)) ? (a) : (b) )
#endif
	char buf[1 << 15];
	size_t amount = min(sizeof(buf), nbytes);
	ssize_t numread;

	if (lseek(fd, ofs, SEEK_SET) == -1)
		err(1, "fseek(%d)", (int)ofs);

	numread = read( fd, buf, amount );

	if (numread == 0) {
		warn("premature eof on fd %d", fd);
		return -1;
	}

	if (numread == -1) {
		warn("error reading on fd %d: %s", fd, strerror(errno));
		return -1;
	}

	if ((size_t)numread != amount) {
		warn("read %zd bytes, expecting %zu bytes on fd %d", numread, amount, fd);
		return -1;
	}

#ifdef ENABLE_SSL
	if ( conn->ssl )
		return ssl_send(conn, buf, amount);

	return send(s, buf, amount, 0);
#else
	//fprintf(logfile, "read %zd bytes, expecting %zu bytes on fd %d\n", numread, amount, fd);
	return send(s, buf, amount, 0);
#endif
}

/* Send chunk on socket <s> from FILE *fp, starting at <ofs> and of size
 * <size>.  Use sendfile() if possible since it's zero-copy on some platforms.
 * Returns the number of bytes sent, 0 on closure, -1 if send() failed, -2 if
 * read error.
 */

//-----------------------------------------------------------------------------
static ssize_t send_from_file(struct connection* conn, size_t nbytes)
//-----------------------------------------------------------------------------
{
	const int s = conn->socket;
	const int fd = conn->reply_fd;
	off_t ofs = conn->reply_start + conn->reply_sent;

	/* Limit truly ridiculous (LARGEFILE) requests. */
	if (nbytes > (1 << 23)) { nbytes = 1 << 20; }

#ifdef __FreeBSD__
	off_t sent = 0;
	int ret = sendfile(fd, s, ofs, nbytes, NULL, &sent, 0);

	/* It is possible for sendfile to send zero bytes due to a blocking
	 * condition.  Handle this correctly.
	 */
	if (ret == -1) {
		//if (errno == EAGAIN) {
		if (errno == EAGAIN || errno == EINTR) {
			if (sent == 0) { return -1; } else { return sent; }
		} else {
			return -1;
		}
	} else {
		return nbytes;
	}

#elif defined(__linux) || defined(__sun__)
	//fprintf(logfile, "Expecting %zu bytes on fd %d\n", nbytes, fd);
	//fflush(logfile);
#ifdef ENABLE_SSL
	if ( conn->ssl )
		return fake_send_from_file( conn, nbytes );

	return sendfile(s, fd, &ofs, nbytes);
#else
	return sendfile(s, fd, &ofs, nbytes);
#endif
#else
	/* Fake sendfile() with read(). */
	return fake_send_from_file( conn, nbytes );
#endif
}

/* Sending reply. */
//-----------------------------------------------------------------------------
static void poll_send_reply(struct connection* conn)
//-----------------------------------------------------------------------------
{
	size_t nbytes = (size_t)(conn->reply_length - conn->reply_sent);
	ssize_t sent;

	assert(conn->state == SEND_REPLY);
	assert(!conn->header_only);

	errno = 0;
	assert(conn->reply_length >= conn->reply_sent);

	if (conn->reply_type == REPLY_CACHED ||
		//conn->reply_type == REPLY_REDIRECT ||
		conn->reply_type == REPLY_GENERATED)
	{
		char *buf = conn->reply + conn->reply_start + conn->reply_sent;

#ifdef ENABLE_SSL
		if ( conn->ssl ) {
			sent = ssl_send( conn, buf, nbytes );
		} else {
			sent = send( conn->socket, buf, nbytes, 0 );
		}
#else
		sent = send( conn->socket, buf, nbytes, 0 );
#endif
	} else {
		if (conn->reply_blksz > 0) {
			if (conn->reply_blksz < nbytes)
				nbytes = conn->reply_blksz;

			if (conn->reply_sent < 1 && conn->reply_length > conn->reply_burst) {
				nbytes = conn->reply_burst;
			}
		}

		sent = send_from_file( conn, nbytes );

		if (debug && (sent < 1)) {
			fprintf( logfile, "send_from_file returned %lld (errno=%d %s)\n",
				(long long)sent, errno, strerror(errno));
		}
	}

	DBG_2("poll_send_reply(%d) sent %d: %llu+[%llu-%llu] of %llu\n", conn->socket, (int)sent, llu(conn->reply_start), llu(conn->reply_sent), llu(conn->reply_sent + sent - 1), llu(conn->reply_length));

	/* handle any errors (-1) or closure (0) in send() */
	if (sent < 1) {
		if (sent == -1) {
			if (errno == EAGAIN || errno == EINTR) {
				DBG_2("poll_send_reply would have blocked\n");
				return;
			}

			DBG_2("send(%d) error: %s\n", conn->socket, strerror(errno));

		} else if (sent == 0) {
			DBG_2("send(%d) closure\n", conn->socket);
		}

		if (conn->state != SSL_DONE) {
			conn->conn_close = 1;
			conn->state = DONE;
		}

		return;
	}

	update_clock( conn );

	conn->reply_sent += sent;
	conn->total_sent += (size_t)sent;
	total_out += (size_t)sent;

	DBG("poll_send_reply SENT=%d %lld\n", sent, conn->total_sent);

	/* check if we're done sending */
	if (conn->reply_sent == conn->reply_length) {
		//if (conn->reply_type == REPLY_REDIRECT)
		conn->state = DONE;
	}
}

/* Main loop of the httpd - a select() and then delegation to accept
 * connections, handle receiving of requests, and sending of replies.
 */
//-----------------------------------------------------------------------------
static void httpd_poll(void)
//-----------------------------------------------------------------------------
{
	fd_set recv_set, send_set;
	struct connection *conn;
	struct connection *next;
	int bother_with_timeout = 0;
	int retcode, max_fd=0;
	int nb_buckets = 0;
	int64_t delay = 0;
	time_t elapsed;

	timeout.tv_sec = idletime;
	timeout.tv_usec = 0;

	FD_ZERO(&recv_set);
	FD_ZERO(&send_set);

/* set recv/send fd_sets */
#define MAX_FD_SET(sock, fdset) \
	{\
		FD_SET(sock,fdset);\
		max_fd = (sock>max_fd) ? sock : max_fd;\
	}

	MAX_FD_SET(sockin, &recv_set);

	if (sockin_ssl > 0) {
		MAX_FD_SET(sockin_ssl, &recv_set);
	}

	/*
	gettimeofday( &chrono, 0L );
	elapsed = chrono.tv_sec - now;
	now = chrono.tv_sec;
	*/

	elapsed = now - lasttime;
	lasttime = now;

	LIST_FOREACH_SAFE(conn, &connlist, entries, next) {

		DBG("httpd_poll 1 LIST_FOREACH_SAFE FD=%d STATE=%d\n", conn->socket, conn->state);

		if (elapsed > 2) { poll_check_timeout(conn); }

		switch (conn->state) {
#ifdef ENABLE_SSL
		case SSL_ACCEPT:
			bother_with_timeout = 1;

			if (ssl_handshake(conn) > 0) {
                poll_recv_request(conn);
				MAX_FD_SET(conn->socket, &recv_set);
            } else if (conn->state == SSL_DONE) {
			    ssl_shutdown(conn);
			} else {
				timeout.tv_sec = 0;
				timeout.tv_usec = 100000;
			}
			break;

		case SSL_DONE:
			bother_with_timeout = 1;

			if (ssl_shutdown(conn) < 1) {
				timeout.tv_sec = 0;
				timeout.tv_usec = 100000;
			}
			break;
#endif

#ifdef ENABLE_PROXY
		case FORWARD_REQUEST:
		case FORWARD_REPLY:
			nb_buckets = 1;
			bother_with_timeout = 1;
			MAX_FD_SET(conn->passthru, &recv_set);
			MAX_FD_SET(conn->socket, &recv_set);
			break;
#endif

		case RECV_REQUEST:
			bother_with_timeout = 1;
			MAX_FD_SET(conn->socket, &recv_set);
#if 0
			if ( conn->ssl ) {
				//delay = s2n_connection_get_delay(conn->ssl) / 1000;
			}
#endif
			break;

		case SEND_REPLY:
			nb_buckets = 1;

		case SEND_HEADER:
			bother_with_timeout = 1;
			MAX_FD_SET(conn->socket, &send_set);
#if 0
			if ( conn->ssl ) {
				//delay = s2n_connection_get_delay(conn->ssl) / 1000;
			}
#endif
			break;

		case DONE:
		default:
			/* do nothing */
			break;
		}
	}

	//if (num_connections > 0 || nb_buckets > 0) {
	if (nb_buckets > 0) {
		bother_with_timeout = 1;
		timeout.tv_sec = nb_buckets > 0 ? 0 : 1;
		timeout.tv_usec = nb_buckets > 0 ? 100000 : 0;
	}

	if (timeout.tv_sec != 1 && timeout.tv_sec != 0 && timeout.tv_sec != idletime) {
		fprintf(errfile,"ASSERT: select() CONN#%d WAIT=[%ld,%ld]\n",
			num_connections, timeout.tv_sec, timeout.tv_usec);
		timeout.tv_sec = 1; timeout.tv_usec = 0;
	}

	errno = 0;

	DBG("SELECT() CONN#%d MAX-FD=%d BUCKETS=%d WAIT=[%ld,%ld]\n",
		num_connections, max_fd, nb_buckets, timeout.tv_sec, timeout.tv_usec);

	DBG_FLUSH();

	retcode = select(max_fd + 1, &recv_set, &send_set, NULL,
		(bother_with_timeout) ? &timeout : NULL);

	DBG("SELECT() RC=%d CONN#%d MAX-FD=%d BUCKETS=%d WAIT=[%ld,%ld]\n",
		retcode, num_connections, max_fd, nb_buckets, timeout.tv_sec, timeout.tv_usec);

	if ( !want_proxy || nb_buckets < 1) {

		  if (retcode == 0) {
				if (!bother_with_timeout) { err(1, "select() timed out"); }
				DBG("httpd_poll RETCODE==0 EXITING -------------------------------------------\n");
				DBG_FLUSH();
				return;
		  }

		  if (retcode == -1) {
				if (errno != EINTR) { err(1, "select() failed"); }
				DBG("httpd_poll RETCODE==-1 EXITING -------------------------------------------\n");
				DBG_FLUSH();
				return; /* interrupted by signal */
		  }
	 }

	gettimeofday( &chrono, 0L );

	now = chrono.tv_sec;

	/* poll connections that select() says need attention */
	if (FD_ISSET(sockin, &recv_set)) {
		DBG( "TRY accept_connection %d\n", sockin );
		accept_connection( 0 );
	}

	if (sockin_ssl > 0 && FD_ISSET(sockin_ssl, &recv_set)) {
		DBG( "TRY accept_connection SSL %d\n", sockin_ssl );
		accept_connection(1);
	}

	LIST_FOREACH_SAFE(conn, &connlist, entries, next) {

		DBG("httpd_poll 2 LIST_FOREACH_SAFE FD=%d STATE=%d\n", conn->socket, conn->state);

		switch (conn->state) {
#ifdef ENABLE_SSL
		case SSL_ACCEPT:
			ssl_handshake(conn);
			break;

		case SSL_DONE:
			ssl_shutdown(conn);
			break;
#endif

#ifdef ENABLE_PROXY
		case FORWARD_REQUEST:
			forward_queued_request(conn);
			break;

		case FORWARD_REPLY:
			if (FD_ISSET(conn->passthru, &recv_set))
				forward_reply(conn);
#endif

		case RECV_REQUEST:
			if (FD_ISSET(conn->socket, &recv_set)) {
				conn->state = RECV_REQUEST;
				poll_recv_request(conn);
			}
			break;

		case SEND_HEADER:
			if (FD_ISSET(conn->socket, &send_set))
				poll_send_header(conn);
			break;

		case SEND_REPLY:
			if (FD_ISSET(conn->socket, &send_set))
			{
				if ( !want_throttling || conn->reply_blksz < 1) {
					poll_send_reply(conn);
				} else if ( want_throttling_in_msecs ) {
					if (TIMERCMP( chrono, conn->chrono ) > 0) {
						poll_send_reply(conn);
					}
				} else if (now > conn->lasttime) {
					poll_send_reply(conn);
				}
			}
			break;

		case DONE:
		default:
			/* (handled later; ignore for now as it's a valid state) */
			break;
		}

		if (conn->state == DONE) {

			/* clean out finished connection */
			if (conn->conn_close) {

				LIST_REMOVE(conn, entries);
				release_resources(conn);
				/*
				if (num_freeconnections < 1000) {
					LIST_INSERT_HEAD(&freeconnlist, conn, entries);
					recycle_connection(conn);
					num_freeconnections += 1;
				} else {
					release_resources(conn);
				}
				*/
			} else {
				recycle_connection(conn);
				// Go right back to recv_request without going through select() again.
				poll_recv_request(conn);
			}
		}
	}
	DBG("httpd_poll EXITING -------------------------------------------\n");
	DBG_FLUSH();
#undef MAX_FD_SET
}

/* Daemonize helpers. */
static int lifeline[2] = { -1, -1 };
static int fd_null = -1;

//-----------------------------------------------------------------------------
static void daemonize_start(void)
//-----------------------------------------------------------------------------
{
	pid_t f;

	if (pipe(lifeline) == -1)
	{ err(1, "pipe(lifeline)"); }

	fd_null = open( "/dev/null", O_RDWR, 0);

	if (fd_null == -1)
	{ err(1, "open(\"/dev/null\")"); }

	f = fork();

	if (f == -1) {
		err(1, "fork");
	}
	else if (f != 0) {
		/* parent: wait for child */
		char tmp[1];
		int status;
		pid_t w;

		if (close(lifeline[1]) == -1)
		{ warn("close lifeline in parent"); }

		if (read(lifeline[0], tmp, sizeof(tmp)) == -1)
		{ warn("read lifeline in parent"); }

		w = waitpid(f, &status, WNOHANG);

		if (w == -1) { err(1, "waitpid"); }
		else if (w == 0)
		/* child is running happily */
		{ exit(EXIT_SUCCESS); }
		else
		/* child init failed, pass on its exit status */
		{ exit(WEXITSTATUS(status)); }
	}

	/* else we are the child: continue initializing */
}

//-----------------------------------------------------------------------------
static void daemonize_finish(void)
//-----------------------------------------------------------------------------
{
	if (fd_null == -1)
	{ return; } /* didn't daemonize_start() so we're not daemonizing */

	if (setsid() == -1)
	{ err(1, "setsid"); }

	if (close(lifeline[0]) == -1)
	{ warn("close read end of lifeline in child"); }

	if (close(lifeline[1]) == -1)
	{ warn("couldn't cut the lifeline"); }

	/* close all our std fds */
	if (dup2(fd_null, STDIN_FILENO) == -1)
	{ warn("dup2(stdin)"); }

	if (dup2(fd_null, STDOUT_FILENO) == -1)
	{ warn("dup2(stdout)"); }

	if (dup2(fd_null, STDERR_FILENO) == -1)
	{ warn("dup2(stderr)"); }

	if (fd_null > 2)
	{ close(fd_null); }
}

#ifdef ENABLE_PIDFILE
/* [->] pidfile helpers, based on FreeBSD src/lib/libutil/pidfile.c,v 1.3
 * Original was copyright (c) 2005 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 */
//-----------------------------------------------------------------------------
static int pidfile_fd = -1;
//-----------------------------------------------------------------------------

static void pidfile_remove(void)
//-----------------------------------------------------------------------------
{
	if (unlink(pidfile_name) == -1) {
		err(1, "unlink(pidfile) failed");
	}

	/* if (flock(pidfile_fd, LOCK_UN) == -1)
			err(1, "unlock(pidfile) failed"); */
	xclose(pidfile_fd);
	pidfile_fd = -1;
}

//-----------------------------------------------------------------------------
static int pidfile_read(void)
//-----------------------------------------------------------------------------
{
	char buf[16];
	long long pid;
	int fd, i;

	fd = open(pidfile_name, O_RDONLY);

	if (fd == -1)
		err(1, "Failed to open PID file");

	i = (int)read(fd, buf, sizeof(buf) - 1);

	if (i == -1)
		err(1, "Failed to read from PID file");

	xclose(fd);

	buf[i] = '\0';

	if (!str_to_num(buf, &pid)) {
		err(1, "invalid pidfile contents: \"%s\"", buf);
	}

	return (int)pid;
}

//-----------------------------------------------------------------------------
static void pidfile_create(void)
//-----------------------------------------------------------------------------
{
	int error, fd;
	char pidstr[16];

	/* Open the PID file and obtain exclusive lock. */
	fd = open(pidfile_name,
		 O_WRONLY | O_CREAT | O_EXLOCK | O_TRUNC | O_NONBLOCK, 0600);

	if (fd == -1) {
		if ((errno == EWOULDBLOCK) || (errno == EEXIST))
		{ errx(1, "daemon already running with PID %d", pidfile_read()); }
		else
		{ err(1, "can't create pidfile %s", pidfile_name); }
	}

	pidfile_fd = fd;

	if (ftruncate(fd, 0) == -1) {
		error = errno;
		pidfile_remove();
		errno = error;
		err(1, "ftruncate() failed");
	}

	snprintf(pidstr, sizeof(pidstr), "%d", (int)getpid());

	if (pwrite(fd, pidstr, strlen(pidstr), 0) != (ssize_t)strlen(pidstr)) {
		error = errno;
		pidfile_remove();
		errno = error;
		err(1, "pwrite() failed");
	}
}
/* [<-] end of pidfile helpers. */
#endif

/* Close all sockets and FILEs and exit. */
//-----------------------------------------------------------------------------
static void stop_running(int sig unused)
//-----------------------------------------------------------------------------
{
	running = 0;
}

//-----------------------------------------------------------------------------
static uid_t get_dropto_uid(const char* name)
//-----------------------------------------------------------------------------
{
	struct passwd* p = getpwnam(name);

	if (p) { return p->pw_uid; }

	p = getpwuid((uid_t)xstr_to_num(name));

	if (p) { return p->pw_uid; }

	errx(1, "no such uid: `%s'", name);

	return 0;
}

//-----------------------------------------------------------------------------
static gid_t get_dropto_gid(const char* name)
//-----------------------------------------------------------------------------
{
	struct group* g = getgrnam(name);

	if (g) { return g->gr_gid; }

	g = getgrgid((gid_t)xstr_to_num(name));

	if (g) { return g->gr_gid; }

	errx(1, "no such gid: `%s'", name);

	return 0;
}

//-----------------------------------------------------------------------------
static int check_folder(char *folder)
//-----------------------------------------------------------------------------
{
	int len = 0;

	if (!strcmp(folder, "/") || !dir_exists(folder))
		errx(1, "Invalid %s rootdir specified !", folder );

	/* Strip ending slash. */
	if ((len = strlen(folder)) > 0) {
		if (folder[len-1] == '/') {
			folder[len-1] = '\0';
		}
	}

	return strlen(folder);
}

//-----------------------------------------------------------------------------
static void parse_commandline(const int argc, char* argv[])
//-----------------------------------------------------------------------------
{
	const char *cfgfile = config_file;
	const char *host = NULL;
	const char *url = NULL;
	char *rootdir = NULL;
	char *value = NULL;
	int len= 0, i = 0;
	int no_daemon = 0;
	int optidx = 1;

	memset( mimetypes, 0, sizeof(mimetypes) );

#ifdef ENABLE_PASSWORD
	memset( passwords, 0, sizeof(passwords) );
#endif

	for (i = optidx; i < argc; i++) {

		if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config")) {
			if ((cfgfile = argv[++i]) == NULL) { 
				errx(1, "Invalid settings file" );
			}
		} else if (strcmp(argv[i], "--no-log") == 0) {
			no_daemon = 1;
			want_logging = 0;
			errfile = stderr;
			logfile = stdout;

		} else if (strcmp(argv[i], "--no-daemon") == 0) {
			no_daemon = 1;
			want_daemon = 0;

		} else if (strcmp(argv[i], "--accf") == 0) {
			want_accf = 1;

		} else {
			errx(1, "unknown argument `%s'", argv[i]);
		}
	}

	inifile_total = load_cfgfile( cfgfile, &inibuf, inifile, MAX_TUPLES );

	if (inifile_total < 1) {
		errx(1, "Invalid ini settings file" );
	}

	wwwrealm = inisearch( "General/realm", "dawnhttpd.io" );
	wwwrealm = xstrdup(wwwrealm);

	baseroot = xstrdup( inisearch( "General/baseroot", "/var/www" ));
	baserootlen = check_folder( baseroot );

	pubroot = xstrdup( inisearch( "General/root", "/var/www/public_html" ));
	pubrootlen = check_folder( pubroot );

#ifdef ENABLE_SLOCATE
	if ((want_slocate = ini_evaluate( "Locate/enabled", "yes", NULL ))) {

		locate_maxhits = inisearch( "Locate/maxhits", "1000" );

		if ((value = inisearch( "Locate/path", NULL )))
			locate_dbpath = xstrdup( value );

		if ( locate_maxhits ) {
			int max = atoi(locate_maxhits);
			if (max < 25 || max > 2500) {
				errx(1, "Invalid maxhits (must be >25 and <2500");
			}
		}

		if ( !locate_dbpath ) {
			errx(1, "No valid Gnu locate database specified!");
		}
	}
#endif

	value = inisearch( "General/port", "80" );
	bindport = (int)xstr_to_num( value );

	value = inisearch( "SSL/port", "443" );
	bindport_ssl = (int)xstr_to_num( value );

	if (ini_evaluate( "General/ipv4", "yes", "yes" )) {
		bindaddr = inisearch( "General/ipv4-addr", "127.0.0.1" );
#ifdef ENABLE_INET6
		errx("\t(This binary was built without IPv4 support)\n");
#endif
	} else {
		bindaddr = inisearch( "General/ipv6-addr", "::1" );
#ifndef ENABLE_INET6
		errx("\t(This binary was built without IPv6 support)\n");
#endif
	}

	value = inisearch( "Connection/max-requests", "256" );
	max_connections = (int)xstr_to_num(value);

	value = inisearch( "Connection/timeout", "15" );
	idletime = (int)xstr_to_num(value);
	idletime = idletime > 60 ? 60 : idletime;
	idletime = idletime < 15 ? 15 : idletime;

	want_ssl = ini_evaluate( "SSL/enabled", "yes", NULL );
	want_drop = ini_evaluate( "Dropto/enabled", "yes", NULL );
	want_cache = ini_evaluate( "Static/enabled", "yes", NULL );
	want_chroot = ini_evaluate( "Chroot/enabled", "yes", NULL );
	want_pidfile = ini_evaluate( "Pidfile/enabled", "yes", NULL );

	if ( !no_daemon ) {
		want_daemon = ini_evaluate( "General/daemon", "yes", NULL );
	}

	want_server_id = ini_evaluate( "General/server-id", "yes", NULL );
	want_listing = ini_evaluate( "Directory/index", "yes", NULL );

	value = inisearch( "Directory/index-name", "index.html" );
	index_name = xstrdup(value);
	index_name_len = strlen( index_name );

	want_redirect = ini_evaluate( "Redirect/enabled", "yes", NULL );

	want_throttling = ini_evaluate( "Throttle/enabled", "yes", NULL );
	want_throttling_in_msecs = ini_evaluate( "Throttle/millisecs", "yes", NULL );

	value = inisearch( "Throttle/audio-burst", "1024" );
	audio_burstsize = (int)xstr_to_num( value ) * 1024;

	value = inisearch( "Throttle/video-burst", "2048" );
	video_burstsize = (int)xstr_to_num( value ) * 1024;

	if (audio_burstsize < 1024 || audio_burstsize < 8192)
		errx(1, "Invalid audio burst size");

	if (video_burstsize < 1024 || video_burstsize < 8192)
		errx(1, "Invalid video burst size");

#ifdef ENABLE_PASSWORD
	if ((use_password = ini_evaluate( "Password/enabled", "yes", NULL ))) {
        password_file = inisearch( "Password/filename", NULL );

        if ((password_salt = inisearch( "Password/salt", NULL )))
            password_saltlen = strlen( password_salt );

        if (use_password && !password_salt)
            errx(1, "Password salt missing");
    }
#endif

	if ( want_drop ) {
		if ((value = inisearch( "Dropto/user", "dawnhttpd" )))
			drop_uid = get_dropto_uid( value );

		if ((value = inisearch( "Dropto/group", "daemon" )))
			drop_gid = get_dropto_gid( value );
	}

	mimefile_name = inisearch( "General/mimetypes", NULL );

	if ( mimefile_name ) {
		mimetypes_total = load_cfgfile( mimefile_name, &mimebuf, mimetypes, MAX_TUPLES );
		if (!mimetypes_total) {
			errx(1, "Invalid mimetype file");
		}
	}

#ifdef ENABLE_PASSWORD
	if ( password_file ) {
		passwords_total = load_cfgfile( password_file, &passwdbuf, passwords, MAX_TUPLES );

		if (passwords_total < 1) {
			errx(1, "Invalid password file");
		}
	}
#endif
}

//-----------------------------------------------------------------------------
static void drop_privileges()
//-----------------------------------------------------------------------------
{
	if (drop_gid != INVALID_GID) {
		gid_t list[1];
		list[0] = drop_gid;

		if (setgroups(1, list) == -1)
		{ err(1, "setgroups([%d])", (int)drop_gid); }

		if (setgid(drop_gid) == -1)
		{ err(1, "setgid(%d)", (int)drop_gid); }
	}

	if (drop_uid != INVALID_UID) {
		if (setuid(drop_uid) == -1)
		{ err(1, "setuid(%d)", (int)drop_uid); }
	}
}

//-----------------------------------------------------------------------------
static void init_pidfile()
//-----------------------------------------------------------------------------
{
#ifdef ENABLE_PIDFILE
	if (ini_evaluate( "pidfile", "yes", NULL )) {

		if (want_chroot) {
			xasprintf( &pidfile_name, "%s/run/dawnhttpd.pid", baseroot);
		} else {
			pidfile_name = xstrdup( "/var/run/dawnhttpd.pid" );
		}

		pidfile_create();
#endif
}

//-----------------------------------------------------------------------------
static void remove_pidfile()
//-----------------------------------------------------------------------------
{
#ifdef ENABLE_PIDFILE
	if (pidfile_name != NULL) {
		pidfile_remove();
		free(pidfile_name);
	}
#endif
}

//-----------------------------------------------------------------------------
static void stop_logging()
//-----------------------------------------------------------------------------
{
	if (logfile != NULL && logfile != stdin) {
		fflush(logfile);
		fclose(logfile);
		logfile = NULL;
	}

	if (errfile != NULL && errfile != stdin) {
		fflush(errfile);
		fclose(errfile);
		errfile = NULL;
	}
}

#ifdef ENABLE_SLOCATE
//-----------------------------------------------------------------------------
static void init_locate()
//-----------------------------------------------------------------------------
{
	struct stat buf;
	char *value;

	if (want_chroot) {
		xasprintf( &value, "%s%s", baseroot, locate_dbpath);
		free(locate_dbpath); locate_dbpath = value;
	}

	if (stat( locate_dbpath, &buf ) < 0) {
		errx(1, "No such file (%s) -- %s", locate_dbpath, strerror(errno));
	}
}
#endif

//-----------------------------------------------------------------------------
static void init_logging()
//-----------------------------------------------------------------------------
{
	char* logfile_name = NULL;
	char* errfile_name = NULL;
	char *value;

	stop_logging();

	if (want_chroot) {
		xasprintf( &logfile_name, "%s/log/dawnhttpd/access.log", baseroot);
		xasprintf( &errfile_name, "%s/log/dawnhttpd/errors.log", baseroot);
	} else {
		logfile_name = xstrdup( "/var/log/dawnhttpd/access.log" );
		errfile_name = xstrdup( "/var/log/dawnhttpd/errors.log" );
	}

	logfile = fopen( logfile_name, "ab+" );

	if (logfile == NULL) {
		errx(1, "No such file (%s) -- %s", logfile_name, strerror(errno));
	}

	fprintf( logfile, "\n%s, %s.\n", pkgname, copyright );
	fprintf( logfile, "Using baseroot '%s'\n", baseroot );
	fprintf( logfile, "Using wwwroot '%s'\n", pubroot );

	errfile = fopen( errfile_name, "ab+" );

	if (errfile == NULL) {
		errx(1, "No such file (%s) -- %s", errfile_name, strerror(errno));
	}

	fprintf( errfile, "\n%s, %s.\n", pkgname, copyright );
	fprintf( logfile, "Using baseroot '%s'\n", baseroot );
	fprintf( logfile, "Using wwwroot '%s'\n", pubroot );

    if ( want_drop ) {
        fprintf( logfile, "Setting GID to %d\n", (int)drop_gid);
        fprintf( logfile, "Setting UID to %d\n", (int)drop_uid);

        fprintf( errfile, "Setting GID to %d\n", (int)drop_gid);
        fprintf( errfile, "Setting UID to %d\n", (int)drop_uid);
    }

	fprintf( logfile, "Started on %s\n", ctime(&now) );
	fprintf( errfile, "Started on %s\n", ctime(&now) );

	free(logfile_name);
	free(errfile_name);
}

//-----------------------------------------------------------------------------
static void init_staticcache()
//-----------------------------------------------------------------------------
{
	struct stat filestat;
	char path[256]={'\0'};
	char key[32]={'\0'};
	char *fname = NULL;
	char *buf = NULL;
	int nread = 0;
	int i = 0;

	for (i=1; i < MAX_CACHE; i++) {

		errno = 0;
		sprintf( key, "Static/%d", i ); 

		fname = inisearch( key, NULL );
		if ( !fname ) { break; }

		sprintf( path, "%s%s", pubroot, fname ); 

		if (lstat( path, &filestat) != 0) {
			err(1, "failed to stat cache file (\"%s\")", path);
			break;
		}

		nread = load_file( path, &buf, (1 << 17) );

		if (nread < 1) {
			err(1, "failed to read cache file (\"%s\")", path);
			break;
		}

		warn("STORE static cache %s",fname);

		staticcache[i-1] = xmalloc(sizeof(struct data_bucket));
		staticcache[i-1]->key = fname;
		staticcache[i-1]->value = buf;
		staticcache[i-1]->size = nread;
		staticcache[i-1]->lastmod = filestat.st_mtime;

		buf = NULL;
	}

	staticcache_total = i-1;

	if (staticcache_total > 1)
		bucket_sort();

	DBG("staticcache_total %d\n", staticcache_total );
}

static void init_hostnames()
{
	char domain[NI_MAXHOST];

	if (!gethostname( domain, NI_MAXHOST )) {
		xasprintf( &hostname, "%s", domain );
	}
}

/* initialize signals */
static void init_signals()
{
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
	{ err(1, "signal(ignore SIGPIPE)"); }

	if (signal(SIGINT, stop_running) == SIG_ERR)
	{ err(1, "signal(SIGINT)"); }

	if (signal(SIGHUP, stop_running) == SIG_ERR)
	{ err(1, "signal(SIGHUP)"); }

	if (signal(SIGTERM, stop_running) == SIG_ERR)
	{ err(1, "signal(SIGTERM)"); }
}

static void init_port()
{
	int rc=0, i=0;

	for (i=0; i<3 && !rc; i++) {
		sockin = rc = init_sockin( i >= 2, bindport, 0 );
	}
}

#ifdef ENABLE_SSL
static void init_ssl_config(const char *domain, const char *wwwroot, const char *certfile, const char *keyfile)
{
	struct tls *server = 0L;
	char *priv = NULL;
	char *cert = NULL;
	int nread_priv=0;
	int nread_cert=0;
	int rc=0;

	nread_cert = load_file( certfile, &cert, (1 << 12) );
	if (nread_cert < 1) { err(1, "ssl_init_config: certificate file"); }

	nread_priv = load_file( keyfile, &priv, (1 << 12) );
	if (nread_priv < 1) { err(1, "ssl_init_config: private key file"); }

#ifdef ENABLE_SSL_S2N
	struct s2n_config *config_ssl = s2n_config_new();
	if (config_ssl == NULL) { err(1, "ssl_init()"); }

	s2n_config_set_cipher_preferences(config_ssl, "default");

	if (s2n_config_add_cert_chain_and_key( config_ssl, cert, priv ) != 0)
		err(1, "ssl_init_config: key and cert file");
#else
	struct tls_config *config_ssl = tls_config_new();
	if (config_ssl == NULL) { err(1, "ssl_init()"); }

	if (tls_config_set_key_mem( config_ssl, (uint8_t*) priv, nread_priv ) < 0)
		err(1, "ssl_init_config: key file");

	if (tls_config_set_cert_mem( config_ssl, (uint8_t*) cert, nread_cert ) < 0)
		err(1, "ssl_init_config: certificate file");

	if ((server = tls_server()) == NULL)
		err(1,"%s: failed to get tls server", __func__);

	if (tls_configure(server, config_ssl) != 0)
		err(1,"%s: failed to configure tls server", __func__);

	tls_config_clear_keys(config_ssl);
	tls_config_free(config_ssl);
#endif

	ssl_configs[ssl_configs_total] = xmalloc(sizeof(struct data_tuple));
	ssl_configs[ssl_configs_total]->key = xstrdup(domain);
	ssl_configs[ssl_configs_total]->value = xstrdup(wwwroot);

#ifdef ENABLE_SSL_S2N
	ssl_configs[ssl_configs_total]->datum = config_ssl;
#else
	ssl_configs[ssl_configs_total]->datum = server;
#endif

	ssl_configs[++ssl_configs_total] = 0L;

	bzero(cert,nread_cert);
	free(cert);

	bzero(priv,nread_priv);
	free(priv);
}

static void init_ssl_ports()
{
	char *cert = inisearch( "SSL/certificate", NULL );
	char *key = inisearch( "SSL/key", NULL );
	char *value, *servers, *curptr;
	int rc=0, i=0;

	putenv( "S2N_DONT_MLOCK=1" );

#if defined( ENABLE_SSL_S2N )
	s2n_init();
#elif defined( ENABLE_SSL_TLS )
	tls_init();
#endif

	for (rc=0, i=0; i<3 && !rc; i++)
		sockin_ssl = rc = init_sockin( i >= 2, bindport_ssl, 1 );

	init_ssl_config( "default", pubroot, cert, key );

	if (!ini_evaluate( "Server/enabled", "yes", NULL ))
		return;

	if ((servers = inisearch( "Server/domains", NULL ))) {

		char *domain = servers;
		char *wwwroot = NULL;

		for (curptr=servers; domain; curptr=NULL) {

			if ((domain = strtok( curptr, "," ))) {

				num_servers += 1;

				cert = key = NULL;
				printf("Adding server '%s'\n", domain);

				xasprintf( &value, "%s/sslcert", domain );
				cert = inisearch( value, NULL );
				free(value);

				xasprintf( &value, "%s/sslkey", domain );
				key = inisearch( value, NULL );
				free(value);

				xasprintf( &value, "%s/root", domain );
				wwwroot = inisearch( value, NULL );
				free(value);

				printf("'%s' '%s' '%s'\n", domain, cert, key);

				if (cert && key) {
					num_ssl_servers += 1;
					init_ssl_config( domain, wwwroot, cert, key );
				}

				if ( !want_proxy ) {
					xasprintf( &value, "%s/ipv4-addr", domain );
					want_proxy = inisearch( value, NULL ) ? 1 : 0;
					free(value);
				}

				if ( !want_indexname ) {
					xasprintf( &value, "%s/index-name", domain );
					want_indexname = inisearch( value, NULL ) ? 1 : 0;
					free(value);
				}
			}
		}
	}
}

//-----------------------------------------------------------------------------
static void ssl_config_free()
//-----------------------------------------------------------------------------
{
	int i;
	for (i=0; ssl_configs[i]; i++) {
		free(ssl_configs[i]->key);
		free(ssl_configs[i]->value);
#ifdef ENABLE_SSL_S2N
		free(ssl_configs[i]->datum);
#else
		tls_free((struct tls*) ssl_configs[i]->datum);
#endif
		free(ssl_configs[i]);
	}
}

static void close_ssl_ports()
{
	shutdown(sockin_ssl,SHUT_RDWR);
#if defined( ENABLE_SSL_S2N )
	s2n_cleanup();
//#elif defined( ENABLE_SSL_TLS )
	//tls_cleanup();
#endif
	ssl_config_free();
}
#endif

//-----------------------------------------------------------------------------
static void close_ports()
//-----------------------------------------------------------------------------
{
	gettimeofday( &chrono, 0L );

#ifdef ENABLE_SSL
	close_ssl_ports();
#endif

	/* clean exit */
	shutdown(sockin,SHUT_RDWR);
}

//-----------------------------------------------------------------------------
static void switch_root()
//-----------------------------------------------------------------------------
{
	/* read /etc/localtime before we chroot */
	tzset();

	if (chroot(baseroot) < 0) {
		err(1, "Failed to chroot into %s", baseroot);
	}

	fprintf( logfile, "Chrooted to %s\n", baseroot);

	baseroot[0] = '\0';
	baserootlen = 0;

	pubroot = rindex( pubroot, '/' );
	pubrootlen = check_folder( pubroot );

	stop_logging();
}

//-----------------------------------------------------------------------------
static void print_usage_stats()
//-----------------------------------------------------------------------------
{
	gettimeofday( &chrono, 0L );

	now = chrono.tv_sec;

	struct rusage r;
	getrusage(RUSAGE_SELF, &r);
	fprintf( logfile, "\nShutdown on %s", ctime(&now));
	fprintf( logfile, "CPU time used: %u.%02u user, %u.%02u system\n",
			(unsigned int)r.ru_utime.tv_sec,
			(unsigned int)(r.ru_utime.tv_usec / 10000),
			(unsigned int)r.ru_stime.tv_sec,
			(unsigned int)(r.ru_stime.tv_usec / 10000)
		  );
	fprintf( logfile, "Requests: %llu\n", llu(num_requests));
	fprintf( logfile, "Bytes: %llu in, %llu out\n", llu(total_in), llu(total_out));
	fflush( logfile );
}

/* close and free connections */
//-----------------------------------------------------------------------------
static void release_connections()
//-----------------------------------------------------------------------------
{
	struct connection* conn, *next;

	LIST_FOREACH_SAFE(conn, &connlist, entries, next) {
		LIST_REMOVE(conn, entries);
		release_resources(conn);
	}
}

//-----------------------------------------------------------------------------
static void release_global_mallocs()
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
{
#ifdef ENABLE_SLOCATE
	free(locate_dbpath);
#endif

#ifdef ENABLE_PASSWORD
	free_tuples( passwords );
#endif

	free_tuples( mimetypes );
	free_tuples( inifile );

	free(mimebuf);
	free(inibuf);

	free(keep_alive_field);
	free(hostname);
	free(wwwrealm);
	free(pubroot);
	free(baseroot);

	free(index_name);
	free(server_hdr);
}

//-----------------------------------------------------------------------------
int main(int argc, char** argv)
//-----------------------------------------------------------------------------
{
	lasttime = now = time(NULL);

	logfile = stdout;
	errfile = stderr;

	if (argc >= 2 && argv[1]) {
		if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
			usage(argv[0]);
			exit(0);
		}
	}

	if (geteuid()) { errx(1, "Must instantiate as root !"); }

	parse_commandline( argc, argv );

	if (want_logging) { init_logging(); }

	parse_default_extension_map();

	xasprintf(&keep_alive_field, "Keep-Alive: timeout=60\r\n");

	if (want_server_id) {
		xasprintf(&server_hdr, "Server: %s\r\n", pkgname);
	} else {
		server_hdr = xstrdup("");
	}

	init_hostnames();

	init_signals();

	init_port();

#ifdef ENABLE_SSL
	if ( want_ssl ) { init_ssl_ports(); }
#endif

#if 0
	struct rlimit old, new;

	if (prlimit(getpid(), RLIMIT_NOFILE, NULL, &old) == -1)
		errx(1,"prlimit-2");
	printf("New limits: soft=%lld; hard=%lld\n",
		(long long) old.rlim_cur, (long long) old.rlim_max);

	old.rlim_cur = 4096;

	if (setrlimit( RLIMIT_NOFILE, &old) == -1)
		errx(1,"prlimit-2");
	printf("New limits: soft=%lld; hard=%lld\n",
		(long long) old.rlim_cur, (long long) old.rlim_max);
#endif

	if ( want_daemon ) {
		daemonize_start();
	}

	if (chdir(baseroot) == -1) {
		err(1, "chdir(%s)", baseroot);
	}

	if (want_chroot) {
		switch_root();
	}

	if (want_drop) {
		drop_privileges();
	}

	init_pidfile();

#ifdef ENABLE_SLOCATE
	init_locate();
#endif

	if (want_chroot || want_drop) {
        if ( want_logging) {
    		init_logging();
        }
	}

#ifdef ENABLE_GUESTBOOK
	init_guestbook();
#endif

	if ( want_cache ) {
		init_staticcache();
	}

	if (want_daemon) {
		daemonize_finish();
	}

	while (running) { httpd_poll(); }

	close_ports();

#ifdef ENABLE_GUESTBOOK
	if (guestbook_file != NULL) {
		fflush(guestbook_file);
		fclose(guestbook_file);
		free(guestbook_reply);
		free(guestbook_template);
	}
#endif

	print_usage_stats();

	release_connections();

	remove_pidfile();

	stop_logging();

	release_global_mallocs();

	return 0;
}

/* vim:set tabstop=4 shiftwidth=4 expandtab tw=78: */
