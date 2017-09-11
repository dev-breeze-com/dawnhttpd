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

static const char pkgname[] = "dawnhttpd/1.4.0";
static const char copyright[] = "copyright (c) 2017 Tsert.Inc";

#ifndef DEBUG
#define NDEBUG
static const int debug = 0;
#else
static const int debug = 1;
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
#  define MAXNAMLEN   255
# endif
#endif

/* To prevent a malformed request from eating up too much memory, die once the
 * request exceeds this many bytes:
 */
#define MAX_REQUEST_LENGTH	4000
#define MAX_POST_LENGTH 	16384
#define MAX_HEADERS	50
#define MAX_TUPLES	250
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
#ifndef CTASSERT                /* Allow lint to override */
# define CTASSERT(x)             _CTASSERT(x, __LINE__)
# define _CTASSERT(x, y)         __CTASSERT(x, y)
# define __CTASSERT(x, y)        typedef char __assert ## y[(x) ? 1 : -1]
#endif
/* [<-] */

CTASSERT(sizeof(unsigned long long) >= sizeof(off_t));
#define llu(x) ((unsigned long long)(x))

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__linux)
# include <err.h>
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
	fprintf(stderr, "warning: ");
	vfprintf(stderr, format, va);
	fprintf(stderr, ": %s\n", strerror(errno));
	va_end(va);
}
#endif

/* [->] LIST_* macros taken from FreeBSD's src/sys/sys/queue.h,v 1.56
 * Copyright (c) 1991, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Under a BSD license.
 */
#define LIST_HEAD(name, type)                                           \
struct name {                                                           \
        struct type *lh_first;  /* first element */                     \
}

#define LIST_HEAD_INITIALIZER(head)                                     \
        { NULL }

#define LIST_ENTRY(type)                                                \
struct {                                                                \
        struct type *le_next;   /* next element */                      \
        struct type **le_prev;  /* address of previous next element */  \
}

#define LIST_FIRST(head)        ((head)->lh_first)

#define LIST_FOREACH_SAFE(var, head, field, tvar)                       \
    for ((var) = LIST_FIRST((head));                                    \
        (var) && ((tvar) = LIST_NEXT((var), field), 1);                 \
        (var) = (tvar))

#define LIST_INSERT_HEAD(head, elm, field) do {                         \
        if ((LIST_NEXT((elm), field) = LIST_FIRST((head))) != NULL)     \
                LIST_FIRST((head))->field.le_prev = &LIST_NEXT((elm), field);\
        LIST_FIRST((head)) = (elm);                                     \
        (elm)->field.le_prev = &LIST_FIRST((head));                     \
} while (0)

#define LIST_NEXT(elm, field)   ((elm)->field.le_next)

#define LIST_REMOVE(elm, field) do {                                    \
        if (LIST_NEXT((elm), field) != NULL)                            \
                LIST_NEXT((elm), field)->field.le_prev =                \
                    (elm)->field.le_prev;                               \
        *(elm)->field.le_prev = LIST_NEXT((elm), field);                \
} while (0)
/* [<-] */

static LIST_HEAD(conn_list_head, connection) connlist =
    LIST_HEAD_INITIALIZER(conn_list_head);

struct dlent {
	char* name;
	int is_dir;
	off_t size;
};

struct data_tuple {
	char* key;
	char* value;
	//int code;
};

struct data_bucket {
	char* key;
	char* value;
	off_t size;
	time_t lastmod;
	time_t lifespan; /* Time to keep ~ 1 hour */
};

struct connection {

	LIST_ENTRY(connection) entries;

	int socket;
#ifdef ENABLE_INET6
	struct in6_addr client;
#else
	in_addr_t client;
#endif
	time_t last_active;
	struct timeval last_chrono;
	enum {
	    RECV_REQUEST=0,   /* receiving request */
	    SEND_HEADER,    /* sending generated header */
	    SEND_REPLY,     /* sending reply */
	    DONE            /* connection closed, need to remove from queue */
	} state;

	/* Session ID */
	uuid_t sessid;

	/* char request[request_length+1] is null-terminated */
	char* request;
	size_t request_length;
	size_t content_len;
	size_t urllen,decoded_urllen;

	/* request fields */
	char *method, *suffix;
	char *url, *decoded_url;
	char *referer, *user_agent;
	char *host, *auth, *cookies;

	off_t payload_size;
	time_t payload_lastmod;

	off_t range_begin, range_end;
	off_t range_begin_given, range_end_given;

	char* auth_header;

	char* header;
	size_t header_length, header_sent;
	int header_only, conn_close;
	int http_code, http_error;
	size_t headers_total;

	char* body;
	struct data_tuple* headers[MAX_HEADERS];
	struct data_tuple* tuples[MAX_TUPLES];
	size_t tuples_total, body_length;

	enum { REPLY_GENERATED=0, REPLY_CACHED, REPLY_FROMFILE } reply_type;
	char* reply;
	int reply_fd, reply_blksz, reply_burst;
	float reply_msecs;
	off_t reply_start, reply_length, reply_sent;
	off_t total_sent; /* header + body = total, for logging */
};

#ifdef ENABLE_SLOCATE
static const char* locate_dbpath = NULL;
static const char* locate_maxhits = NULL;
#endif

static const char* redirect_all_url = NULL;
static int use_redirect = 0;

#ifdef ENABLE_PASSWORD
static char *passwdbuf = NULL;
static const char *password_salt = NULL;
static const char* password_file = NULL;
static struct data_tuple* passwords[MAX_TUPLES];
static int password_saltlen = 0;
static int passwords_total = 0;
static int use_password = 0;
#endif

static char *mimebuf = NULL;
static const char* mimefile_name = NULL;
static struct data_tuple* mimetypes[MAX_TUPLES];
static int mimetypes_total = 0;

static char *inibuf = NULL;
static struct data_tuple* inifile[MAX_TUPLES];
static int inifile_total = 0;

static struct data_bucket* memcache[MAX_CACHE];
static int memcache_total = 0;

static size_t longest_ext = 0;

/* If a connection is idle for idletime seconds or more, it gets closed and
 * removed from the connlist.  Set to 0 to remove the timeout
 * functionality.
 */
static int idletime = 60;
static char* keep_alive_field = NULL;

/* Time is cached in the event loop to avoid making an excessive number of
 * gettimeofday() calls.
 */
static int CHRONO_SZ = sizeof(struct timeval);
static struct timeval chrono;
static int use_millisecs = 0;
static int use_throttling = 0;
static int burst_size = 0;
static time_t now;

/* Defaults can be overridden on the command-line */
static const char* bindaddr = NULL;
static uint16_t bindport = 8080; /* or 80 if running as root */
static int max_connections = -1; /* kern.ipc.somaxconn */

static size_t index_name_len = 10;
static const char* index_name = "index.html";
static const char* postfile_name = NULL;

#ifdef ENABLE_GUESTBOOK
static char* guestbook_template = NULL;
static FILE* guestbook_file = NULL;
#endif

static int sockin = -1;   /* socket to accept connections from */
static int use_inet6 = 0; /* whether the socket uses inet6 */

static char* wwwroot = NULL;
static char* wwwrealm = NULL;
static char* server_hdr = NULL;

static char* pidfile_name = NULL; /* NULL = no pidfile */
static char* logfile_name = "/var/log/dawnhttpd.log";
static FILE* logfile = NULL;

static int want_cache = 0;
static int want_chroot = 0;
static int want_redirect = 0;

static int want_accf = 0;
static int want_daemon = 0;
static int want_keepalive = 1;
static int want_server_id = 1;
static int want_listing = 1;
static int wwwrootlen = 0;

static uint64_t total_in = 0;
static uint64_t total_out = 0;
static uint64_t num_requests = 0;
static uint64_t num_connections = 0;

static volatile int running = 1; /* signal handler sets this to false */

#define INVALID_UID ((uid_t) -1)
#define INVALID_GID ((gid_t) -1)

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

static const char config_file[] = "/etc/dawnhttpd/settings.ini";
static const char octet_stream[] = "application/octet-stream";
static const char* default_mimetype = octet_stream;

static char base64_buffer[MAXNAMLEN]; 
static char* base64_buf = base64_buffer;

/* Prototypes. */
static void poll_recv_request(struct connection* conn);
static void poll_send_header(struct connection* conn);
static void poll_send_reply(struct connection* conn);

/* close() that dies on error.  */
static void xclose(const int fd)
{
	if (close(fd) == -1)
	//{ err(1, "close()"); }
	{ warn( "close()"); }
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
	//assert(left < strlen(src));   /* [left means must be smaller */
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
		}
		else {
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
static int make_safe_url(struct connection* conn)
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

static const char* get_address_text(const void* addr)
{
#ifdef ENABLE_INET6
	if (use_inet6) {
		static char text_addr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, (const struct in6_addr*)addr, text_addr,
		          INET6_ADDRSTRLEN);
		return text_addr;
	}
	else
#endif
	{
		return inet_ntoa(*(const struct in_addr*)addr);
	}
}

static void update_clock(struct connection *conn)
{
	conn->last_active = now;

	if ( use_millisecs ) {
		memcpy( &conn->last_chrono, &chrono, CHRONO_SZ );
		conn->last_chrono.tv_usec += conn->reply_msecs * 100 * 1000;
	}
}

static int bucket_sortcmp(const void* key, const void* item)
{
	struct data_bucket** i1 = (struct data_bucket**) key;
	struct data_bucket** i2 = (struct data_bucket**) item;
	return strcasecmp( (*i1)->key, (*i2)->key );
}

static int bucket_cmp(const void* o1, const void* const o2)
{
	struct data_bucket* i1 = (struct data_bucket*) o1;
	struct data_bucket** i2 = (struct data_bucket**) o2;
	return strcasecmp( i1->key, (*i2)->key );
}

static int tuple_sortcmp(const void* key, const void* item)
{
	struct data_tuple** i1 = (struct data_tuple**) key;
	struct data_tuple** i2 = (struct data_tuple**) item;
	return strcasecmp( (*i1)->key, (*i2)->key );
}

static int tuple_cmp(const void* o1, const void* const o2)
{
	struct data_tuple* i1 = (struct data_tuple*) o1;
	struct data_tuple** i2 = (struct data_tuple**) o2;

#ifdef DEBUG
    // To check out a problem I encountered, where the parameter 'o2'
    // get re-assigned a null value, after the second assignment;
    printf( "tuple_cmp[1]: 0x%x 0x%x 0x%x 0x%x\n", i1, i2, (*i2), o2 );
	fflush( stdout );
	struct data_tuple* i3 = (struct data_tuple*) o2; /* BUG HERE */
    printf( "tuple_cmp[2]: 0x%x 0x%x 0x%x 0x%x\n", i1, i3, (*i3), o2 );
    //printf( "tuple_cmp[3]: '%s' '%s'\n", i1->key, (*i2)->key );
	fflush( stdout );
#endif
	return strcasecmp( i1->key, (*i2)->key );
}

static void bucket_sort()
{
	qsort(
		memcache,
		memcache_total,
		sizeof(struct data_bucket*),
		bucket_sortcmp
	);
}

static void tuple_sort(struct data_tuple* tuples[], int total)
{
	qsort( tuples, total, sizeof(struct data_tuple*), tuple_sortcmp );
}

static char* tuple_search(struct data_tuple* tuples[], int total, const char* arg)
{
    struct data_tuple key={ (char*) arg, NULL };
    struct data_tuple** found = bsearch(
		&key, tuples, total,
		sizeof(struct data_tuple*),
		tuple_cmp
	);
	return (char*) (found ? (*found)->value : NULL);
}

static char* hdrsearch(struct connection* conn, const char* arg)
{
	return tuple_search( conn->headers, conn->headers_total, arg );
}

static int ini_evaluate(const char* key, const char* eqvalue, const char* deflt)
{
	char *value = tuple_search( inifile, inifile_total, key );
	if (!value)
		return deflt ? !strcasecmp(deflt,eqvalue) : 0;
	return value ? !strcasecmp(value,eqvalue) : 0;
}

static char* inisearch(const char* key, const char* deflt)
{
	char *value = tuple_search( inifile, inifile_total, key );
	return value ? value : (char*) deflt;
}

#ifdef ENABLE_PASSWORD
static int htpasswd(const char* user, const char* password)
{
	char *value = tuple_search( passwords, passwords_total, user );
	return value ? !strcasecmp(value,password) : 0;
}
#endif

/* Initialize the sockin global.  This is the socket that we accept
 * connections from.
 */
static int init_sockin(int lasttime)
{
	struct sockaddr_in addrin;
#ifdef ENABLE_INET6
	struct sockaddr_in6 addrin6;
#endif
	socklen_t addrin_len;
	char *value = NULL;
	int sockopt = 0;
	int i = 0;

#ifdef ENABLE_INET6
	if (use_inet6) {
		memset(&addrin6, 0, sizeof(addrin6));

		if (inet_pton(AF_INET6, bindaddr ? bindaddr : "::", &addrin6.sin6_addr) == -1) {
			errx(1, "malformed --addr argument");
		}

#if 0
		if ( want_daemon ) {
			for (i=0; i < delay; i++) {
				sockin = socket(PF_INET6, SOCK_STREAM, 0);
				if (sockin > 0) break;
				sleep(1);
			}
		} else {
			sockin = socket(PF_INET6, SOCK_STREAM, 0);
		}
#endif
		sockin = socket(PF_INET6, SOCK_STREAM, 0);
	}
	else
#endif
	{
		memset(&addrin, 0, sizeof(addrin));

		addrin.sin_addr.s_addr = bindaddr ? inet_addr(bindaddr) : INADDR_ANY;

		if (addrin.sin_addr.s_addr == (in_addr_t)INADDR_NONE)
		{ errx(1, "malformed --addr argument"); }

#if 0
		if ( want_daemon ) {
			for (i=0; i < delay; i++) {
				sockin = socket(PF_INET, SOCK_STREAM, 0);
				if (sockin > 0) break;
				sleep(1);
			}
		} else {
			sockin = socket(PF_INET, SOCK_STREAM, 0);
		}
#endif
		sockin = socket(PF_INET, SOCK_STREAM, 0);
	}

	if (sockin == -1) { 
		if (lasttime) {
			err(1, "socket()");
		}
		warn( "socket()");
		return 0;
	}

	/* reuse address */
	sockopt = 1;

	if (setsockopt(sockin, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) == -1)
	{ err(1, "setsockopt(SO_REUSEADDR)"); }

#if 0
	/* disable Nagle since we buffer everything ourselves */
	sockopt = 1;

	if (setsockopt(sockin, IPPROTO_TCP, TCP_NODELAY,
	               &sockopt, sizeof(sockopt)) == -1)
	{ err(1, "setsockopt(TCP_NODELAY)"); }

#endif
#ifdef TORTURE
	/* torture: cripple the kernel-side send buffer so we can only squeeze out
	 * one byte at a time (this is for debugging)
	 */
	sockopt = 1;

	if (setsockopt(sockin, SOL_SOCKET, SO_SNDBUF,
        &sockopt, sizeof(sockopt)) == -1)
	{ err(1, "setsockopt(SO_SNDBUF)"); }

#endif
	/* bind socket */
#ifdef ENABLE_INET6

	if (use_inet6) {
		addrin6.sin6_family = AF_INET6;
		addrin6.sin6_port = htons(bindport);

		if (bind(sockin, (struct sockaddr*)&addrin6, sizeof(struct sockaddr_in6)) == -1)
		{ err(1, "bind(port %u)", bindport); }

		addrin_len = sizeof(addrin6);

		if (getsockname(sockin, (struct sockaddr*)&addrin6, &addrin_len) == -1)
		{ err(1, "getsockname()"); }

		fprintf( logfile, "listening on: http://[%s]:%u/\n",
            get_address_text(&addrin6.sin6_addr), bindport);
	}
	else
#endif
	{
		addrin.sin_family = (u_char)PF_INET;
		addrin.sin_port = htons(bindport);

		if (bind(sockin, (struct sockaddr*)&addrin,
            sizeof(struct sockaddr_in)) == -1)
		{ err(1, "bind(port %u)", bindport); }

		addrin_len = sizeof(addrin);

		if (getsockname(sockin, (struct sockaddr*)&addrin, &addrin_len) == -1)
		{ err(1, "getsockname()"); }

		fprintf( logfile, "listening on: http://%s:%u/\n",
            get_address_text(&addrin.sin_addr), bindport);
	}

	/* listen on socket */
	if (listen(sockin, max_connections) == -1)
	{ err(1, "listen()"); }

	/* enable acceptfilter (this is only available on FreeBSD) */
	if (want_accf) {
#if defined(__FreeBSD__)
		struct accept_filter_arg filt = {"httpready", ""};

		if (setsockopt(sockin, SOL_SOCKET, SO_ACCEPTFILTER,
		               &filt, sizeof(filt)) == -1)
			fprintf(stderr, "cannot enable acceptfilter: %s\n",
			        strerror(errno));
		else
		{ printf("enabled acceptfilter\n"); }

#else
		printf("this platform doesn't support acceptfilter\n");
#endif
	}
	return 1;
}

static void usage(const char* argv0)
{
	printf("Usage:\t%s [options]\n\n", argv0);
	printf("\t--port number (default: %u, or 80 if running as root)\n"
	       "\t\tSpecifies which port to listen on for connections.\n"
	       "\t\tPass 0 to let the system choose any free port for you.\n\n", bindport);
	printf("\t--addr ip (default: all)\n"
	       "\t\tIf multiple interfaces are present, specifies\n"
	       "\t\twhich one to bind the listening port to.\n\n");
	printf("\t--maxconn number (default: system maximum)\n"
	       "\t\tSpecifies how many concurrent connections to accept.\n\n");
	printf("\t--stdout (default: /var/log/dawnhttpd.log)\n"
	       "\t\tOutputs log info to stdout.\n\n");
	printf("\t--chroot (default: don't chroot)\n"
	       "\t\tLocks server into wwwroot directory for added security.\n\n");
	printf("\t--no-daemon (default: daemonize)\n"
	       "\t\tDo not detach from the controlling terminal to run in the background.\n\n");
	printf("\t--no-keepalive\n"
	       "\t\tDisables HTTP Keep-Alive functionality.\n\n");
#if 0
	printf("\t--index filename (default: %s)\n"
	       "\t\tDefault file to serve when a directory is requested.\n\n",
	       index_name);
	printf("\t--post filename)\n"
	       "\t\tDefault file to serve after a post request.\n\n");
	printf("\t--no-listing\n"
	       "\t\tDo not serve listing if directory is requested.\n\n");
	printf("\t--mimetypes filename (optional)\n"
	       "\t\tParses specified file for extension-MIME associations.\n\n");
	printf("\t--forward host url (default: don't forward)\n"
	       "\t\tWeb forward (301 redirect).\n"
	       "\t\tRequests to the host are redirected to the corresponding url.\n"
	       "\t\tThe option may be specified multiple times, in which case\n"
	       "\t\tthe host is matched in order of appearance.\n\n");
	printf("\t--default-mimetype string (optional, default: %s)\n"
	       "\t\tFiles with unknown extensions are served as this mimetype.\n\n",
	       octet_stream);
#endif
#ifdef ENABLE_PIDFILE
	printf("\t--pidfile filename (default: no pidfile)\n"
	       "\t\tWrite PID to the specified file.  Note that if you are\n"
	       "\t\tusing --chroot, then the pidfile must be relative to,\n"
	       "\t\tand inside the wwwroot.\n\n");
#else
	printf("\t(This binary was built without PID file support)\n\n");
#endif
	printf("\t--uid uid/uname, --gid gid/gname (default: don't privdrop)\n"
	       "\t\tDrops privileges to given uid:gid after initialization.\n\n");
#ifdef __FreeBSD__
	printf("\t--accf (default: don't use acceptfilter)\n"
	       "\t\tUse acceptfilter.  Needs the accf_http module loaded.\n\n");
#endif
	printf("\t--forward-all url (default: don't forward)\n"
	       "\t\tWeb forward (301 redirect).\n"
	       "\t\tAll requests are redirected to the corresponding url.\n\n");
	printf("\t--no-server-id\n"
	       "\t\tDon't identify the server type in headers\n"
	       "\t\tor directory listings.\n\n");
#ifdef ENABLE_INET6
	printf("\t--ipv6\n"
	       "\t\tListen on IPv6 address.\n\n");
#else
	printf("\t(This binary was built without IPv6 support)\n");
#endif
#ifndef ENABLE_PASSWORD
	printf("\t(This binary was built without password support)\n");
#endif
}

/* Allocate and initialize an empty connection. */
static struct connection* new_connection(void)
{
	struct connection* conn = xmalloc(sizeof(struct connection));

	num_connections += 1;

	memset(&conn->client, 0, sizeof(conn->client) );

	conn->socket = -1;
	conn->last_active = now;
	conn->request = NULL;
	conn->request_length = 0;
	conn->method = NULL;
	conn->url = NULL;
	conn->host = NULL;
	conn->decoded_url = NULL;
	conn->referer = NULL;
	conn->user_agent = NULL;

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
	conn->reply_burst = 1 << 20;
	conn->reply_sent = 0;
	conn->total_sent = 0;
	conn->reply_type = REPLY_GENERATED;

	memset( conn->tuples, 0, sizeof(conn->tuples) );
	memset( conn->headers, 0, sizeof(conn->headers) );

	conn->body = NULL;
	conn->body_length = 0;

	/* Make it harmless so it gets garbage-collected if it should, for some
	 * reason, fail to be correctly filled out.
	 */
	conn->state = DONE;
	return conn;
}

/* Accept a connection from sockin and add it to the connection queue. */
static void accept_connection(void)
{
	struct sockaddr_in addrin;
#ifdef ENABLE_INET6
	struct sockaddr_in6 addrin6;
#endif

	socklen_t sin_size;
	struct connection* conn;
	/* allocate and initialise struct connection */
	conn = new_connection();

#ifdef ENABLE_INET6
	if (use_inet6) {
		sin_size = sizeof(addrin6);
		memset(&addrin6, 0, sin_size);
		conn->socket = accept(sockin, (struct sockaddr*)&addrin6, &sin_size);
	}
	else
#endif
	{
		sin_size = sizeof(addrin);
		memset(&addrin, 0, sin_size);
		conn->socket = accept(sockin, (struct sockaddr*)&addrin, &sin_size);
	}

	if (conn->socket == -1)
	{ err(1, "accept()"); }

	nonblock_socket(conn->socket);
	conn->state = RECV_REQUEST;

#ifdef ENABLE_INET6
	if (use_inet6) {
		conn->client = addrin6.sin6_addr;
	}
	else
#endif
	{
		*(in_addr_t*)&conn->client = addrin.sin_addr.s_addr;
	}

	LIST_INSERT_HEAD(&connlist, conn, entries);

	if (debug) {
		printf("accepted connection from %s:%u\n",
			inet_ntoa(addrin.sin_addr), ntohs(addrin.sin_port));
	}

	/* Try to read straight away rather than going through another iteration
	 * of the select() loop.
	 */
	poll_recv_request(conn);
}

/* Should this character be logencoded?
 */
static int needs_logencoding(const unsigned char c)
{
	return ((c <= 0x1F) || (c >= 0x7F) || (c == '"'));
}

/* Encode string for logging.
 */
static void logencode(const char* src, char* dest)
{
	static const char hex[] = "0123456789ABCDEF";
	int i, j;

	for (i = j = 0; src[i] != '\0'; i++) {
		if (needs_logencoding((unsigned char)src[i])) {
			dest[j++] = '%';
			dest[j++] = hex[(src[i] >> 4) & 0xF];
			dest[j++] = hex[ src[i]       & 0xF];
		} else {
			dest[j++] = src[i];
		}
	}
	dest[j] = '\0';
}

static void log_connection(const struct connection* conn, int onrequest)
{
	char* safe_referer, *safe_user_agent;
	char* safe_method, *safe_url;

	if (logfile == NULL) { return; }

	/* invalid - didn't parse - maybe too long */
	if (conn->method == NULL) { return; }

	/* invalid - died in request */
	if (!onrequest && conn->http_code == 0) { return; }

    //if (onrequest) {
	//}

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
	fprintf(logfile, "%lu %s \"%s %s\" [%d] %llu \"%s\" \"%s\"\n",
	        (unsigned long int)now,
	        get_address_text(&conn->client),
	        //conn->method,
	        use_safe(method),
	        use_safe(url),
	        conn->http_code,
	        //num_connections,
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

static void free_tuples(struct data_tuple *tuples[])
{
    int i;
    for (i=0; tuples[i]; i++)
        free(tuples[i]);
}

/* Log a connection, then cleanly deallocate its internals. */
/* Log a connection, then cleanly deallocate its internals. */
static void free_conn_tuples(struct connection* conn)
{
    free_tuples( conn->tuples );
    free_tuples( conn->headers );
}

static void free_connection(struct connection* conn)
{
	if (debug) {
        printf("free_connection(%d)\n", conn->socket);
    }

	if ( conn->http_error )
		log_connection( conn, 0 );

	if (conn->socket != -1) { xclose(conn->socket); }

	if (conn->request != NULL) { free(conn->request); }

	if (conn->method != NULL) { free(conn->method); }

	if (conn->url != NULL) { free(conn->url); }

	if (conn->decoded_url != NULL) { free( conn->decoded_url ); }

	if (conn->header != NULL) { free(conn->header); }

	if (conn->reply != NULL && conn->reply_type != REPLY_CACHED) { free(conn->reply); }

	if (conn->reply_fd != -1) { xclose(conn->reply_fd); }
}

/* Recycle a finished connection for HTTP/1.1 Keep-Alive. */
static void recycle_connection(struct connection* conn)
{
	int socket_tmp = conn->socket;

	if (debug) {
		printf("recycle_connection(%d)\n", socket_tmp);
	}

    /* so free_connection() doesn't close it */
	conn->socket = -1;

	free_connection(conn);

	conn->socket = socket_tmp;

	/* don't reset conn->client */
	conn->request = NULL;
	conn->request_length = 0;

	conn->method = NULL;
	conn->url = NULL;
	conn->referer = NULL;
	conn->user_agent = NULL;
	conn->host = NULL;
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
	conn->reply_burst = 1 << 20;
	conn->reply_sent = 0;
	conn->total_sent = 0;
	//conn->reply_type = REPLY_GENERATED;
	conn->state = RECV_REQUEST; /* ready for another */

	if ( conn->tuples[0] ) { conn->tuples[0]->key = NULL; }
	if ( conn->headers[0] ) { conn->headers[0]->key = NULL; }
}

/* Uppercasify all characters in a string of given length. */
static void strntoupper(char* str, const size_t length)
{
	size_t i;

	for (i = 0; i < length; i++)
	{ str[i] = (char)toupper(str[i]); }
}

/* If a connection has been idle for more than idletime seconds, it will be
 * marked as DONE and killed off in httpd_poll()
 */
static void poll_check_timeout(struct connection* conn)
{
	if (idletime > 0) { /* optimised away by compiler */
		if ((now - conn->last_active) >= idletime) {
			if (debug) {
				fprintf(
					logfile,
					"poll_check_timeout(%d) caused closure\n",
					conn->socket
				);
			}
			conn->conn_close = 1;
			conn->state = DONE;
		}
	}
}

/* Format [when] as an RFC1123 date, stored in the specified buffer.  The same
 * buffer is returned for convenience.
 */
#define DATE_LEN 30 /* strlen("Fri, 28 Feb 2003 00:02:08 GMT")+1 */
static char* rfc1123_date(char* dest, const time_t when)
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
static void urldecode(struct connection* conn)
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
static const char* keep_alive(const struct connection* conn)
{
	return (conn->conn_close ? "Connection: close\r\n" : keep_alive_field);
}

/* "Generated by " + pkgname + " on " + date + "\n"
 *  1234567890123               1234            2 ('\n' and '\0')
 */
static char _generated_on_buf[13 + sizeof(pkgname) - 1 + 4 + DATE_LEN + 2];
static const char* generated_on(const char date[DATE_LEN])
{
	if (!want_server_id)
	{ return ""; }

	snprintf(_generated_on_buf, sizeof(_generated_on_buf),
	         "Generated by %s on %s\n", pkgname, date);
	return _generated_on_buf;
}

/* A default reply for any (erroneous) occasion. */
static void default_reply(struct connection* conn, const int errcode, const char* errname, const char* format, ...) __printflike(4, 5);

static void default_reply(struct connection* conn, const int errcode, const char* errname, const char* format, ...)
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

static void redirect(struct connection* conn, const char* format, ...) __printflike(2, 3);
static void redirect(struct connection* conn, const char* format, ...)
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

static char* decode_url(struct connection* conn)
{
	/* Work out path of file being requested */
	urldecode( conn );

	/* Make sure it's safe */
	if (make_safe_url( conn ))
		return conn->decoded_url;

	default_reply(conn, 400, "Bad Request", "You requested an invalid URL: %s", conn->url);
	return NULL;
}

static int dir_exists(const char* path)
{
	struct stat strec;
	if ((stat(path, &strec) == -1) && (errno == ENOENT))
	    return 0;
	return S_ISDIR( strec.st_mode ) ? 1 : 0;
}

static int file_exists(const char* path)
{
	struct stat strec;
	if ((stat(path, &strec) == -1) && (errno == ENOENT))
	    return 0;
	return S_ISREG( strec.st_mode ) ? 1 : 0;
}

static int file_size(const char* path)
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
static void parse_default_extension_map(void)
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
static char *parse_field(const struct connection *conn, const char *field) {

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

static char* skipcr(char *sptr, char **bptr)
{
    for (; *sptr != '\r' && *sptr != '\n'; sptr++) ;
    for (; *sptr == '\r' || *sptr == '\n'; sptr++) ;
    (*bptr) = sptr;
    sptr--;
    return sptr;
}

static int parse_tuples(struct connection* conn, struct data_tuple* tuples[],
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

	if (debug && for_hdr)
    { fprintf( logfile, "Buffer: '%s'\n", buffer); }

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
                if (debug)
                { printf("begofline=%d\n",begofline); }

                if ( begofline ) {
				    bptr = ++sptr;
                    for (; *sptr != ']'; sptr++) ;
					*sptr = '\0';

                    inigrp = bptr;
                    sptr = skipcr( sptr, &bptr );
                    begofline = 1;

					if (debug)
					{ printf("inigrp='%s'\n",inigrp); }
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
                if (debug)
                { printf("SEQLEN=%d\n",seqlen); }
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
                if (debug)
                { printf("VALUE='%s'\n", tuples[i-1]->value); }
                if (debug)
                { printf("KEY='%s'\n", bptr); }
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

                    if (debug)
                    { printf("VALUE[%d]=\"%s\"\n", i-1, tuples[i-1]->value); }
                /*
                */
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

                    if (debug)
                    { printf("KEY[%d]=\"%s\" 0x%x\n", i, tuples[i]->key, tuples[i]->key); }
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

	if (debug) {
        printf("LAST TUPLES[%d]=0x%x\n", i, tuples[i] );
    }

    if ( tuples[i] ) {

		if ( tuples[i]->key ) {

			if (debug)
				{ printf("LAST TUPLES[%d]='%s'\n", i, tuples[i]->key ); }

			if (bptr && !tuples[i]->value) {
				if (debug)
					{ printf("LAST VALUE TUPLES[%d]='%s'\n", i, bptr); }

				tuples[i++]->value = bptr;
			}
		}

		if ( tuples[i] ) {
			tuples[i]->key = NULL;
			tuples[i]->value = NULL;
		}
	}

    tuple_sort( tuples, total=i );

    /*
	if (debug)
        { printf("TUPLES 0x%x\n", tuples ); }

	if (debug)
        { printf("TOTAL %d\n", i ); }

    for (i=0; i<total; i++) {
        printf(
            "TUPLE[%d][0x%x][%s]='%s'\n",
            i, tuples[i], tuples[i]->key, tuples[i]->value 
        );
	}
    */

    return total;
}

static int load_file(const char* filename, char** buffer, int maximum)
{
	FILE* fp = fopen( filename, "rb" );
	int sz = file_size( filename );
	char *sptr = (*buffer) = NULL;
	size_t nread = 0;
	int total = sz;
	int i = 0;

	if (debug) {
		fprintf( logfile, "load_file: file size=%d max=%d\n", sz, maximum );
	}

    if (sz >= maximum)
        return 0;

	sptr = (*buffer) = xmalloc( sz+3 );

	while (!feof( fp )) {

        if (ferror(fp)) {
	        fclose(fp);
            return 0;
        }

        if ((nread = fread( sptr, sz, sizeof(char), fp )) > 0) {
            sptr += nread;
            sz -= nread;
        }
    }

	fclose(fp);

	sptr = (*buffer);
	sptr += total;
    (*sptr) = '\0';

    return total;
}

static int load_cfgfile(const char* path, char **buffer, struct data_tuple* tuples[], int maxsz)
{
    int total = load_file( path, buffer, 1 << 15 );
    if (total > 0)
        total = parse_tuples( 0L, tuples, (*buffer), '=', "\r\n", maxsz );
    return total;
}

static int get_cached_url(struct connection* conn, const char* arg)
{
    struct data_bucket key={ (char*) arg, NULL };
    struct data_bucket** found = bsearch(
		&key, memcache, memcache_total,
		sizeof(struct data_bucket*),
		bucket_cmp
	);

	if ( found ) {
		conn->payload_size = (*found)->size;
		conn->payload_lastmod = (*found)->lastmod;
		conn->reply = (*found)->value;
		conn->reply_type = REPLY_CACHED;
		conn->reply_start = 0;
	}
	return found ? 1 : 0;
}

static const char* url_content_type(const char* url, int urllen, char** suffix)
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
static void parse_range_field(struct connection* conn)
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

/* Parse an HTTP request like "GET / HTTP/1.1" to get the method (GET), the
 * url (/), the referer (if given) and the user-agent (if given).  Remember to
 * deallocate all these buffers.  The method will be returned in uppercase.
 */
static int parse_request(struct connection* conn)
{
	size_t bound1, bound2;
	char* tmp, *sptr;

	assert(conn->request_length == strlen(conn->request));

	/* parse method */
	for (bound1 = 0;
	        (bound1 < conn->request_length) &&
	        (conn->request[bound1] != ' ');
	        bound1++)
		;

	conn->method = split_string(conn->request, 0, bound1);
	strntoupper(conn->method, bound1);

	/* parse url */
	for (;
	        (bound1 < conn->request_length) &&
	        (conn->request[bound1] == ' ');
	        bound1++)
		;

	if (bound1 == conn->request_length) { return 0; } /* fail */

	for (bound2 = bound1 + 1;
	        (bound2 < conn->request_length) &&
	        (conn->request[bound2] != ' ') &&
	        (conn->request[bound2] != '\r') &&
	        (conn->request[bound2] != '\n');
	        bound2++)
		;

	conn->url = split_string(conn->request, bound1, bound2);
	conn->urllen = bound2 - bound1;

	/* parse protocol to determine conn_close */
	if (conn->request[bound2] == ' ') {

		char* proto;

		for (bound1 = bound2;
		        (bound1 < conn->request_length) &&
		        (conn->request[bound1] == ' ');
		        bound1++)
			;

		for (bound2 = bound1 + 1;
		        (bound2 < conn->request_length) &&
		        (conn->request[bound2] != ' ') &&
		        (conn->request[bound2] != '\r');
		        bound2++)
			;

		proto = split_string(conn->request, bound1, bound2);

		if (strcasecmp(proto, "HTTP/1.1") == 0) {
			conn->conn_close = 0;
		}

		free(proto);
	}

	sptr = &(conn->request[bound2+1]);
	for (; (*sptr) == '\n' || (*sptr) == '\r'; sptr++);
	conn->header = sptr;

    conn->headers_total = parse_tuples(
        conn, conn->headers, conn->header, ':', "\r\n", MAX_HEADERS
    );

    if (conn->headers_total < 1)
        return 0;

	/* Parse Connection Field */
	tmp = hdrsearch( conn, "Connection" );

	if (tmp != NULL) {

		if (strcasecmp(tmp, "close") == 0) {
			conn->conn_close = 1;
		} else if (strcasecmp(tmp, "keep-alive") == 0) {
			conn->conn_close = 0;
		}
	}

	/* cmdline flag can be used to deny keep-alive */
	if (!want_keepalive) {
		conn->conn_close = 1;
	}

	/* Parse Important Fields */
	conn->referer = hdrsearch( conn, "Referer" );
	conn->user_agent = hdrsearch( conn, "User-Agent" );

	parse_range_field( conn );
	return 1;
}

static int dlent_cmp(const void* a, const void* b)
{
	return strcmp((*((const struct dlent * const*)a))->name,
		(*((const struct dlent * const*)b))->name);
}

#ifdef ENABLE_SLOCATE
/* Make sorted list of files in a directory.
 * Returns number of entries, or -1 if error occurs.
 */
static ssize_t get_locate_listing(const char* path, struct dlent** *output, size_t *maxlen)
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
static ssize_t make_sorted_dirlist(const char* path, struct dlent** *output, size_t *maxlen)
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
static void cleanup_sorted_dirlist(struct dlent** list, const ssize_t size)
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
static int is_unreserved(const unsigned char c)
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
static void urlencode(const char* src, char* dest)
{
	static const char hex[] = "0123456789ABCDEF";
	int i, j;

	for (i = j = 0; src[i] != '\0'; i++) {
		if (!is_unreserved((unsigned char)src[i])) {
			dest[j++] = '%';
			dest[j++] = hex[(src[i] >> 4) & 0xF];
			dest[j++] = hex[ src[i]       & 0xF];
		}
		else
		{ dest[j++] = src[i]; }
	}

	dest[j] = '\0';
}

static void generate_dir_listing(struct connection* conn, const char* path)
{
	char date[DATE_LEN], *spaces;
	char *hdr = hdrsearch( conn, "Accept" );
	struct dlent** list;
	ssize_t listsize;
	size_t maxlen = 2; /* There has to be ".." */
	struct apbuf* listing;
	int i = 0;

#ifdef ENABLE_SLOCATE
	if (hdr && !strcasecmp( hdr, "text/tsv" )) {
        if ( !locate_dbpath || !locate_maxhits ) {
            default_reply(conn, 500, "Internal Server Error",
                "Search mode must be enabled");
            return;
        }

	    listsize = get_locate_listing(path, &list, &maxlen);

        if (listsize == -1) {
            default_reply(conn, 500, "Internal Server Error",
                "No hits found for %s", path);
            return;
        }
    } else {
#endif /* ENABLE_SLOCATE */
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
#ifdef ENABLE_SLOCATE
    }
#endif /* ENABLE_SLOCATE */

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
static int fill_guestbook(struct connection* conn)
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
static int password_ok(struct connection* conn, const char* user, const char* password)
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

static int parse_auth(struct connection* conn)
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
static void process_get(struct connection* conn)
{
	/* work out path of file being requested */
	char* decoded_url = conn->decoded_url;
	char date[DATE_LEN], lastmod[DATE_LEN];
	char *throttle, *target, *if_mod_since;
	char *redirect_key, *msecs;
	const char* mimetype = NULL;
	const char* blksize = NULL;
	const char* forward_to = NULL;
	struct stat filestat;
	int slash_path = 0;
	int kbps, rc = 0;
	size_t i=0;

	if (use_redirect && conn->host) {
		xasprintf(&redirect_key, "%s%s", "Redirect/", conn->host);
		forward_to = inisearch( redirect_key, NULL );
	}

	if (!forward_to) {
		forward_to = redirect_all_url;
	}

	if (forward_to) {
		redirect(conn, "%s%s", forward_to, decoded_url);
		return;
	}

	/* does it end in a slash? serve up url/index_name */
	slash_path = decoded_url[ conn->decoded_urllen - 1 ] == '/';
	//slash_path = decoded_url [strlen(decoded_url) - 1] == '/';

	if ( slash_path ) {

		xasprintf(&target, "%s%s%s", wwwroot, decoded_url, index_name);

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

			xasprintf(&target, "%s%s", wwwroot, decoded_url);
			generate_dir_listing(conn, target);
			free(target);
			return;
		}
	} else {
		/* points to a file */
		xasprintf(&target, "%s%s", wwwroot, decoded_url);
		//mimetype = url_content_type( decoded_url, strlen(decoded_url));
		mimetype = url_content_type( decoded_url, conn->decoded_urllen, &conn->suffix );
	}

	if ( use_throttling ) {

		xasprintf(&throttle, "%s%s", "Throttle/", mimetype);

		if ((blksize = inisearch( throttle, NULL ))) {

			assert( strlen(blksize) < 16 );

			if (strstr(mimetype, "video/"))
				conn->reply_burst = burst_size;

			if (use_millisecs && (msecs = strchr( blksize, ',' ))) {
				conn->reply_msecs = atoi( msecs+1 );
				conn->reply_msecs /= 1000;
				strncpy( throttle, blksize, msecs-blksize );
				throttle[msecs-blksize] = '\0';
				conn->reply_blksz = atoi( throttle ) * 1024;
//		fprintf( logfile, "Throttling '%s' '%s' [%d, %02f, %d]\n", throttle, blksize, conn->reply_burst, conn->reply_msecs, conn->reply_blksz);

			} else {
				conn->reply_blksz = atoi( blksize ) * 1024;
			}

			kbps = conn->reply_blksz * 8;

			if ( use_millisecs ) {
				kbps /= conn->reply_msecs;
			}

			fprintf( logfile, "Throttling '%s' at %d Kbps [%d, %02f]\n", mimetype, kbps, conn->reply_burst, conn->reply_msecs);
			fflush( logfile );
		}
		free(throttle);
	}

	/* check if url was cached */
	rc = get_cached_url( conn, target+wwwrootlen );

	if ( rc ) {
		conn->header_only = 0;
		//conn->reply_type = REPLY_CACHED;
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
			if (conn->reply != NULL) { free(conn->reply); }
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

		if (debug) {
			fprintf( logfile, "sending %llu-%llu/%llu\n",
			    llu(from), llu(to), llu(conn->payload_size));
		}
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
static void process_post(struct connection* conn)
{
	if (conn->content_len < MAX_POST_LENGTH) {

        conn->tuples_total = parse_tuples(
            conn, conn->tuples, conn->body, '=', "&", MAX_TUPLES
        );

        if (conn->tuples_total > 0) {

#ifdef ENABLE_GUESTBOOK
            if (fill_guestbook( conn )) {
                if ( postfile_name ) {
                    free(conn->url);
                    conn->url = xstrdup( postfile_name );

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

/* Process a request: build the header and reply, advance state. */
static void process_request(struct connection* conn)
{
	num_requests++;

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

	log_connection( conn, 1 );

#ifdef ENABLE_PASSWORD
	if (use_password && !parse_auth(conn)) {
		conn->state = SEND_HEADER;
		return;
	}
#endif

	if (strcmp(conn->method, "GET") == 0) {
		process_get(conn);
	}
	else if (strcmp(conn->method, "HEAD") == 0) {
		process_get(conn);
		conn->header_only = 1;
	}
	else if (strcmp(conn->method, "POST") == 0) {
		process_post(conn);
	}
	else if ((strcmp(conn->method, "OPTIONS") == 0) ||
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

/* Receiving request. */
static void poll_recv_request(struct connection* conn)
{
	char buf[1 << 15];
	char *sptr = NULL;
	ssize_t recvd;

	assert(conn->state == RECV_REQUEST);

	recvd = recv(conn->socket, buf, sizeof(buf), 0);

	if (debug) {
		printf("poll_recv_request(%d) got %d bytes\n", conn->socket, (int)recvd);
    }

	if (recvd < 1) {
		if (recvd == -1) {
			if (errno == EAGAIN) {
				if (debug) { printf("poll_recv_request would have blocked\n"); }
				return;
			}

			if (debug) {
                printf("recv(%d) error: %s\n", conn->socket, strerror(errno));
            }
		}

		conn->conn_close = 1;
		conn->state = DONE;
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
	if ((conn->request_length > 2) &&
        (memcmp(conn->request + conn->request_length - 2, "\n\n", 2) == 0))
    {
	    process_request(conn);
	}
	else if ((conn->request_length > 4) &&
        (memcmp(conn->request + conn->request_length - 4, "\r\n\r\n", 4) == 0))
    {
		process_request(conn);
	}
    else if (memcmp( conn->request, "POST ", 5 ) == 0) {

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

            if (debug)
            { printf("request %d %d\n", recvd, conn->content_len); }

            if (recvd == conn->content_len) {
                process_request(conn);
            } else {
                default_reply(conn, 400, "Bad Request",
                    "You requested an invalid URL: %s", conn->url);
		        conn->state = SEND_HEADER;
            }
        }
    }

	/* die if it's too large */
	if (conn->request_length > MAX_REQUEST_LENGTH) {
		default_reply(conn, 413, "Request Entity Too Large",
		    "Your request was dropped because it was too long.");
		conn->state = SEND_HEADER;
	}

	/* if we've moved on to the next state, try to send right away, instead of
	 * going through another iteration of the select() loop.
	 */
	if (conn->state == SEND_HEADER) {
		poll_send_header(conn);
	}
}

/* Sending header.  Assumes conn->header is not NULL. */
static void poll_send_header(struct connection* conn)
{
	ssize_t sent;

	assert(conn->state == SEND_HEADER);
	assert(conn->header_length == strlen(conn->header));

	sent = send(conn->socket,
        conn->header + conn->header_sent,
        conn->header_length - conn->header_sent,
        0);

	update_clock( conn );

	if (debug) {
		printf(
		    "poll_send_header(%d) sent %d bytes\n",
		    conn->socket, (int)sent
		);
	}

	/* handle any errors (-1) or closure (0) in send() */
	if (sent < 1) {
		if ((sent == -1) && (errno == EAGAIN)) {
			if (debug) { printf("poll_send_header would have blocked\n"); }

			return;
		}

		if (debug && (sent == -1))
		{ printf("send(%d) error: %s\n", conn->socket, strerror(errno)); }

		conn->conn_close = 1;
		conn->state = DONE;
		return;
	}

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

/* Send chunk on socket <s> from FILE *fp, starting at <ofs> and of size
 * <size>.  Use sendfile() if possible since it's zero-copy on some platforms.
 * Returns the number of bytes sent, 0 on closure, -1 if send() failed, -2 if
 * read error.
 */
static ssize_t send_from_file(const int s, const int fd, off_t ofs, size_t nbytes)
{
	/* Limit truly ridiculous (LARGEFILE) requests. */
	if (nbytes > (1 << 23)) { nbytes = 1 << 20; }

#ifdef __FreeBSD__
	off_t sent = 0;
	int ret = sendfile(fd, s, ofs, nbytes, NULL, &sent, 0);

	/* It is possible for sendfile to send zero bytes due to a blocking
	 * condition.  Handle this correctly.
	 */
	if (ret == -1) {
		if (errno == EAGAIN) {
			if (sent == 0)
			{ return -1; }
			else
			{ return sent; }
		}
		else
		{ return -1; }
	}
	else
	{ return nbytes; }

#elif defined(__linux) || defined(__sun__)
	//fprintf(logfile, "Expecting %zu bytes on fd %d\n", nbytes, fd);
	return sendfile(s, fd, &ofs, nbytes);
#else
	/* Fake sendfile() with read(). */
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
		fprintf(stderr, "premature eof on fd %d\n", fd);
		return -1;
	}

	if (numread == -1) {
		fprintf(stderr, "error reading on fd %d: %s", fd, strerror(errno));
		return -1;
	}

	if ((size_t)numread != amount) {
		fprintf(stderr, "read %zd bytes, expecting %zu bytes on fd %d\n", numread, amount, fd);
		return -1;
	}

	//fprintf(logfile, "read %zd bytes, expecting %zu bytes on fd %d\n", numread, amount, fd);
	return send(s, buf, amount, 0);
#endif
}

/* Sending reply. */
static void poll_send_reply(struct connection* conn)
{
	size_t nbytes = (size_t)(conn->reply_length - conn->reply_sent);
	ssize_t sent;

	assert(conn->state == SEND_REPLY);
	assert(!conn->header_only);

	errno = 0;
	assert(conn->reply_length >= conn->reply_sent);

	/*
	if (conn->reply_type == REPLY_FROMFILE) {
		fprintf( logfile, "send_from_file REPLY_FROMFILE %d\n", conn->reply_blksz );
	}
	*/

	if (conn->reply_type == REPLY_CACHED ||
		conn->reply_type == REPLY_GENERATED)
	{
		sent = send(
			conn->socket,
			conn->reply + conn->reply_start + conn->reply_sent,
			nbytes, 0
		);
	}
	else {
		if (conn->reply_blksz > 0) {
			if (conn->reply_blksz < nbytes)
				nbytes = conn->reply_blksz;

			if (conn->reply_sent < 1 && conn->reply_length > conn->reply_burst) {
				nbytes = conn->reply_burst;
			}
		}

		sent = send_from_file(
			conn->socket, conn->reply_fd,
			conn->reply_start + conn->reply_sent, nbytes
			//(size_t)(conn->reply_length - conn->reply_sent));
		);

		if (debug && (sent < 1)) {
			printf("send_from_file returned %lld (errno=%d %s)\n",
	    		(long long)sent, errno, strerror(errno));
        }
	}

	update_clock( conn );

	if ( debug ) {
		//fprintf(logfile,"poll_send_reply(%d) sent %d: %llu+[%llu-%llu] of %llu\n",
		printf("poll_send_reply(%d) sent %d: %llu+[%llu-%llu] of %llu\n",
		       conn->socket, (int)sent, llu(conn->reply_start),
		       llu(conn->reply_sent), llu(conn->reply_sent + sent - 1),
		       llu(conn->reply_length));
		//fflush( logfile );
	}

	/* handle any errors (-1) or closure (0) in send() */
	if (sent < 1) {
		if (sent == -1) {
			if (errno == EAGAIN) {
				if (debug)
				{ printf("poll_send_reply would have blocked\n"); }

				return;
			}

			if (debug)
			{ printf("send(%d) error: %s\n", conn->socket, strerror(errno)); }
		}
		else if (sent == 0) {
			if (debug)
			{ printf("send(%d) closure\n", conn->socket); }
		}

		conn->conn_close = 1;
		conn->state = DONE;
		return;
	}

	conn->reply_sent += sent;
	conn->total_sent += (size_t)sent;
	total_out += (size_t)sent;

	/* check if we're done sending */
	if (conn->reply_sent == conn->reply_length) {
		conn->state = DONE;
	}
}

/* Main loop of the httpd - a select() and then delegation to accept
 * connections, handle receiving of requests, and sending of replies.
 */
static void httpd_poll(void)
{
	fd_set recv_set, send_set;
	int max_fd, select_ret;
	struct connection* conn, *next;
	int bother_with_timeout = 0;
	struct timeval timeout;

	timeout.tv_sec = idletime;
	timeout.tv_usec = 0;

	FD_ZERO(&recv_set);
	FD_ZERO(&send_set);
	max_fd = 0;
	/* set recv/send fd_sets */
#define MAX_FD_SET(sock, fdset) { FD_SET(sock,fdset); \
                                max_fd = (max_fd<sock) ? sock : max_fd; }
	MAX_FD_SET(sockin, &recv_set);

	LIST_FOREACH_SAFE(conn, &connlist, entries, next) {

		poll_check_timeout(conn);

		switch (conn->state) {
		case RECV_REQUEST:
			MAX_FD_SET(conn->socket, &recv_set);
			bother_with_timeout = 1;
			break;

		case SEND_HEADER:
		case SEND_REPLY:
			MAX_FD_SET(conn->socket, &send_set);
			bother_with_timeout = 1;
			break;

		case DONE:
		default:
			/* do nothing */
			break;
		}
	}

#undef MAX_FD_SET
	/* -select- */
	select_ret = select(max_fd + 1, &recv_set, &send_set, NULL,
		(bother_with_timeout) ? &timeout : NULL);

	if (select_ret == 0) {
		if (!bother_with_timeout)
		{ err(1, "select() timed out"); }
		else
		{ return; }
	}

	if (select_ret == -1) {
		if (errno == EINTR)
		{ return; } /* interrupted by signal */
		else
		{ err(1, "select() failed"); }
	}

	/* update time */
	//now = time(NULL);
	gettimeofday( &chrono, 0L );

	now = chrono.tv_sec;

	/* poll connections that select() says need attention */
	if (FD_ISSET(sockin, &recv_set))
		accept_connection();

	LIST_FOREACH_SAFE(conn, &connlist, entries, next) {

		switch (conn->state) {
		case RECV_REQUEST:
			if (FD_ISSET(conn->socket, &recv_set))
			{ poll_recv_request(conn); }

			break;

		case SEND_HEADER:
			if (FD_ISSET(conn->socket, &send_set))
			{ poll_send_header(conn); }

			break;

		case SEND_REPLY:
			if (FD_ISSET(conn->socket, &send_set))
			{
				if ( !use_throttling || conn->reply_blksz < 1) {
					poll_send_reply(conn);
				} else if ( use_millisecs ) {
					if (memcmp( &chrono, &conn->last_chrono, CHRONO_SZ ) > 0) {
						poll_send_reply(conn);
					}
				} else if (now > conn->last_active) {
					poll_send_reply(conn);
				}
			}
			break;

		case DONE:
			/* (handled later; ignore for now as it's a valid state) */

			break;
		}

		if (conn->state == DONE) {

			/* clean out finished connection */
			if (conn->conn_close) {
				LIST_REMOVE(conn, entries);
				free_connection(conn);
				free_conn_tuples(conn);
				free(conn);
				num_connections -= 1;
			}
			else {
				recycle_connection(conn);
				/* and go right back to recv_request without going through
				 * select() again.
				 */
				poll_recv_request(conn);
			}
		}
	}
}

/* Daemonize helpers. */
static int lifeline[2] = { -1, -1 };
static int fd_null = -1;

static void daemonize_start(void)
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

		if (w == -1)
		{ err(1, "waitpid"); }
		else if (w == 0)
			/* child is running happily */
		{ exit(EXIT_SUCCESS); }
		else
			/* child init failed, pass on its exit status */
		{ exit(WEXITSTATUS(status)); }
	}

	/* else we are the child: continue initializing */
}

static void daemonize_finish(void)
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
static int pidfile_fd = -1;

static void pidfile_remove(void)
{
	if (unlink(pidfile_name) == -1)
	{ err(1, "unlink(pidfile) failed"); }

	/* if (flock(pidfile_fd, LOCK_UN) == -1)
	       err(1, "unlock(pidfile) failed"); */
	xclose(pidfile_fd);
	pidfile_fd = -1;
}

static int pidfile_read(void)
{
	char buf[16];
	int fd, i;
	long long pid;
	fd = open(pidfile_name, O_RDONLY);

	if (fd == -1)
	{ err(1, " after create failed"); }

	i = (int)read(fd, buf, sizeof(buf) - 1);

	if (i == -1)
	{ err(1, "read from pidfile failed"); }

	xclose(fd);

	buf[i] = '\0';

	if (!str_to_num(buf, &pid)) {
		err(1, "invalid pidfile contents: \"%s\"", buf);
	}

	return (int)pid;
}

static void pidfile_create(void)
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
static void stop_running(int sig unused)
{
	running = 0;
}

static uid_t get_dropto_uid(const char* name)
{
	struct passwd* p = getpwnam(name);

	if (p) { return p->pw_uid; }

	p = getpwuid((uid_t)xstr_to_num(name));

	if (p) { return p->pw_uid; }

	errx(1, "no such uid: `%s'", name);
}

static gid_t get_dropto_gid(const char* name)
{
	struct group* g = getgrnam(name);

	if (g) { return g->gr_gid; }

	g = getgrgid((gid_t)xstr_to_num(name));

	if (g) { return g->gr_gid; }

	errx(1, "no such gid: `%s'", name);
}

static void parse_commandline(const int argc, char* argv[])
{
	const char *cfgfile = config_file;
	const char *host = NULL;
	const char *url = NULL;
	char *rootdir = NULL;
	char *value = NULL;
	int len= 0, i = 0;
	int optidx = 1;

	memset( mimetypes, 0, sizeof(mimetypes) );

#ifdef ENABLE_PASSWORD
	memset( passwords, 0, sizeof(passwords) );
#endif

    inifile_total = load_cfgfile( cfgfile, &inibuf, inifile, MAX_TUPLES );
    if (!inifile_total) {
		errx(1, "Invalid ini settings file" );
	}

	rootdir = inisearch( "General/wwwroot", "/var/www/htdocs" );
	wwwroot = xstrdup(rootdir);

	wwwrealm = inisearch( "General/realm", "dawnhttpd.io" );
	wwwrealm = xstrdup(wwwrealm);

	if (!strcmp(wwwroot, "/") || !dir_exists(wwwroot))
		errx(1, "Invalid www rootdir specified !" );

	/* Strip ending slash. */
	if ((len = strlen(wwwroot)) > 0) {
		if (wwwroot[len-1] == '/') {
			wwwroot[len-1] = '\0';
		}
	}

	wwwrootlen = strlen(wwwroot);

#ifdef ENABLE_SLOCATE
	locate_dbpath = inisearch( "Locate/path", NULL );
	locate_maxhits = inisearch( "Locate/maximum", NULL );

	if ( locate_maxhits ) {
        int max = atoi(locate_maxhits);
        if (max < 25 || max > 2500) {
			errx(1, "Invalid locate search maximum");
        }
    }
#endif

	value = inisearch( "General/max-conn", "-1" );
	max_connections = (int)xstr_to_num( value );

	value = inisearch( "General/port", getuid() ? "8080" : "80" );
	bindport = (int)xstr_to_num( value );

	if (ini_evaluate( "General/use-ipv4", "yes", "yes" )) {
		bindaddr = inisearch( "General/ipv4-addr", "127.0.0.1" );
	} else {
		bindaddr = inisearch( "General/ipv6-addr", NULL );
		use_inet6 = 1;
	}

	want_daemon = ini_evaluate( "General/daemon", "yes", NULL );
	want_cache = ini_evaluate( "General/use-cache", "yes", NULL );
	want_chroot = ini_evaluate( "General/use-chroot", "yes", NULL );
	want_listing = ini_evaluate( "General/use-listing", "yes", "yes" );
	want_server_id = ini_evaluate( "General/use-server-id", "yes", NULL );
	mimefile_name = inisearch( "General/mimetypes", NULL );

	use_redirect = ini_evaluate( "Redirect/enabled", "yes", NULL );
	use_throttling = ini_evaluate( "Throttle/enabled", "yes", NULL );
	use_millisecs = ini_evaluate( "Throttle/millisecs", "yes", NULL );

	value = inisearch( "Throttle/burst", "2048" );
	burst_size = (int)xstr_to_num( value ) * 1024;

#ifdef ENABLE_PASSWORD
	use_password = ini_evaluate( "Password/enabled", "yes", NULL );
	password_file = inisearch( "Password/filename", NULL );

	if ((password_salt = inisearch( "Password/salt", NULL )))
		password_saltlen = strlen( password_salt );

    if (use_password && !password_salt)
        errx(1, "Password salt missing");
#endif

	if (ini_evaluate( "Dropto/enabled", "yes", NULL )) {

		if ((value = inisearch( "Dropto/user", NULL )))
			drop_uid = get_dropto_uid( value );

		if ((value = inisearch( "Dropto/group", NULL )))
			drop_gid = get_dropto_gid( value );
	}

	/* walk through the remainder of the arguments (if any) */
	for (i = optidx; i < argc; i++) {

		if (strcmp(argv[i], "--port") == 0) {
			if (++i >= argc)
			{ errx(1, "missing number after --port"); }
			bindport = (uint16_t)xstr_to_num(argv[i]);
		}
		else if (strcmp(argv[i], "--addr") == 0) {
			if (++i >= argc)
			{ errx(1, "missing ip after --addr"); }
			bindaddr = argv[i];
		}
		else if (strcmp(argv[i], "--maxconn") == 0) {
			if (++i >= argc)
			{ errx(1, "missing number after --maxconn"); }
			max_connections = (int)xstr_to_num(argv[i]);
		}
		else if (strcmp(argv[i], "--stdout") == 0) {
			logfile_name = NULL;
		}
		else if (strcmp(argv[i], "--logfile") == 0) {
			if (++i >= argc)
			{ errx(1, "missing logfile after --log"); }
			logfile_name = argv[i];
		}
#ifdef ENABLE_PIDFILE
		else if (strcmp(argv[i], "--pidfile") == 0) {
			if (++i >= argc)
			{ errx(1, "missing filename after --pidfile"); }
			pidfile_name = xstrdup(argv[i]);
		}
#endif
		else if (strcmp(argv[i], "--no-daemon") == 0) {
			want_daemon = 0;
		}
		else if (strcmp(argv[i], "--no-keepalive") == 0) {
			want_keepalive = 0;
		}
		else if (strcmp(argv[i], "--chroot") == 0) {
			want_chroot = 1;
		}
#if 0
		else if (strcmp(argv[i], "--no-server-id") == 0) {
			want_server_id = 0;
		}
		else if (strcmp(argv[i], "--no-listing") == 0) {
			want_listing = 1;
		}
		else if (strcmp(argv[i], "--index") == 0) {
			if (++i >= argc)
			{ errx(1, "missing filename after --index"); }

			index_name = argv[i];
		}
		else if (strcmp(argv[i], "--post") == 0) {
			if (++i >= argc)
			{ errx(1, "missing filename after --post"); }
	        postfile_name = argv[i];
		}
		else if (strcmp(argv[i], "--mimetypes") == 0) {
			if (++i >= argc)
			{ errx(1, "missing filename after --mimetypes"); }
	        mimefile_name = argv[i];
		}
		else if (strcmp(argv[i], "--forward") == 0) {

			if (++i >= argc)
			{ errx(1, "missing host after --forward"); }
			host = argv[i];

			if (++i >= argc)
			{ errx(1, "missing url after --forward"); }
			url = argv[i];

			if (!add_redirect( host, url )) {
				errx(1, "too many redirects --forward");
			}
		}
		else if (strcmp(argv[i], "--default-mimetype") == 0) {
			if (++i >= argc)
			{ errx(1, "missing string after --default-mimetype"); }
			default_mimetype = argv[i];
		}
#endif
		else if (strcmp(argv[i], "--uid") == 0) {

			if (++i >= argc)
			{ errx(1, "missing uid after --uid"); }

			drop_uid = get_dropto_uid( argv[i] );
		}
		else if (strcmp(argv[i], "--gid") == 0) {

			if (++i >= argc)
			{ errx(1, "missing gid after --gid"); }

			drop_gid = get_dropto_gid( argv[i] );
		}
		else if (strcmp(argv[i], "--accf") == 0) {
			want_accf = 1;
		}
#ifdef ENABLE_GUESTBOOK
		else if (strcmp(argv[i], "--guestbook") == 0) {

			const char* gbook_filename;
			const char* gbook_template;

			if (++i >= argc)
			{ errx(1, "missing host after --guestbook"); }
			gbook_template = argv[i];

			if (++i >= argc)
			{ errx(1, "missing url after --guestbook"); }
			gbook_filename = argv[i];

            guestbook_file = fopen(gbook_filename, "ab");

            if (guestbook_file == NULL) {
                errx(1, "failed to open guestbook file");
            }

			if (!load_file( gbook_template, &guestbook_template, (1 << 12))) {
				errx(1, "invalid guestbook template file --guestbook");
			}
		}
#endif
		else if (strcmp(argv[i], "--forward-all") == 0) {

			if (++i >= argc)
			{ errx(1, "missing url after --forward-all"); }

			redirect_all_url = argv[i];
		}
#ifdef ENABLE_INET6
		else if (strcmp(argv[i], "--ipv6") == 0) {
			use_inet6 = 1;
		}
#endif
		else
		{ errx(1, "unknown argument `%s'", argv[i]); }
	}

	index_name_len = strlen( index_name );

	if ( mimefile_name ) {
    	mimetypes_total = load_cfgfile( mimefile_name, &mimebuf, mimetypes, MAX_TUPLES );
    	if (!mimetypes_total) {
			errx(1, "Invalid mimetype file");
		}
	}

#ifdef ENABLE_PASSWORD
	if ( password_file ) {
		passwords_total = load_cfgfile( password_file, &passwdbuf, passwords, MAX_TUPLES );
    	if (!passwords_total) {
			errx(1, "Invalid password file");
		}
	}
#endif
}

void init_memcache()
{
	struct stat filestat;
	char path[256]={'\0'};
	char key[32]={'\0'};
	char *fname = NULL;
	char *buf = NULL;
    int nread = 0;
	int i = 0;

	for (i=1; i < MAX_CACHE; i++) {

		sprintf( key, "Memcache/%d", i ); 

		fname = inisearch( key, NULL );
		if ( !fname ) { break; }

		sprintf( path, "%s/%s", wwwroot, fname ); 

		if (lstat( path, &filestat) != 0) {
            err(1, "failed to stat cache file (\"%s\")", path);
			break;
		}

    	nread = load_file( path, &buf, (1 << 17) );

		if (nread < 1) {
            err(1, "failed to read cache file (\"%s\")", path);
			break;
		}

		memcache[i-1] = xmalloc(sizeof(struct data_bucket));
		memcache[i-1]->key = fname;
		memcache[i-1]->value = buf;
		memcache[i-1]->size = nread;
		memcache[i-1]->lastmod = filestat.st_mtime;

		buf = NULL;
	}

	memcache_total = i-1;

	if (memcache_total > 1)
		bucket_sort();

	//fprintf(stderr, "memcache_total %d\n", memcache_total );
}

/* Execution starts here. */
int main(int argc, char** argv)
{
	int rc = 0, i = 0;

	if (argv[1]) {
		if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
			usage(argv[0]);
			exit(0);
		}
	}

	now = time(NULL);
	logfile = stdout;

	parse_commandline( argc, argv );

	if (logfile_name == NULL) {
	    logfile = stdout;
	} else {
		logfile = fopen( logfile_name, "ab" );
		if (logfile == NULL) {
            errx(1, "failed to open log file (\"%s\")", logfile_name);
		}
	}

	fprintf( logfile, "\n%s, %s.\n", pkgname, copyright );
	fprintf( logfile, "Using WWWROOT '%s'\n", wwwroot );
	fprintf( logfile, "Started on %s\n", ctime(&now) );

	parse_default_extension_map();

	xasprintf(&keep_alive_field, "Keep-Alive: timeout=%d\r\n", idletime);

	if (want_server_id) {
        xasprintf(&server_hdr, "Server: %s\r\n", pkgname);
    } else {
        server_hdr = xstrdup("");
    }

	for (i=0; i<3 && !rc; i++)
		rc = init_sockin( i >= 2 );

	if ( want_cache ) { init_memcache(); }

	if ( want_daemon ) { daemonize_start(); }

	/* signals */
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
	{ err(1, "signal(ignore SIGPIPE)"); }

	if (signal(SIGINT, stop_running) == SIG_ERR)
	{ err(1, "signal(SIGINT)"); }

	if (signal(SIGTERM, stop_running) == SIG_ERR)
	{ err(1, "signal(SIGTERM)"); }

	if (chdir(wwwroot) == -1)
	{ err(1, "chdir(%s)", wwwroot); }

	/* security */
	if (want_chroot) {

		tzset(); /* read /etc/localtime before we chroot */

		if (chroot(wwwroot) == -1)
		{ err(1, "chroot(%s)", wwwroot); }

		fprintf( logfile, "chrooted to `%s'\n", wwwroot);
		wwwroot[0] = '\0'; /* empty string */
	}

	if (drop_gid != INVALID_GID) {
		gid_t list[1];
		list[0] = drop_gid;

		if (setgroups(1, list) == -1)
		{ err(1, "setgroups([%d])", (int)drop_gid); }

		if (setgid(drop_gid) == -1)
		{ err(1, "setgid(%d)", (int)drop_gid); }

		fprintf( logfile, "set gid to %d\n", (int)drop_gid);
	}

	if (drop_uid != INVALID_UID) {
		if (setuid(drop_uid) == -1)
		{ err(1, "setuid(%d)", (int)drop_uid); }

		fprintf( logfile, "set uid to %d\n", (int)drop_uid);
	}

#ifdef ENABLE_PIDFILE
	if (want_chroot) {
		if (pidfile_name) { free(pidfile_name); }
		xasprintf( &pidfile_name, "%s/dawnhttpd.pid", wwwroot);
	} else if ( !pidfile_name) {
		xasprintf( &pidfile_name, "%s", "/var/log/dawnhttpd.pid");
	}

	if (pidfile_name) { pidfile_create(); }
#endif

	if (want_daemon) { daemonize_finish(); }

	/* main loop */
	while (running) { httpd_poll(); }

	/* clean exit */
	xclose(sockin);

#ifdef ENABLE_GUESTBOOK
	if (guestbook_file != NULL) {
        fflush(guestbook_file);
        fclose(guestbook_file);
    }
#endif

	//now = time(NULL);
	gettimeofday( &chrono, 0L );

	now = chrono.tv_sec;

	/* usage stats */
	{
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
	{
		struct connection* conn, *next;
		LIST_FOREACH_SAFE(conn, &connlist, entries, next) {
			LIST_REMOVE(conn, entries);
			free_connection(conn);
			free_conn_tuples(conn);
			free(conn);
		}
	}

#ifdef ENABLE_PIDFILE
	if (pidfile_name != NULL) {
        pidfile_remove();
		free(pidfile_name);
    }
#endif

	if (logfile != NULL) {
        fflush(logfile);
        fclose(logfile);
    }

	/* free the mallocs */
	{
#ifdef ENABLE_PASSWORD
        free_tuples( passwords );
#endif
        free_tuples( mimetypes );
        free_tuples( inifile );

        //free(passbuf);
        free(mimebuf);
        free(inibuf);

		free(keep_alive_field);
		free(wwwrealm);
		free(wwwroot);
		free(server_hdr);
	}
	return 0;
}

/* vim:set tabstop=4 shiftwidth=4 expandtab tw=78: */
