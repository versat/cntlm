/*
 * These are helping routines for the main module of CNTLM
 *
 * CNTLM is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * CNTLM is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
 * St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * Copyright (c) 2007 David Kubicek
 *
 */

#ifndef UTILS_H
#define UTILS_H

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
# include <sys/param.h>
#endif
#include <pthread.h>
#include <netinet/in.h>

#include "config/config.h"

#define BUFSIZE			4096
#define MINIBUF_SIZE		64
/*
* Longest password that appears to be supported in a Microsoft authn/authz implementation is 256 characters;
* therefore support passwords up to 256 characters plus null terminator.
* source: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-combined-policy#azure-ad-password-policies
*/
#define PASSWORD_BUFSIZE	257
#define HOST_BUFSIZE	260
#define VAL(var, type, offset)	*((type *)(var+offset))
#define MEM(var, type, offset)	(type *)(var+offset)

#if !defined(__FreeBSD__) && !defined(__NetBSD__) && !defined(__OpenBSD__)
# define MIN(a, b)		((a) < (b) ? (a) : (b))
# define MAX(a, b)		((a) > (b) ? (a) : (b))
#endif

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/*
 * Solaris doesn't have LOG_PERROR
 */
#ifndef LOG_PERROR
# define LOG_PERROR	LOG_CONS
#endif

/*
 * Two single-linked list types. First is for storing headers,
 * second keeps a list of finished threads or cached connections.
 * Each has a different set of manipulation routines.
 */
typedef struct hlist_s *hlist_t;
typedef const struct hlist_s *hlist_const_t;
struct hlist_s {
	char *key;
	char *value;
	int islist;
	struct hlist_s *next;
};

typedef struct plist_s *plist_t;
typedef const struct plist_s *plist_const_t;
struct plist_s {
	unsigned long key;
	void *aux;
	struct plist_s *next;
};

typedef enum {
	HLIST_NOALLOC = 0,
	HLIST_ALLOC
} hlist_add_t;

/*
 * Request/response data structure. Complete and parsed req/res is
 * kept in this. See below for (de)allocation routines.
 */
typedef struct rr_data_s *rr_data_t;
typedef const struct rr_data_s *rr_data_const_t;
struct rr_data_s {
	int req;
	hlist_t headers;
	int code;
	int skip_http;
	int body_len;
	int empty;
	int port;
	int http_version;
	char *method;
	char *url;
	char *rel_url;
	char *hostname;
	char *http;
	char *msg;
	char *body;
	char *errmsg;
};

/*
 * This structure can represent a sockaddr or
 * an AF_INET (ipv4) sockaddr or an AF_INET6 (ipv6) sockaddr
 */
union sock_addr {
	struct sockaddr addr;
	struct sockaddr_in addr_in;
	struct sockaddr_in6 addr_in6;
};

/*
 * This is used in main() for passing arguments to the thread.
 */
struct thread_arg_s {
	int fd;
	char *target;
	union sock_addr addr;
};

/*
 * Returns the string representation of an inet or inet6 address (determined by the family).
 * (sa) must be a pointer to sockaddr_in or sockaddr_in6.
 * (s) must be a char array of at least INET6_ADDRSTRLEN size.
 * (len) is the length of (s).
 */
#define INET_NTOP(sa, s, len)	\
	(inet_ntop(((struct sockaddr*)(sa))->sa_family, \
		((struct sockaddr*)(sa))->sa_family == AF_INET ? (void*)&((struct sockaddr_in*)(sa))->sin_addr : (void*)&((struct sockaddr_in6*)(sa))->sin6_addr, (s), (len)))

/*
 * Returns the port of an inet or inet6 address (determined by the family).
 * (sa) must be a pointer to sockaddr_in or sockaddr_in6.
 */
#define INET_PORT(sa) \
	(((struct sockaddr*)(sa))->sa_family == AF_INET ? ((struct sockaddr_in*)(sa))->sin_port : ((struct sockaddr_in6*)(sa))->sin6_port)

extern void myexit(int rc) __attribute__((noreturn));
extern void croak(const char *msg, const int console) __attribute__((noreturn));

extern plist_t plist_add(plist_t list, unsigned long key, void *aux);
extern plist_t plist_del(plist_t list, const unsigned long key);
extern int plist_in(plist_const_t list, const unsigned long key) __attribute__((warn_unused_result));
extern void plist_dump(plist_const_t list);
extern char *plist_get(plist_const_t list, const unsigned long key) __attribute__((warn_unused_result));
extern int plist_pop(plist_t *list, void **aux);
extern int plist_count(plist_const_t list) __attribute__((warn_unused_result));
extern plist_t plist_free(plist_t list);

extern hlist_t hlist_add(hlist_t list, char *key, char *value, hlist_add_t allockey, hlist_add_t allocvalue);
extern hlist_t hlist_dup(hlist_const_t list) __attribute__((warn_unused_result));
extern hlist_t hlist_del(hlist_t list, const char *key);
extern hlist_t hlist_mod(hlist_t list, char *key, char *value, int add);
extern int hlist_in(hlist_const_t list, const char *key) __attribute__((warn_unused_result));
extern int hlist_count(hlist_const_t list) __attribute__((warn_unused_result));
extern char *hlist_get(hlist_const_t list, const char *key) __attribute__((warn_unused_result));
extern int hlist_subcmp(hlist_const_t list, const char *key, const char *substr) __attribute__((warn_unused_result));
extern int hlist_subcmp_all(hlist_const_t list, const char *key, const char *substr) __attribute__((warn_unused_result));
extern hlist_t hlist_free(hlist_t list);
extern void hlist_dump(hlist_const_t list);

extern char *substr(const char *src, int pos, int len) __attribute__((warn_unused_result));
#if config_strlcpy == 0
extern size_t strlcpy(char *dst, const char *src, size_t siz);
#endif
#if config_strlcat == 0
extern size_t strlcat(char *dst, const char *src, size_t siz);
#endif
extern char *trimr(char * const buf);
extern char *lowercase(char * const str);
extern char *uppercase(char * const str);
extern size_t unicode(char **dst, const char * const src);
extern void *zmalloc(size_t size) __attribute__((warn_unused_result, malloc, alloc_size(1)));
extern char *urlencode(const char * const str) __attribute__((warn_unused_result));

extern rr_data_t new_rr_data(void) __attribute__((warn_unused_result));
extern rr_data_t copy_rr_data(rr_data_t dst, const rr_data_const_t src);
extern rr_data_t dup_rr_data(const rr_data_const_t data) __attribute__((warn_unused_result));
extern rr_data_t reset_rr_data(rr_data_t data);
extern void free_rr_data(rr_data_t * data);

extern char *printmem(const char * const src, const size_t len, const int bitwidth) __attribute__((warn_unused_result));
extern char *scanmem(const char * const src, const int bitwidth) __attribute__((warn_unused_result));

extern int is_memory_all_zero(const void * const p_memory, const size_t length) __attribute__((warn_unused_result, pure));

extern void to_base64(unsigned char *out, const unsigned char *in, size_t len, size_t olen);
extern int from_base64(char *out, const char *in);

extern uint64_t getrandom64(void) __attribute__((warn_unused_result));

extern ssize_t write_wrapper(int fildes, const void *buf, const size_t nbyte);

extern void compat_memset_s( void *dest, size_t destsz, char ch, size_t count );

#if config_strdup == 0
extern char *strdup(const char *src)  __attribute__((warn_unused_result));
#endif

#endif /* UTILS_H */
