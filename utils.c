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

#include "config/config.h"

#if config_memset_s == 1
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <syslog.h>
#include <assert.h>
#ifdef __CYGWIN__
#include <windows.h>
#include <wincrypt.h>
#endif

#include "utils.h"
#include "swap.h"
#include "socket.h"
#include "globals.h"

static const char hextab[17] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 0};
static const int hexindex[128] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,
	-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};

void myexit(int rc) {
	if (rc)
		fprintf(stderr, "Exiting with error. Check daemon logs or run with -v.\n");

	exit(rc);
}

void croak(const char *msg, const int console) {
	if (console)
		printf("%s", msg);
	else
		syslog(LOG_ERR, "%s", msg);

	myexit(1);
}

/*
 * Add a new item to a list. Every plist_t variable must be
 * initialized to NULL (or pass NULL for "list" when adding
 * the first item). This is for simplicity's sake (we don't
 * need any plist_new).
 *
 * This list type allows to store an arbitrary pointer
 * associating it with the key.
 */
plist_t plist_add(plist_t list, const unsigned long key, void *aux) {
	plist_t tmp;
	plist_t t = list;

	tmp = zmalloc(sizeof(struct plist_s));
	tmp->key = key;
	tmp->aux = aux;
	tmp->next = NULL;

	if (list == NULL)
		return tmp;

	while (t->next)
		t = t->next;

	t->next = tmp;

	return list;
}

/*
 * Delete an item from the list, possibly returning NULL when
 * the list is empty or nothing was found.
 */
plist_t plist_del(plist_t list, const unsigned long key) {
	plist_t ot = NULL;
	plist_t t = list;

	while (t) {
		if (t->key == key)
			break;
		ot = t;
		t = t->next;
	}

	if (t) {
		plist_t tmp = t->next;

		if (t->aux)
			free(t->aux);
		free(t);
		if (ot == NULL)
			return tmp;

		ot->next = tmp;
	}

	return list;
}

/*
 * Return true if an item is present in the list.
 */
int plist_in(plist_const_t list, const unsigned long key) {
	plist_const_t t = list;

	while (t) {
		if (t->key == key)
			break;
		t = t->next;
	}

	return (t != NULL);
}

/*
 * For debugging purposes - dump the entire contents
 * of a list.
 */
void plist_dump(plist_const_t list) {
	plist_const_t t;

	t = list;
	while (t) {
		printf("List data: %lu => 0x%8p\n", t->key, t->aux);
		t = t->next;
	}
}

/*
 * Return the pointer associated with the key.
 */
char *plist_get(plist_const_t list, const unsigned long key) {
	plist_const_t t = list;

	while (t) {
		if (t->key == key)
			break;
		t = t->next;
	}

	return (t == NULL ? NULL : t->aux);
}

/*
 * Scan the list for an open descriptor (socket), possibly
 * discarding all closed ones on the way. Return the first
 * match.
 *
 * Use this method only for lists of descriptors!
 *
 * In conjunction with plist_add, the list behaves as a FIFO.
 * This feature is used for rotating cached connections in the
 * list, so that none is left too long unused (proxy timeout).
 *
 * Returns key value (descriptor) and if aux != NULL, *aux gets
 * aux pointer value (which caller must free if != NULL).
 */

int plist_pop(plist_t *list, void **aux) {
	plist_t tmp;
	plist_t t;
	int id = 0;
	int ok = 0;
	void *a = NULL;

	if (list == NULL || *list == NULL)
		return 0;

	t = *list;
	while (!ok && t) {
		id = (int)t->key;
		a = t->aux;
		tmp = t->next;

		if (so_closed(id)) {
			close(id);
			if (t->aux)
				free(t->aux);
		} else
			ok = 1;

		free(t);
		t = tmp;
	}

	*list = t;

	if (ok) {
		if (aux != NULL)
			*aux = a;
		return id;
	}

	return 0;
}

/*
 * Return the number of items in a list.
 */
int plist_count(plist_const_t list) {
	plist_const_t t = list;
	int rc = 0;

	while (t) {
		rc++;
		t = t->next;
	}

	return rc;
}

/*
 * Free the list.
 */
plist_t plist_free(plist_t list) {
	plist_t t = list;

	while (list) {
		t = list->next;
		if (list->aux)
			free(list->aux);
		free(list);
		list = t;
	}

	return NULL;
}

/*
 * The same as plist_add. Here we have two other arguments.
 * They are boolean flags - HLIST_ALLOC means to duplicate a
 * key/value, HLIST_NOALLOC means to store the pointer directly.
 *
 * Caller decides this on a by-call basis. Part of the manipulation
 * routines is a "free". That method always deallocates both the
 * key and the value. So for static or temporary keys/values,
 * the caller can instruct us to duplicate the necessary amount
 * of heap. This mechanism is used to minimize memory-related
 * bugs throughout the code and tons of free's.
 */
hlist_t hlist_add(hlist_t list, char *key, char *value, hlist_add_t allockey, hlist_add_t allocvalue) {
	hlist_t tmp;
	hlist_t t = list;

	if (key == NULL || value == NULL)
		return list;

	tmp = zmalloc(sizeof(struct hlist_s));
	tmp->key = (allockey == HLIST_ALLOC ? strdup(key) : key);
	tmp->value = (allocvalue == HLIST_ALLOC ? strdup(value) : value);
	tmp->next = NULL;
	tmp->islist = 0;

	if (list == NULL)
		return tmp;

	while (t->next)
		t = t->next;

	t->next = tmp;

	return list;
}

/*
 * Return a duplicate of the list (copy).
 */
hlist_t hlist_dup(hlist_const_t list) {
	hlist_t tmp = NULL;
	hlist_const_t t = list;

	while (t) {
		tmp = hlist_add(tmp, t->key, t->value, HLIST_ALLOC, HLIST_ALLOC);
		t = t->next;
	}

	return tmp;
}

/*
 * Remove an item from the list.
 */
hlist_t hlist_del(hlist_t list, const char *key) {
	hlist_t ot = NULL;
	hlist_t t = list;

	while (t) {
		if (!strcasecmp(t->key, key))
			break;
		ot = t;
		t = t->next;
	}

	if (t) {
		hlist_t tmp = t->next;

		free(t->key);
		free(t->value);
		free(t);

		if (ot == NULL)
			return tmp;

		ot->next = tmp;
	}

	return list;
}

/*
 * Change the value of a key. If add is true, we store it in the
 * list if the key is not found. Unlike hlist_add, which offers
 * pointer storage or memory duplication for both the key and the
 * value separately, hlist_mod always duplicates.
 *
 * Used to add a header, which might already be present.
 */
hlist_t hlist_mod(hlist_t list, char *key, char *value, int add) {
	hlist_t t = list;

	while (t) {
		if (!strcasecmp(t->key, key))
			break;
		t = t->next;
	}

	if (t) {
		free(t->value);
		t->value = strdup(value);
	} else if (add) {
		list = hlist_add(list, key, value, HLIST_ALLOC, HLIST_ALLOC);
	}

	return list;
}

/*
 * Return true if the key is in the list.
 */
int hlist_in(hlist_const_t list, const char *key) {
	hlist_const_t t = list;

	while (t) {
		if (!strcasecmp(t->key, key))
			break;
		t = t->next;
	}

	return (t != NULL);
}

/*
 * Return the number of items in a list.
 */
int hlist_count(hlist_const_t list) {
	hlist_const_t t = list;
	int rc = 0;

	while (t) {
		rc++;
		t = t->next;
	}

	return rc;
}

/*
 * Return the value for the key.
 */
char *hlist_get(hlist_const_t list, const char *key) {
	hlist_const_t t = list;

	while (t) {
		if (!strcasecmp(t->key, key))
			break;
		t = t->next;
	}

	return (t == NULL ? NULL : t->value);
}

/*
 * Test if substr is part of the header's value.
 * Both case-insensitive.
 */
int hlist_subcmp(hlist_const_t list, const char *key, const char *substr) {
	int found = 0;
	char *tmp;
	char *low;

	low = strdup(substr);
	lowercase(low);
	tmp = hlist_get(list, key);
	if (tmp) {
		tmp = strdup(tmp);
		lowercase(tmp);
		if (strstr(tmp, low))
			found = 1;

		free(tmp);
	}

	free(low);
	return found;
}

/*
 * Test if substr is part of the header's value.
 * Both case-insensitive, checks all headers, not just first one.
 */
int hlist_subcmp_all(hlist_const_t list, const char *key, const char *substr) {
	hlist_const_t t = list;
	int found = 0;
	char *tmp;
	char *low;

	assert(key != NULL);
	assert(substr != NULL);

	low = strdup(substr);
	lowercase(low);
	while (t) {
		if (!strcasecmp(t->key, key)) {
			tmp = strdup(t->value);
			lowercase(tmp);
			if (strstr(tmp, low))
				found = 1;

			free(tmp);
		}
		t = t->next;
	}

	free(low);
	return found;
}

/*
 * Free the list. For more about list memory management,
 * see hlist_add.
 */
hlist_t hlist_free(hlist_t list) {
	hlist_t t = list;

	while (list) {
		t = list->next;

		free(list->key);
		free(list->value);
		free(list);

		list = t;
	}

	return NULL;
}

/*
 * This is for debugging purposes.
 */
void hlist_dump(hlist_const_t list) {
	hlist_const_t t;

	t = list;
	while (t) {
		printf("%-30s => %s\n", t->key, t->value);
		t = t->next;
	}
}

/*
 * Standard substr. To prevent modification of the source
 * (terminating \x0), return the result in a new memory.
 */
char *substr(const char *src, int pos, int len) {
	int min_len;
	char *tmp;

	assert(src != NULL);
	assert(pos >= 0);
	assert(len >= 0);

	if (len == 0)
		len = (int)strlen(src);

	min_len = MIN(len, (int)strlen(src)-pos);
	if (min_len <= 0)
		return zmalloc(1);

	tmp = zmalloc(min_len+1);
	strlcpy(tmp, src+pos, min_len+1);

	return tmp;
}

/*
 * Allocate memory and initialize a new rr_data_t structure.
 */
rr_data_t new_rr_data(void) {
	rr_data_t data;

	data = zmalloc(sizeof(struct rr_data_s));
	data->req = 0;
	data->code = 0;
	data->skip_http = 0;
	data->body_len = 0;
	data->empty = 1;
	data->port = 0;
	data->http_version = -1;
	data->headers = NULL;
	data->method = NULL;
	data->url = NULL;
	data->rel_url = NULL;
	data->hostname = NULL;
	data->http = NULL;
	data->msg = NULL;
	data->body = NULL;
	data->errmsg = NULL; 			/* for static strings - we don't free, dup, nor copy */

	return data;
}

/*
 * Copy the req/res data.
 */
rr_data_t copy_rr_data(rr_data_t dst, const rr_data_const_t src) {
	if (dst == NULL) {
		fprintf(stderr, "Internal error in copy_rr_data: Pointer dst is NULL\n");
		assert(0);
		return NULL;
	}
	if (src == NULL) {
		fprintf(stderr, "Internal error in copy_rr_data: Pointer src is NULL\n");
		assert(0);
		return NULL;
	}

	reset_rr_data(dst);
	dst->req = src->req;
	dst->code = src->code;
	dst->skip_http = src->skip_http;
	dst->body_len = src->body_len;
	dst->empty = src->empty;
	dst->port = src->port;
	dst->http_version = src->http_version;

	if (src->headers)
		dst->headers = hlist_dup(src->headers);
	if (src->method)
		dst->method = strdup(src->method);
	if (src->url)
		dst->url = strdup(src->url);
	if (src->rel_url)
		dst->rel_url = strdup(src->rel_url);
	if (src->hostname)
		dst->hostname = strdup(src->hostname);
	if (src->http)
		dst->http = strdup(src->http);
	if (src->msg)
		dst->msg = strdup(src->msg);
	if (src->body && src->body_len > 0) {
		dst->body = zmalloc(src->body_len);
		memcpy(dst->body, src->body, src->body_len);
	}

	return dst;
}

/*
 * Duplicate the req/res data.
 */
rr_data_t dup_rr_data(const rr_data_const_t data) {
	rr_data_t tmp;

	if (data == NULL) {
		fprintf(stderr, "Internal error in dup_rr_data: Pointer data is NULL\n");
		assert(0);
		return NULL;
	}

	tmp = new_rr_data();
	return copy_rr_data(tmp, data);
}

/*
 * Reset, freeing if necessary
 */
rr_data_t reset_rr_data(rr_data_t data) {
	if (data == NULL) {
		fprintf(stderr, "Internal error in reset_rr_data: Pointer data is NULL\n");
		assert(0);
		return NULL;
	}

	data->req = 0;
	data->code = 0;
	data->skip_http = 0;
	data->body_len = 0;
	data->empty = 1;
	data->port = 0;
	data->http_version = -1;

	if (data->headers) hlist_free(data->headers);
	if (data->method) free(data->method);
	if (data->url) free(data->url);
	if (data->rel_url) free(data->rel_url);
	if (data->hostname) free(data->hostname);
	if (data->http) free(data->http);
	if (data->msg) free(data->msg);
	if (data->body) free(data->body);

	data->headers = NULL;
	data->method = NULL;
	data->url = NULL;
	data->rel_url = NULL;
	data->hostname = NULL;
	data->http = NULL;
	data->msg = NULL;
	data->body = NULL;
	data->errmsg = NULL;

	return data;
}

/*
 * Free rr_data_t structure. We also take care of freeing
 * the memory of its members.
 */
void free_rr_data(rr_data_t * pdata) {
	if (pdata == NULL) {
		fprintf(stderr, "Internal error in free_rr_data: Pointer pdata is NULL\n");
		assert(0);
		return;
	}
	rr_data_t data = *pdata;
	if (data == NULL)
		return;

	if (data->headers) hlist_free(data->headers);
	if (data->method) free(data->method);
	if (data->url) free(data->url);
	if (data->rel_url) free(data->rel_url);
	if (data->hostname) free(data->hostname);
	if (data->http) free(data->http);
	if (data->msg) free(data->msg);
	if (data->body) free(data->body);

	free(data);
	data = NULL;
}

/*
 * Cut the whitespace at the end of a string.
 */
char *trimr(char * const buf) {
	ssize_t i;

	assert(buf != NULL);

	for (i = strlen(buf)-1; i >= 0 && isspace((u_char)buf[i]); --i);

	buf[i+1] = 0;

	return buf;
}

#if config_strdup == 0
/*
 * Our implementation of non-POSIX strdup()
 */
char *strdup(const char *src) {
	size_t len;
	char *tmp;

	if (!src)
		return NULL;

	len = strlen(src)+1;
	tmp = calloc(1, len);
	memcpy(tmp, src, len-1);

	return tmp;
}
#endif

#if config_strlcpy == 0
/*
 * More intuitive version of strncpy with string termination
 * from OpenBSD
 */
size_t strlcpy(char *dst, const char *src, size_t siz) {
	char *d = dst;
	const char *s = src;
	size_t n = siz;

	assert(dst != NULL);
	assert(src != NULL);

	/* Copy as many bytes as will fit */
	if (n != 0) {
		while (--n != 0) {
			if ((*d++ = *s++) == '\0')
				break;
		}
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (siz != 0)
			*d = '\0';		/* NUL-terminate dst */
		while (*s++);
	}

	return (s - src - 1);	/* count does not include NUL */
}
#endif

#if config_strlcat == 0
/*
 * More intuitive version of strncat with string termination
 * from OpenBSD
 */
size_t strlcat(char *dst, const char *src, size_t siz) {
	char *d = dst;
	const char *s = src;
	size_t n = siz;
	size_t dlen;

	assert(dst != NULL);
	assert(src != NULL);
	assert(siz > 0);

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
		d++;

	dlen = d - dst;
	n = siz - dlen;

	if (n == 0)
		return(dlen + strlen(s));

	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return (dlen + (s - src));	/* count does not include NUL */
}
#endif

/*
 * Allocates memory and makes sure it is zero initialized.
 */
void *zmalloc(size_t size) {
	void *tmp = calloc(1, size);
	return tmp;
}

/*
 * Self-explanatory.
 */
char *lowercase(char * const str) {
	assert(str != NULL);

	for (size_t i = 0; i < strlen(str); ++i)
		str[i] = (char)tolower(str[i]);

	return str;
}

/*
 * Self-explanatory.
 */
char *uppercase(char * const str) {
	assert(str != NULL);

	for (size_t i = 0; i < strlen(str); ++i)
		str[i] = (char)toupper(str[i]);

	return str;
}

size_t unicode(char **dst, const char * const src) {
	char *tmp;
	size_t l;

	if (!src) {
		*dst = NULL;
		return 0;
	}

	l = MIN(BUFSIZE, strlen(src));
	tmp = zmalloc(2*l);
	for (size_t i = 0; i < l; ++i)
		tmp[2*i] = src[i];

	*dst = tmp;
	return 2*l;
}

char *urlencode(const char * const str) {
	char *tmp;
	size_t i;
	size_t pos;

	assert(str != NULL);

	const size_t str_length = strlen(str);
	const size_t tmp_length = str_length * 3 + 1;
	tmp = zmalloc(tmp_length);
	for (pos = 0, i = 0; i < str_length; ++i) {
		if (isdigit((u_char)str[i]) || (tolower(str[i]) >= 'a' && tolower(str[i]) <= 'z') || str[i] == '.' || str[i] == '-' || str[i] == '_' || str[i] == '~') {
			tmp[pos] = str[i];
			++pos;
		} else {
			snprintf(tmp+pos, tmp_length - pos, "%%%X", (unsigned char)str[i]);
			pos += 3;
		}
	}

	return tmp;
}

char *printmem(const char * const src, const size_t len, const int bitwidth) {
	char *tmp;

	tmp = zmalloc(2*len+1);
	for (size_t i = 0; i < len; ++i) {
		uint8_t val = (uint8_t)src[i] & (0xFF >> (8-bitwidth));
		tmp[i*2] = hextab[val >> 4];
		tmp[i*2+1] = hextab[val & 0x0F];
	}

	return tmp;
}

char *scanmem(const char * const src, const int bitwidth) {
	size_t i;
	size_t bytes;
	char *tmp;

	if (strlen(src) % 2)
		return NULL;

	bytes = strlen(src)/2;
	tmp = zmalloc(bytes+1);
	for (i = 0; i < bytes; ++i) {
		int h = hexindex[(int)src[i*2]];
		int l = hexindex[(int)src[i*2+1]];
		if (h < 0 || l < 0) {
			free(tmp);
			return NULL;
		}
		tmp[i] = ((h << 4) + l) & (0xFF >> (8-bitwidth));
	}
	tmp[i] = 0;

	return tmp;
}

/**
 * Checks if the given memory contains only zeros.
 *
 * @param p_memory Pointer to the memory that is checked.
 * @param length Number of bytes to check for zero.
 * @return 0 means false (not only zeros), 1 means true (only zeros)
 */
int is_memory_all_zero(const void * const p_memory, const size_t length) {
	for(size_t i = 0; i < length; ++i) {
		if(((const unsigned char * const)p_memory)[i] != 0) {
			return 0;
		}
	}

	return 1;
}

/*
 * BASE64 CODE FROM MUTT BEGIN - ORIGINAL COPYRIGHT APPLIES:
 *
 * Copyright (C) 1996-2001 Michael R. Elkins <me@cs.hmc.edu>
 * Copyright (C) 1996-2001 Brandon Long <blong@fiction.net>
 * Copyright (C) 1997-2001 Thomas Roessler <roessler@guug.de>
 * Copyright (C) 1998-2001 Werner Koch <wk@isil.d.shuttle.de>
 * Copyright (C) 1999-2001 Brendan Cully <brendan@kublai.com>
 * Copyright (C) 1999-2001 Tommi Komulainen <Tommi.Komulainen@iki.fi>
 * Copyright (C) 2000-2001 Edmund Grimley Evans <edmundo@rano.org>
 *
 */

#define BAD     	-1
#define base64val(c)	index64[(unsigned int)(c)]

static const char base64[64] = {
	'A','B','C','D','E','F','G','H','I','J','K','L','M','N',
	'O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b',
	'c','d','e','f','g','h','i','j','k','l','m','n','o','p',
	'q','r','s','t','u','v','w','x','y','z','0','1','2','3',
	'4','5','6','7','8','9','+','/'
};

static const int index64[128] = {
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,
	61,-1,-1,-1,-1,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,
	14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,-1,26,
	27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,
	46,47,48,49,50,51,-1,-1,-1,-1,-1
};

void to_base64(unsigned char *out, const unsigned char *in, size_t len, size_t olen) {
	while (len >= 3 && olen > 10) {
		*out++ = base64[in[0] >> 2];
		*out++ = base64[((in[0] << 4) & 0x30) | (in[1] >> 4)];
		*out++ = base64[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
		*out++ = base64[in[2] & 0x3f];
		olen  -= 4;
		len   -= 3;
		in    += 3;
	}

	/* clean up remainder */
	if (len > 0 && olen > 4) {
		unsigned char fragment;

		*out++ = base64[in[0] >> 2];
		fragment = (in[0] << 4) & 0x30;
		if (len > 1)
			fragment |= in[1] >> 4;
		*out++ = base64[fragment];
		*out++ = (len < 2) ? '=' : base64[(in[1] << 2) & 0x3c];
		*out++ = '=';
	}
	*out = '\0';
}

/* Convert '\0'-terminated base 64 string to raw bytes.
 * Returns length of returned buffer, or -1 on error */
int from_base64(char *out, const char *in)
{
	int len = 0;
	uint8_t digit4;

	do {
		uint8_t digit1 = in[0];
		if (digit1 > 127 || base64val (digit1) == BAD)
			return -1;

		uint8_t digit2 = in[1];
		if (digit2 > 127 || base64val (digit2) == BAD)
			return -1;

		uint8_t digit3 = in[2];
		if (digit3 > 127 || ((digit3 != '=') && (base64val (digit3) == BAD)))
			return -1;

		digit4 = in[3];
		if (digit4 > 127 || ((digit4 != '=') && (base64val (digit4) == BAD)))
			return -1;

		in += 4;

		/* digits are already sanity-checked */
		*out++ = (char)((base64val(digit1) << 2) | (base64val(digit2) >> 4));
		len++;
		if (digit3 != '=') {
			*out++ = (char)(((base64val(digit2) << 4) & 0xf0) | (base64val(digit3) >> 2));
			len++;
			if (digit4 != '=') {
				*out++ = (char)(((base64val(digit3) << 6) & 0xc0) | base64val(digit4));
				len++;
			}
		}
	} while (*in && digit4 != '=');

	return len;
}
/*
 * CODE FROM MUTT END
 */

/**
 * Returns a 64 bit wide random number.
 * First the function tries the best (most secure) ways to get a random number,
 * falling back to less secure ones until only simple pseudo random numbers can
 * be obtained if everything else is not possible.
 *
 * @return uint64_t random number
 */
uint64_t getrandom64(void)
{
	uint64_t random_number = 0;
	int success = 0;

#ifndef __CYGWIN__
	// Try reading a better random number from /dev/urandom (only on real
	// unix / linux systems since Cygwins urandom is not really secure).
	FILE * fp = fopen("/dev/urandom", "rb");
	if (fp != NULL) {
		const size_t num_read = fread(&random_number, sizeof(random_number), 1, fp);
		if (1 == num_read) {
			success = 1;
		}
		else {
			if (debug) {
				printf("fread for /dev/urandom failed: %s\n", strerror(errno));
			}
		}
		fclose(fp);
	}
	else {
		if (debug) {
			printf("/dev/urandom can not be opened for reading\n");
		}
	}
#endif

#ifdef __CYGWIN__
#if 0
	// BCryptGenRandom is the successor of the deprecated CryptGenRandom.
	// Once it is established and available (in Cygwin) maybe without needing an external library it can be enabled.
	// Needs bcrypt.h
	if (!success) {
		if (BCRYPT_SUCCESS(BCryptGenRandom(NULL, (PUCHAR)&random_number, sizeof(random_number), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
			success = 1;
		}
	}
#endif

	if (!success) {
		HCRYPTPROV prov;
		if (CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
			if (CryptGenRandom(prov, sizeof(random_number), (BYTE *)&random_number)) {
				success = 1;
			}
			CryptReleaseContext(prov, 0);
		}
	}
#endif

#if config_arc4random_buf == 1
	if (!success) {
		arc4random_buf(&random_number, sizeof(random_number));
	}
#else
	if (!success) {
		// Use random() as a fallback
		random_number = ((uint64_t)random() << 32) | random();
	}
#endif

	return random_number;
}

/**
 * Wrapper for the write() function that does retries and error handling.
 * The parameters and return value have the same meaning as for write().
 *
 * @param[in] fildes File descriptor
 * @param[in] buf Buffer that should be written
 * @param[in] nbyte Number of bytes that should be written
 * @return ssize_t The same values write() returns.
 */
ssize_t write_wrapper(int fildes, const void *buf, const size_t nbyte)
{
	ssize_t retval = 0;
	const size_t max_retries = 50;
	size_t bytes_written = 0;

	if ((buf == NULL) || (nbyte == 0)) {
		return 0;
	}

	for(size_t retry_cnt = 0;
		(retry_cnt < max_retries) && (bytes_written < nbyte) && (retval >= 0);
		++retry_cnt) {
		retval = write(fildes, (const uint8_t *)(buf) + bytes_written, nbyte - bytes_written);
		if (retval >= 0) {
			bytes_written += retval;
		}
	}

	if (retval < 0) {
		syslog(LOG_ERR, "write() failed with error %d: %s\n", errno, strerror(errno));
	}
	else {
		retval = (ssize_t)(bytes_written);
		if(bytes_written < nbyte) {
			syslog(LOG_ERR, "ERROR: write() only wrote %zu of %zu bytes after %zu retries.\n", bytes_written, nbyte, max_retries);
		}
	}

	return retval;
}

/**
 * Use memset_s for zeroing buffers. This function is not optimized by the compiler,
 * so it can be used for clearing passwords.
 * Prefer using the standard library version if available, otherwise use a custom
 * implementation such that the compiler does not optimize it.
 */
void compat_memset_s( void *dest, size_t destsz, char ch, size_t count ){
#if config_memset_s == 1
	memset_s(dest, destsz, ch, count);
#else
	count = MIN(count, destsz);
	volatile unsigned char *p = dest;
	while (count--){
		*p++ = ch;
	}
#endif
}
