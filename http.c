/*
 * HTTP handling routines and related socket stuff for CNTLM
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

#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <assert.h>
#include <syslog.h>

#include "http.h"
#include "socket.h"
#include "ntlm.h"

#define BLOCK		2048

extern int debug;

/*
 * True if src is a header. This is just a basic check
 * for the colon delimiter. Might eventually become more
 * sophisticated. :)
 */
int is_http_header(const char *src) {
	return strcspn(src, ":") != strlen(src);
}

/*
 * Extract the header name from the source.
 */
char *get_http_header_name(const char *src) {
	size_t i;

	i = strcspn(src, ":");
	if (i != strlen(src))
		return substr(src, 0, (int)i);
	else
		return NULL;
}

/*
 * Extract the header value from the source.
 */
char *get_http_header_value(const char *src) {
	const char *sub;

	if ((sub = strchr(src, ':'))) {
		sub++;
		while (*sub == ' ')
			sub++;

		return strdup(sub);
	} else
		return NULL;
}

/*
 * Receive HTTP request/response from the given socket. Fill in pre-allocated
 * rr_data_t structure.
 * Returns: 1 if OK, 0 in case of socket EOF or other error
 */
int headers_recv(int fd, rr_data_t data) {
	int i;
	int bsize;
	size_t len;
	int is_http = 0;
	char *buf;
	char *tok;
	char *s3 = NULL;
	char *orig = NULL;
	char *ccode = NULL;
	char *host = NULL;

	bsize = BUFSIZE;
	buf = zmalloc(bsize);

	i = so_recvln(fd, &buf, &bsize);
	if (i <= 0)
		goto bailout;

	if (debug)
		printf("HEAD: %s", buf);

	/*
	 * Are we reading HTTP request (from client) or response (from server)?
	 */
	trimr(buf);
	orig = strdup(buf);
	len = strlen(buf);
	tok = strtok_r(buf, " ", &s3);
	if (tok && ((is_http = !strncasecmp(tok, "HTTP/", 5)) || !strncasecmp(tok, "ICY", 3))) {
		data->req = 0;
		data->empty = 0;
		data->http = strdup(tok);
		data->msg = NULL;

		/*
		 * Let's find out the numeric version of the HTTP version: 09, 10, 11.
		 * Set to -1 if header is misformatted.
		 */
		if (is_http && (tok = strchr(data->http, '/')) && strlen(tok) >= 4 && isdigit((u_char)tok[1]) && isdigit((u_char)tok[3])) {
			data->http_version = (tok[1] - 0x30) * 10 + (tok[3] - 0x30);
		} else {
			data->http_version = -1;
		}

		tok = strtok_r(NULL, " ", &s3);
		if (tok) {
			ccode = strdup(tok);

			tok += strlen(ccode);
			while (tok < buf+len && *tok++ == ' ');

			if (strlen(tok))
				data->msg = strdup(tok);
		}

		if (!data->msg)
			data->msg = strdup("");

		if (!ccode || strlen(ccode) != 3 || (data->code = atoi(ccode)) == 0) {
			i = -2;
			goto bailout;
		}
	} else if (strstr(orig, " HTTP/") && tok) {
		data->req = 1;
		data->empty = 0;
		data->method = NULL;
		data->url = NULL;
		data->rel_url = NULL;
		data->http = NULL;
		data->hostname = NULL;

		data->method = strdup(tok);

		tok = strtok_r(NULL, " ", &s3);
		if (tok)
			data->url = strdup(tok);

		tok = strtok_r(NULL, " ", &s3);
		if (tok)
			data->http = strdup(tok);

		if (!data->url || !data->http) {
			i = -3;
			goto bailout;
		}

		/*
		 * Let's find out the numeric version of the HTTP version: 09, 10, 11.
		 * Set to -1 if header is misformatted.
		 */
		if ((tok = strchr(data->http, '/')) && strlen(tok) >= 4 && isdigit((u_char)tok[1]) && isdigit((u_char)tok[3])) {
			data->http_version = (tok[1] - 0x30) * 10 + (tok[3] - 0x30);
		} else {
			data->http_version = -1;
		}

		if ((tok = strstr(data->url, "://"))) {
			tok += 3;
		} else {
			tok = data->url;
		}

		s3 = strchr(tok, '/');
		if (s3) {
			host = substr(tok, 0, (int)(s3-tok));
			data->rel_url = strdup(s3);
		} else {
			host = substr(tok, 0, (int)strlen(tok));
			data->rel_url = strdup("/");
		}

	} else {
		if (debug)
			printf("headers_recv: Unknown header (%s).\n", orig);
		i = -4;
		goto bailout;
	}

	/*
	 * Read in all headers, do not touch any possible HTTP body
	 */
	do {
		i = so_recvln(fd, &buf, &bsize);
		trimr(buf);
		if (i > 0 && is_http_header(buf)) {
			data->headers = hlist_add(data->headers, get_http_header_name(buf), get_http_header_value(buf), HLIST_NOALLOC, HLIST_NOALLOC);
		}
	} while (strlen(buf) != 0 && i > 0);

	if (data->req) {
		/*
		 * Fix requests, make sure the Host: header is present
		 */
		if (host && strlen(host)) {
			if (!hlist_get(data->headers, "Host"))
				data->headers = hlist_add(data->headers, "Host", host, HLIST_ALLOC, HLIST_ALLOC);
		} else {
			if (debug)
				printf("headers_recv: no host name (%s)\n", orig);
			i = -6;
			goto bailout;
		}


		if (host[0] == '[') {
			tok = strchr(host, ']');
			*tok = 0;
			data->hostname = strdup(host+1);
			if (*(tok+1) == ':') {
				data->port = atoi(tok+2);
			}
		} else if ((tok = strchr(host, ':'))) {
			*tok = 0;
			data->hostname = strdup(host);
			data->port = atoi(tok+1);
		} else {
			data->hostname = strdup(host);
		}

		if (!data->port) {
			if (!strncasecmp(data->url, "https", 5))
				data->port = 443;
			else
				data->port = 80;
		}

		assert(data != NULL);
		assert(data->hostname != NULL);
		if (!strlen(data->hostname) || !data->port) {
			i = -5;
			goto bailout;
		}
	}

bailout:
	if (orig) free(orig);
	if (ccode) free(ccode);
	if (host) free(host);
	free(buf);

	if (i <= 0) {
		if (debug)
			printf("headers_recv: fd %d error %d\n", fd, i);
		return 0;
	}

	return 1;
}

/*
 * Send HTTP request/response to the given socket based on what's in "data".
 * Returns: 1 if OK, 0 in case of socket error
 */
int headers_send(int fd, rr_data_const_t data) {
	hlist_const_t t;
	char *buf;
	size_t i;
	size_t len;

	/*
	 * First compute required buffer size (avoid realloc, etc)
	 */
	if (data->req)
		len = 20 + strlen(data->method) + strlen(data->url) + strlen(data->http);
	else
		len = 20 + strlen(data->http) + strlen(data->msg);

	t = data->headers;
	while (t) {
		len += 20 + strlen(t->key) + strlen(t->value);
		t = t->next;
	}

	/*
	 * We know how much memory we need now...
	 */
	const size_t buf_len = len;
	buf = zmalloc(buf_len);

	/*
	 * Prepare the first request/response line
	 */
	len = 0;
	if (data->req)
		len = snprintf(buf, buf_len, "%s %s %s\r\n", data->method, data->url, data->http);
	else if (!data->skip_http)
		len = snprintf(buf, buf_len, "%s %03d %s\r\n", data->http, data->code, data->msg);

	/*
	 * Now add all headers.
	 */
	t = data->headers;
	while (t) {
		len += snprintf(buf+len, buf_len - len, "%s: %s\r\n", t->key, t->value);
		t = t->next;
	}

	/*
	 * Terminate headers
	 */
	strlcat(buf, "\r\n", buf_len);

	/*
	 * Flush it all down the toilet
	 */
	if (!so_closed(fd))
		i = write_wrapper(fd, buf, len+2);
	else
		i = -999;

	free(buf);

	if (i <= 0 || i != len+2) {
		if (debug)
			printf("headers_send: fd %d warning %zu (connection closed)\n", fd, i);
		return 0;
	}

	return 1;
}

/*
 * Forward "size" of data from "src" to "dst". If size == -1 then keep
 * forwarding until src reaches EOF.
 * If dst == -1, data is discarded.
 */
int data_send(int dst, int src, length_t len) {
	char *buf;
	ssize_t i;
	ssize_t block;
	int c = 0;
	ssize_t j = 1;

	if (!len)
		return 1;

	buf = zmalloc(BLOCK);

	do {
		block = (len == -1 || len-c > BLOCK ? BLOCK : len-c);
		i = read(src, buf, block);

		if (i > 0)
			c += i;

		if (dst >= 0 && debug)
			printf("data_send: read %zu of %zu / %d of %lld (errno = %s)\n", i, block, c, len, i < 0 ? strerror(errno) : "ok");

		if (dst >= 0 && so_closed(dst)) {
			i = -999;
			break;
		}

		if (dst >= 0 && i > 0) {
			j = write_wrapper(dst, buf, i);
			if (debug)
				printf("data_send: wrote %zd of %zu\n", j, i);
		}

	} while (i > 0 && j > 0 && (len == -1 || c <  len));

	free(buf);

	if (i <= 0 || j <= 0) {
		if (i == 0 && j > 0 && (len == -1 || c == len))
			return 1;

		if (debug)
			printf("data_send: fds %d:%d warning %zu (connection closed)\n", dst, src, i);
		return 0;
	}

	return 1;
}

/*
 * Forward chunked HTTP body from "src" descriptor to "dst".
 * If dst == -1, data is discarded.
 */
int chunked_data_send(int dst, int src) {
	char *buf;
	int bsize;
	ssize_t len;
	int i;
	ssize_t w;
	length_t csize;

	char *err = NULL;

	bsize = BUFSIZE;
	buf = zmalloc(bsize);

	/* Take care of all chunks */
	do {
		i = so_recvln(src, &buf, &bsize);
		if (i <= 0) {
			if (debug)
				printf("chunked_data_send: aborting, read error\n");
			free(buf);
			return 0;
		}

		csize = strtol(buf, &err, 16);

		if (!isspace((u_char)*err) && *err != ';') {
			if (debug)
				printf("chunked_data_send: aborting, chunk size format error\n");
			free(buf);
			return 0;
		}

		if (dst >= 0)
			(void) write_wrapper(dst, buf, strlen(buf));

		if (csize && !data_send(dst, src, csize+2)) {
			if (debug)
				printf("chunked_data_send: aborting, data_send failed\n");

			free(buf);
			return 0;
		}
	} while (csize != 0);

	/* Take care of possible trailer */
	w = len = 0;
	do {
		i = so_recvln(src, &buf, &bsize);
		if (dst >= 0 && i > 0) {
			len = strlen(buf);
			w = write_wrapper(dst, buf, len);
		}
	} while (w == len && i > 0 && buf[0] != '\r' && buf[0] != '\n');

	free(buf);
	return 1;
}

/*
 * Full-duplex forwarding between proxy and client descriptors.
 * Used for bidirectional HTTP CONNECT connection.
 */
int tunnel(int cd, int sd) {
	struct pollfd fds[2];
	int from;
	int to;
	int ret;
	int sel;
	char *buf;

	buf = zmalloc(BUFSIZE);

	if (debug)
		printf("tunnel: poll cli: %d, srv: %d\n", cd, sd);

	fds[0].fd = cd;
	fds[1].fd = sd;

	do {
		fds[0].events = POLLIN;
		fds[1].events = POLLIN;

		sel = poll(fds, 2, -1); // Wait indefinitely
		if (sel > 0) {
			if (fds[0].revents & POLLIN) {
				from = fds[0].fd;
				to = fds[1].fd;
			} else {
				from = fds[1].fd;
				to = fds[0].fd;
			}

			ret = (int)read(from, buf, BUFSIZE);
			if (ret > 0) {
				(void) write_wrapper(to, buf, ret);
			} else {
				ret = (ret == 0);
				break;
			}
		} else if (sel < 0) {
			ret = 0;
		}
	} while (sel >= 0);

	free(buf);
	return ret;
}

/*
 * Return 0 if no body, -1 if body until EOF, number if size known
 * One of request/response can be NULL
 */
length_t http_has_body(rr_data_const_t request, rr_data_const_t response) {
	rr_data_const_t current;
	length_t length;
	int nobody;
	const char *tmp;

	/*
	 * Are we checking a complete req+res conversation or just the
	 * request body?
	 */
	current = (!response || response->empty ? request : response);

	if (current == NULL) {
		syslog(LOG_ERR, "Internal error in function http_has_body(): Both arguments to function seem to be invalid/NULL: request: %p response: %p\n",
				(const void *)request, (const void *)response);
		return 0;
	}

	/*
	 * HTTP body length decisions. There MUST NOT be any body from
	 * server if the request was HEAD or reply is 1xx, 204 or 304.
	 * No body can be in GET request if direction is from client.
	 */
	if (current == response) {
		nobody = (HEAD(request) ||
			(response->code >= 100 && response->code < 200) ||
			response->code == 204 ||
			response->code == 304);
	} else {
		nobody = GET(request) || HEAD(request);
	}

	/*
	 * Otherwise consult Content-Length. If present, we forward exactly
	 * that many bytes.
	 *
	 * If not present, but there is Transfer-Encoding or Content-Type
	 * (or a request to close connection, that is, end of data is signaled
	 * by remote close), we will forward until EOF.
	 *
	 * No C-L, no T-E, no C-T == no body.
	 */
	tmp = hlist_get(current->headers, "Content-Length");
	if (!nobody && tmp == NULL && (hlist_in(current->headers, "Content-Type")
			|| hlist_in(current->headers, "Transfer-Encoding")
			|| hlist_subcmp(current->headers, "Connection", "close"))) {
		if (hlist_in(current->headers, "Transfer-Encoding")
				&& hlist_subcmp(current->headers, "Transfer-Encoding", "chunked"))
			length = 1;
		else
			length = -1;
	} else
		length = (tmp == NULL || nobody ? 0 : atoll(tmp));

	if (current == request && length == -1)
		length = 0;

	return length;
}

/*
 * Send a HTTP body (if any) between descriptors readfd and writefd
 */
int http_body_send(int writefd, int readfd, rr_data_const_t request, rr_data_const_t response) {
	length_t bodylen;
	int rc = 1;
	rr_data_const_t current;

	/*
	 * Are we checking a complete req+res conversation or just the
	 * request body?
	 */
	current = (response->empty ? request : response);

	/*
	 * Ok, so do we expect any body?
	 */
	bodylen = http_has_body(request, response);
	if (bodylen) {
		/*
		 * Check for supported T-E.
		 */
		if (hlist_subcmp(current->headers, "Transfer-Encoding", "chunked")) {
			if (debug)
				printf("Chunked body included.\n");

			rc = chunked_data_send(writefd, readfd);
			if (debug)
				printf("%s", rc ? "Chunked body sent.\n" : "Could not chunk send whole body\n");
		} else {
			if (debug)
				printf("Body included. Length: %lld\n", bodylen);

			rc = data_send(writefd, readfd, bodylen);
			if (debug)
				printf("%s", rc ? "Body sent.\n" : "Could not send whole body\n");
		}
	} else if (debug)
		printf("No body.\n");

	return rc;
}

/*
 * Connection cleanup - C-L or chunked body
 * Return 0 if connection closed or EOF, 1 if OK to continue
 */
int http_body_drop(int fd, rr_data_const_t response) {
	length_t bodylen;
	int rc = 1;

	bodylen = http_has_body(NULL, response);
	if (bodylen) {
		if (hlist_subcmp(response->headers, "Transfer-Encoding", "chunked")) {
			if (debug)
				printf("Discarding chunked body.\n");
			rc = chunked_data_send(-1, fd);
		} else {
			if (debug)
				printf("Discarding %lld bytes.\n", bodylen);
			rc = data_send(-1, fd, bodylen);
		}
	}

	return rc;
}

/*
 * Parse headers for BASIC auth credentials
 *
 * Return 1 = creds parsed OK, 0 = no creds, -1 = invalid creds
 */
int http_parse_basic(hlist_const_t headers, const char *header, struct auth_s *tcreds) {
	char *tmp = NULL;
	char *pos = NULL;
	char *buf = NULL;
	char *dom = NULL;
	size_t i;

	if (!hlist_subcmp(headers, header, "basic"))
		return 0;

	tmp = hlist_get(headers, header);
	assert(tmp != NULL);
	size_t header_bufsize = strlen(tmp) + 1;
	buf = zmalloc(header_bufsize);
	i = 5;
	while (i < strlen(tmp) && tmp[++i] == ' ');
	from_base64(buf, tmp+i);
	pos = strchr(buf, ':');

	if (pos == NULL) {
		compat_memset_s(buf, header_bufsize, 0, strlen(buf)); /* clean memory containing credentials */
		free(buf);
		return -1;
	} else {
		*pos = 0;
		dom = strchr(buf, '\\');
		if (dom == NULL) {
			auth_strcpy(tcreds, user, buf);
		} else {
			*dom = 0;
			++dom;
			auth_strcpy(tcreds, domain, buf);
			auth_strcpy(tcreds, user, dom);
		}

		if (tcreds->hashntlm2) {
			tmp = ntlm2_hash_password(tcreds->user, tcreds->domain, pos+1);
			auth_memcpy(tcreds, passntlm2, tmp, 16);
			free(tmp);
		}

		if (tcreds->hashnt) {
			tmp = ntlm_hash_nt_password(pos+1);
			auth_memcpy(tcreds, passnt, tmp, 21);
			free(tmp);
		}

		if (tcreds->hashlm) {
			tmp = ntlm_hash_lm_password(pos+1);
			auth_memcpy(tcreds, passlm, tmp, 21);
			free(tmp);
		}

		compat_memset_s(buf, header_bufsize, 0, header_bufsize);
		free(buf);
	}

	return 1;
}
