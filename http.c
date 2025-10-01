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

/*
 * Read the HTTP body from fd into a newly allocated buffer.
 * For chunked transfer encoding this will decode chunks and concatenate them.
 * The caller is responsible to free(*outbuf).
 * Returns 1 on success, 0 on failure.
 */
int http_read_body(int fd, rr_data_const_t response, char **outbuf, size_t *outlen) {
	length_t bodylen;
	char *buf = NULL;
	ssize_t alloc = 0;
	ssize_t filled = 0;

	if (!outbuf || !outlen || !response)
		return 0;

	*outbuf = NULL;
	*outlen = 0;

	bodylen = http_has_body(NULL, response);
	if (!bodylen) {
		// no body
		*outbuf = zmalloc(1);
		*outlen = 0;
		return 1;
	}

	if (hlist_subcmp(response->headers, "Transfer-Encoding", "chunked")) {
		/* read chunked body by reading lines and chunks from fd */
		int bsize = BUFSIZE;
		char *line = zmalloc(bsize);
		char *err = NULL;
		long csize;
		do {
			int r = so_recvln(fd, &line, &bsize);
			if (r <= 0) {
				free(line);
				free(buf);
				return 0;
			}
			trimr(line);
			csize = strtol(line, &err, 16);
			if (!isspace((u_char)*err) && *err != ';' && *err != '\0') {
				free(line);
				free(buf);
				return 0;
			}
			if (csize > 0) {
				// ensure capacity
				if (filled + csize > alloc) {
					alloc = (filled + csize) * 2;
					buf = realloc(buf, alloc);
				}
				// read csize bytes
				length_t need = csize;
				while (need > 0) {
					size_t toread = (need > BLOCK ? BLOCK : (size_t)need);
					ssize_t got = read(fd, buf + filled, toread);
					if (got <= 0) {
						free(line);
						free(buf);
						return 0;
					}
					filled += got;
					need -= got;
				}
				// read and discard CRLF after chunk
				char crlf[2];
				if (read(fd, crlf, 2) != 2) {
					free(line);
					free(buf);
					return 0;
				}
			}
		} while (csize != 0);

		// read possible trailer headers until empty line
		do {
			int r = so_recvln(fd, &line, &bsize);
			if (r <= 0) {
				free(line);
				free(buf);
				return 0;
			}
		} while (line[0] != '\r' && line[0] != '\n');

		free(line);
	} else if (bodylen == -1) {
		/* read until EOF */
		buf = NULL;
		alloc = 0;
		filled = 0;
		char tmp[BLOCK];
		ssize_t r;
		while ((r = read(fd, tmp, BLOCK)) > 0) {
			if (filled + r >= alloc) {
				alloc = (alloc == 0) ? r + 1 : alloc * 2;
				buf = realloc(buf, alloc);
			}
			memcpy(buf + filled, tmp, r);
			filled += r;
			buf[filled] = '\0';
		}
		if (r < 0) {
			free(buf);
			return 0;
		}
	} else {
		/* fixed length */
		if (bodylen > 0) {
			buf = zmalloc(bodylen+1);
			length_t need = bodylen;
			size_t pos = 0;
			while (need > 0) {
				size_t toread = (need > BLOCK ? BLOCK : (size_t)need);
				ssize_t got = read(fd, buf + pos, toread);
				if (got <= 0) {
					free(buf);
					return 0;
				}
				pos += got;
				need -= got;
			}
			filled = pos;
		} else {
			buf = zmalloc(1);
			filled = 0;
		}
	}

	// finalize buffer
	if (buf == NULL) {
		buf = zmalloc(1);
		filled = 0;
	}

	*outbuf = buf;
	*outlen = filled;

	return 1;
}

/*
 * Minimal HTTP GET fetcher to retrieve a file from URL into memory.
 * Supports only http scheme (no HTTPS) and basic parsing of host:port/path.
 * The function allocates *outbuf and sets *outlen. Caller must free(*outbuf).
 * If outcode != NULL, the HTTP response status code will be stored there
 * (or -1 on protocol/error).
 * Returns 1 on successful fetch+read, 0 on error.
 */
int fetch_url(const char *url, char **outbuf, size_t *outlen, int *outcode) {
	if (!url || !outbuf || !outlen)
		return 0;

	if (outcode)
		*outcode = -1;

	// Basic parse: expect http://host[:port]/path
	const char *p = url;
	if (strncasecmp(p, "http://", 7) == 0)
		p += 7;
	else
		return 0; // only http supported for now

	char *host = NULL;
	int port = 80;
	const char *path = strchr(p, '/');
	if (path) {
		host = substr(p, 0, (int)(path - p));
	} else {
		host = strdup(p);
		path = "/";
	}

	// split port
	char *colon = strchr(host, ':');
	if (colon) {
		*colon = '\0';
		port = atoi(colon+1);
		if (port == 0) port = 80;
	}

	struct addrinfo *addresses = NULL;
	if (!so_resolv(&addresses, host, port)) {
		free(host);
		return 0;
	}

	int sd = so_connect(addresses);
	freeaddrinfo(addresses);
	if (sd < 0) {
		free(host);
		return 0;
	}

	// Build simple GET request
	rr_data_t req = new_rr_data();
	req->req = 1;
	req->method = strdup("GET");
	req->url = strdup(path);
	req->http = strdup("HTTP/1.1");
	req->headers = hlist_add(req->headers, "Host", host, HLIST_ALLOC, HLIST_ALLOC);
	req->headers = hlist_add(req->headers, "User-Agent", "cntlm-fetch/1.0", HLIST_ALLOC, HLIST_ALLOC);
	req->headers = hlist_add(req->headers, "Connection", "close", HLIST_ALLOC, HLIST_ALLOC);

	// send headers
	if (!headers_send(sd, req)) {
		free_rr_data(&req);
		close(sd);
		free(host);
		return 0;
	}
	free_rr_data(&req);
	free(host);

	// read response headers
	rr_data_t res = new_rr_data();
	if (!headers_recv(sd, res)) {
		free_rr_data(&res);
		close(sd);
		return 0;
	}

	/* expose HTTP status code to caller */
	if (outcode)
		*outcode = res->code;

	// read body into memory
	char *body = NULL;
	size_t bodylen = 0;
	if (!http_read_body(sd, res, &body, &bodylen)) {
		free_rr_data(&res);
		close(sd);
		return 0;
	}
	free_rr_data(&res);
	close(sd);

	*outbuf = body;
	*outlen = bodylen;

	return 1;
}
