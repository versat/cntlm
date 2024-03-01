/*
 * Static HTML page generators for CNTLM
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

#include <stdio.h>

#include "pages.h"
#include "utils.h"

char *gen_407_page(const char *http) {
	char *tmp;
	if (http == NULL)
		http = "HTTP/1.0";
	tmp = zmalloc(BUFSIZE);
	snprintf(tmp, BUFSIZE-1,
		"%s 407 Access denied\r\n"
		"Proxy-Authenticate: Basic realm=\"Cntlm Proxy\"\r\n"
		"Content-Type: text/html\r\n\r\n"
		"<html><body><h1>407 Access denied</h1><p><a href='http://cntlm.sf.net/'>Cntlm</a> requests your credentials for proxy access.</p></body></html>",
		http);
	return tmp;
}

char *gen_401_page(const char *http, const char *host, int port) {
	char *tmp;
	if (http == NULL)
		http = "HTTP/1.0";
	tmp = zmalloc(BUFSIZE);
	snprintf(tmp, BUFSIZE-1,
		"%s 401 Access denied\r\n"
		"WWW-Authenticate: Basic realm=\"%s:%d\"\r\n"
		"Content-Type: text/html\r\n\r\n"
		"<html><body><h1>401 Access denied</h1><p><a href='http://cntlm.sf.net/'>Cntlm</a> proxy requests your credentials for this URL.</p></body></html>",
		http, host, port);
	return tmp;
}

char *gen_denied_page(const char *ip) {
	char *tmp;
	if (ip == NULL)
		ip = "client";
	tmp = zmalloc(BUFSIZE);
	snprintf(tmp, BUFSIZE-1,
		"HTTP/1.0 407 Access denied\r\n"
		"Content-Type: text/html\r\n\r\n"
		"<html><body><h1>Access denied</h1><p>Your request has been declined, %s is not allowed to connect.</p></body></html>",
		ip);
	return tmp;
}

char *gen_502_page(const char *http, const char *msg) {
	char *tmp;
	if (http == NULL)
		http = "HTTP/1.0";
	if (msg == NULL)
		msg = "Proxy error";
	tmp = zmalloc(BUFSIZE);
	snprintf(tmp, BUFSIZE-1,
		"%s 502 %s\r\n"
		"Content-Type: text/html\r\n\r\n"
		"<html><body><h1>502 %s</h1><p><a href='http://cntlm.sf.net/'>Cntlm</a> proxy failed to complete the request.</p></body></html>",
		http, msg, msg);
	return tmp;
}
