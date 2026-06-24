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

#ifndef HTTP_H
#define HTTP_H

#include <stdint.h>

#include "utils.h"
#include "auth.h"

/*
 * A couple of shortcuts for if statements
 */
#define CONNECT(data)	((data) && (data)->req && !strcasecmp("CONNECT", (data)->method))
#define HEAD(data)	((data) && (data)->req && !strcasecmp("HEAD", (data)->method))
#define GET(data)	((data) && (data)->req && !strcasecmp("GET", (data)->method))

typedef long long int length_t;

extern int is_http_header(const char *src);
extern char *get_http_header_name(const char *src);
extern char *get_http_header_value(const char *src);
extern int http_parse_basic(hlist_const_t headers, const char *header, struct auth_s *tcreds);
extern int headers_recv(int fd, rr_data_t data);
extern int headers_send(int fd, rr_data_const_t data);
extern int tunnel(int cd, int sd);
extern length_t http_has_body(rr_data_const_t request, rr_data_const_t response);
extern int http_body_send(int writefd, int readfd, rr_data_const_t request, rr_data_const_t response);
extern int http_body_drop(int fd, rr_data_const_t response);
extern int fetch_url(const char *url, char **outbuf, size_t *outlen, int *outcode);

#endif /* HTTP_H */
