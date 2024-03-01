/*
 * Parsing of pac files
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
 * Copyright (c) 2022 Francesco MDE aka fralken, David Kubicek
 *
 */

#include <netdb.h>
#include <ifaddrs.h>

#include "duktape/duktape.h"
#include "pac_utils_js.h"
#include "pac.h"

/*
 * global duktape context
 */
duk_context *pac_ctx = NULL;

static duk_ret_t native_dnsresolve(duk_context *ctx) {
	const char *hostname;
	struct addrinfo hints;
	struct addrinfo *addresses;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;

	hostname = duk_to_string(ctx, 0);

	int rc = getaddrinfo(hostname, NULL, &hints, &addresses);
	if (rc != 0) {
		duk_push_string(ctx, NULL);
	} else {
    	char s[INET_ADDRSTRLEN] = {0};
		for(struct addrinfo *p = addresses; p != NULL; p = p->ai_next) {
			if (p->ai_family == AF_INET) {
				getnameinfo(p->ai_addr, p->ai_addrlen, s, sizeof(s), NULL, 0, NI_NUMERICHOST);
				break;
			}
		}
		duk_push_string(ctx, s);
		freeaddrinfo(addresses);
	}

	return 1;
}

static duk_ret_t native_myipaddress(duk_context *ctx) {
	struct ifaddrs *addrs;

	int rc = getifaddrs(&addrs);
	if (rc != 0) {
		duk_push_string(ctx, "127.0.0.1");
	} else {
    	char s[INET_ADDRSTRLEN] = {0};
		for (struct ifaddrs *p = addrs; p != NULL; p = p->ifa_next) {
			if (p->ifa_addr && p->ifa_addr->sa_family == AF_INET) {
				getnameinfo(p->ifa_addr, sizeof(struct sockaddr_in), s, sizeof(s), NULL, 0, NI_NUMERICHOST);
			}
		}
		duk_push_string(ctx, s);
		freeifaddrs(addrs);
	}

	return 1;
}

char *read_file(const char* filename) {
    FILE    *fd;
    char    *buf;
    size_t  len;
    size_t  ret;
    
    fd = fopen(filename, "r");
    if(fd == NULL)
        return NULL;
    
    fseek(fd, 0L, SEEK_END);
    len = ftell(fd);
    fseek(fd, 0L, SEEK_SET);	

    buf = (char*)calloc(len+1, sizeof(char));	
    if(buf == NULL) {
        fclose(fd);
        return NULL;
    }

    ret = fread(buf, sizeof(char), len, fd);
    if (ret < len) {
        free(buf);
        buf = NULL;
    } 
    fclose(fd);

    return buf;
}

// returns an escaped string or null if original string
// does not need to be escaped, or it is null, 
// or an allocation error happens
char *escape_string(const char *str) {
    if (!str)
        return NULL;

    int n = 0;
    const char *p = str;
    while (*p) {
        if (*p == '"' || *p == '\\')
            n++;
        p++;
    }
    if (n == 0)
        return NULL;

    char *newstr = (char*)calloc(p - str + n + 1, sizeof(char));
    if (!newstr)
        return NULL;

    char *q = newstr;
    p = str;
    while (*p) {
        if (*p == '"' || *p == '\\')
            *q++ = '\\';
        *q++ = *p++;
    }
    *q = 0;
    return newstr;
}

int pac_init(void) {
    pac_ctx = duk_create_heap_default();

    if (pac_ctx) {
        duk_push_c_function(pac_ctx, native_dnsresolve, 1);
        duk_put_global_string(pac_ctx, "dnsResolve");
        duk_push_c_function(pac_ctx, native_myipaddress, 0);
        duk_put_global_string(pac_ctx, "myIpAddress");

        duk_eval_string(pac_ctx, pac_utils_js);
        duk_pop(pac_ctx);
    }

    return pac_ctx != NULL;
}

int pac_parse_file(const char *pacfile) {
    char *pacstring = read_file(pacfile);
    if (!pacstring)
        return 0;

    int rc = pac_parse_string(pacstring);
    free(pacstring);

    return rc;
}

int pac_parse_string(const char *pacstring) {
    if (!pac_ctx)
        return 0;

    duk_eval_string(pac_ctx, pacstring);
    duk_pop(pac_ctx);

    return 1;
}

const char *pac_find_proxy(const char *url, const char *host) {
    if (!pac_ctx || !url || !host)
        return NULL;

    char* escaped_url = escape_string(url);
    char* escaped_host = escape_string(host);

    duk_push_sprintf(pac_ctx, "FindProxyForURL(\"%s\", \"%s\");",
        escaped_url ? escaped_url : url,
        escaped_host ? escaped_host : host);
    duk_eval(pac_ctx);
    const char* res = duk_get_string(pac_ctx, -1);
    duk_pop(pac_ctx);

    if (escaped_url)
        free(escaped_url);
    if (escaped_host)
        free(escaped_host);

    return res;
}

void pac_cleanup(void) {
    if (pac_ctx) {
        duk_destroy_heap(pac_ctx);
        pac_ctx = NULL;
    }
}
