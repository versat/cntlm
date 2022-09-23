/*
 * Management of parent proxies
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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>

#include "globals.h"
#include "socket.h"
#include "http.h"
#include "ntlm.h"
#include "proxy.h"

#if config_gss == 1
#include "kerberos.h"
#endif

#include "pac.h"

/*
 * Proxy types defined by PAC specification. Used in proxy_t to
 * specify proxy type.
 */
enum proxy_type_t { DIRECT, PROXY };

typedef struct {
	enum proxy_type_t type;
	char hostname[64];
	int port;
	struct auth_s creds;
	struct addrinfo *addresses;
	int resolved;
} proxy_t;

typedef struct proxylist_s *proxylist_t;
typedef const struct proxylist_s *proxylist_const_t;
struct proxylist_s {
	unsigned long key;
	proxy_t *proxy;
	struct proxylist_s *next;
};

typedef struct paclist_s *paclist_t;
typedef const struct paclist_s *paclist_const_t;
struct paclist_s {
	const char *pacstr;
	struct proxylist_s *proxylist;
	unsigned long proxycurr;
	int count;
	struct paclist_s *next;
}; 

paclist_t pac_list = NULL;

void paclist_free(paclist_t paclist);

/*
 * Pac Mutex
 */
pthread_mutex_t pac_mtx = PTHREAD_MUTEX_INITIALIZER;

/*
 * List of available proxies and current proxy id for proxy_connect().
 */
int parent_count = 0;
proxylist_t parent_list = NULL;

unsigned long parent_curr = 0;
pthread_mutex_t parent_mtx = PTHREAD_MUTEX_INITIALIZER;

#if config_gss == 1
proxy_t *curr_proxy;
#endif

/*
 * Add a new item to a list. Every proxylist_t variable must be
 * initialized to NULL (or pass NULL for "list" when adding
 * the first item). This is for simplicity's sake (we don't
 * need any proxylist_new).
 *
 * This list type allows to store a pointer to a proxy_t struct
 * associating it with the key.
 */
proxylist_t proxylist_add(proxylist_t list, const unsigned long key, proxy_t *proxy) {
	proxylist_t tmp;
	proxylist_t t = list;

	tmp = zmalloc(sizeof(struct proxylist_s));
	tmp->key = key;
	tmp->proxy = proxy;
	tmp->next = NULL;

	if (list == NULL)
		return tmp;

	while (t->next)
		t = t->next;

	t->next = tmp;

	return list;
}

/*
 * Return the pointer associated with the key.
 */
proxy_t *proxylist_get(proxylist_const_t list, const unsigned long key) {
	proxylist_const_t t = list;

	while (t) {
		if (t->key == key)
			break;
		t = t->next;
	}

	return (t == NULL ? NULL : t->proxy);
}

/*
 * Return the pointer of the element next to the one associated with the key.
 * If it reaches the end of list or key is not found it returns the first element.
 */
proxylist_const_t proxylist_get_next(proxylist_const_t list, const unsigned long key) {
	proxylist_const_t t = list;

	while (t) {
		if (t->key == key)
			break;
		t = t->next;
	}

	return (t == NULL || t->next == NULL ? list : t->next);
}

/*
 * For debugging purposes - dump the entire contents
 * of a proxy list.
 */
void proxylist_dump(proxylist_const_t list) {
	proxylist_const_t t;

	t = list;
	while (t) {
		if (t->proxy->type == DIRECT)
			printf("List data: %lu => DIRECT\n", t->key);
		else
			printf("List data: %lu => %s:%d\n", t->key, t->proxy->hostname, t->proxy->port);
		t = t->next;
	}
}

/*
 * Free the list of proxy_t data.
 */
void proxylist_free(proxylist_t list, int free_proxy) {
	while (list) {
		proxylist_t t = list->next;
		if (free_proxy) {
			proxy_t *proxy = list->proxy;
			freeaddrinfo(proxy->addresses);
			free(proxy);
		}
		free(list);

		list = t;
	}
}

/*
 * Parse proxy parameter and add it to the global list.
 */
int parent_add(const char *parent, int port) {
	char *spec;
	char *tmp;
	proxy_t *proxy;

	/*
	 * Check format and parse it.
	 */
	spec = strdup(parent);
	const char *q = strrchr(spec, ':');
	if (q != NULL || port) {
		int p;
		p = (q != NULL) ? (int)(q - spec) : (int)strlen(spec);

		if(spec[0] == '[' && spec[p-1] == ']') {
			tmp = substr(spec, 1, p-2);
		} else {
			tmp = substr(spec, 0, p);
		}

		if (q != NULL)
			port = atoi(spec+p+1);

		if (!port) {
			syslog(LOG_ERR, "Invalid port in proxy address %s\n", spec);
			myexit(1);
		}
	} else {
		syslog(LOG_ERR, "Port not found in proxy address %s\n", spec);
		myexit(1);
	}

	proxy = (proxy_t *)zmalloc(sizeof(proxy_t));
	proxy->type = PROXY;
	strlcpy(proxy->hostname, tmp, sizeof(proxy->hostname));
	proxy->port = port;
	proxy->resolved = 0;
	proxy->addresses = NULL;
	parent_list = proxylist_add(parent_list, ++parent_count, proxy);

	free(spec);
	free(tmp);
	return parent_count;
}

/*
 * Returns non zero if the global proxy list is not empty.
 */
int parent_available(void) {
	return parent_count > 0;
}

/*
 * Frees the global proxy list.
 */
void parent_free(void) {
	paclist_free(pac_list);
	proxylist_free(parent_list, 1);
}

/*
 * Create list of proxy_t structs parsed from the PAC string returned
 * by Pac.
 * TODO: Harden against malformed pacp_str.
 */
paclist_t paclist_create(const char *pacp_str) {
	paclist_t tmp;
	proxylist_t plist = NULL;
	int plist_count = 0;
	char *pacp_tmp = NULL;
	char *pacp_start = NULL;
	char *cur_proxy = NULL;

	if (pacp_str == NULL) {
		return NULL;
	}

	/* Make a copy of shared PAC string pacp_str (coming
	 * from pac) to avoid manipulation by strsep.
	 */
	pacp_start = strdup(pacp_str);
	pacp_tmp = pacp_start; // save the pointer to this buffer so we can free it

	cur_proxy = strsep(&pacp_tmp, ";");

	if (debug)
		printf("Parsed PAC Proxies:\n");

	while (cur_proxy != NULL) {
		enum proxy_type_t type = DIRECT; // default is DIRECT
		char *type_str = NULL;
		char *hostname = NULL;
		char *port = NULL;
		proxy_t *proxy;

		/* skip whitespace after semicolon */
		if (*cur_proxy == ' ')
			cur_proxy = cur_proxy + 1;

		type_str = strsep(&cur_proxy, " ");
		if (strcmp(type_str, "PROXY") == 0) {
			type = PROXY; // TODO: support more types
			hostname = strsep(&cur_proxy, ":");
			port = cur_proxy; // last token is always the port
		}

		if (debug) {
			if (type != DIRECT) {
				printf("   %s %s %s\n", type_str, hostname, port);
			} else {
				printf("   %s\n", type_str);
			}
		}

		proxylist_t p = parent_list;
		if (type == PROXY) {
			int iport = atoi(port);
			while (p != NULL && !(p->proxy->type == type && p->proxy->port == iport && !strcmp(p->proxy->hostname, hostname)))
					p = p->next;
			if (p == NULL) {
				pthread_mutex_lock(&parent_mtx);
				parent_add(hostname, iport);
				proxy = proxylist_get(parent_list, parent_count);
				plist = proxylist_add(plist, parent_count, proxy);
				pthread_mutex_unlock(&parent_mtx);
			}
		} else { // type == DIRECT
			while (p != NULL && p->proxy->type != type)
				p = p->next;
			if (p == NULL) {
				proxy = (proxy_t *)zmalloc(sizeof(proxy_t));
				proxy->type = DIRECT;
				
				pthread_mutex_lock(&parent_mtx);
				++parent_count;
				parent_list = proxylist_add(parent_list, parent_count, proxy);
				plist = proxylist_add(plist, parent_count, proxy);
				pthread_mutex_unlock(&parent_mtx);
			}
		}
		if (p != NULL)
			plist = proxylist_add(plist, p->key, p->proxy);

		++plist_count;
		cur_proxy = strsep(&pacp_tmp, ";"); /* get next proxy */
	}

	if (debug) {
		printf("Created PAC list with %d item(s):\n", plist_count);
		proxylist_dump(plist);
	}

	free(pacp_start);

	tmp = zmalloc(sizeof(struct paclist_s));
	tmp->pacstr = pacp_str;
	tmp->proxylist = plist;
	tmp->proxycurr = 0;
	tmp->count = plist_count;
	tmp->next = NULL;

	return tmp;
}

/*
 * Returns the list of proxies associated with the pac string,
 * if it is not available it is created and added to the global
 * list of pac proxies lists.
 */
paclist_t paclist_get(const char *pacp_str) {
	paclist_t tmp;
	paclist_t p = pac_list;

	while (p) {
		if (strcmp(pacp_str, p->pacstr) == 0) {
			if (debug)
				printf("Found PAC list for [%s]\n", pacp_str);
			return p;
		}
		p = p->next;
	}

	tmp = paclist_create(pacp_str);

	if (pac_list == NULL) {
		pac_list = tmp;
	} else {
		p = pac_list;
		while (p->next)
			p = p->next;
		p->next = tmp;
	}

	if (debug)
		printf("New PAC list for [%s]\n", pacp_str);

	return tmp;
}

/*
 * Frees the list of pac proxies lists.
 */
void paclist_free(paclist_t paclist) {
	while (paclist) {
		paclist_t t = paclist->next;
		proxylist_free(paclist->proxylist, 0);
		free(paclist);
		paclist = t;
	}
}

/*
 * Connect to the selected proxy. If the request fails, pick next proxy
 * in the line. Each request scans the whole list until all items are tried
 * or a working proxy is found, in which case it is selected and used by
 * all threads until it stops working. Then the search starts again.
 *
 * Writes required credentials into passed auth_s structure
 *
 * Returns >0 valid handle
 * Returns -1 if it fails connection with proxy
 * Returns -2 if connection is DIRECT
 */
int proxy_connect(struct auth_s *credentials, const char* url, const char* hostname) {
	proxylist_const_t proxylist;
	proxylist_const_t p;
	unsigned long proxycurr;
	proxy_t *proxy;
	int i;
	int loop = 0;
	int proxycount = 0;

	paclist_t paclist = NULL;
	const char *pacp_str;
	if (pac_initialized) {
		/*
		 * Create proxy list for request from PAC file.
		 */
		pthread_mutex_lock(&pac_mtx);
		pacp_str = pac_find_proxy(url, hostname);
		pthread_mutex_unlock(&pac_mtx);

		paclist = paclist_get(pacp_str);
		proxylist = paclist->proxylist;
		proxycurr = paclist->proxycurr;
		proxycount = paclist->count;
	} else {
		proxylist = parent_list;
		proxycurr = parent_curr;
		proxycount = parent_count;
	}

	if (proxycurr == 0 && proxylist) {
		proxycurr = proxylist->key;
	}

	do {
		pthread_mutex_lock(&parent_mtx);
		proxy = proxylist_get(proxylist, proxycurr);
		if (proxy &&
			proxy->type == PROXY &&
			proxy->resolved == 0) {
			if (debug)
				printf("Resolving proxy %s...\n", proxy->hostname);
			if (so_resolv(&proxy->addresses, proxy->hostname, proxy->port)) {
				proxy->resolved = 1;
			} else {
				syslog(LOG_ERR, "Cannot resolve proxy %s\n", proxy->hostname);
			}
		}
		pthread_mutex_unlock(&parent_mtx);

		if (proxy && proxy->type == DIRECT)
			return -2;

		i = -1;
		if (proxy && proxy->resolved != 0)
			i = so_connect(proxy->addresses);

		/*
		 * Resolve or connect failed?
		 */
		if (i < 0) {
			p = proxylist_get_next(proxylist, proxycurr);
			if (p && p->proxy) {
				proxycurr = p->key;
				proxy = p->proxy;
				syslog(LOG_ERR, "Proxy connect failed, will try %s:%d\n", proxy->hostname, proxy->port);
			}
#if config_gss == 1
		} else {
			//kerberos needs the hostname of the parent proxy for generate the token, so we keep it
			curr_proxy = proxy;
#endif
		}
	} while (i < 0 && ++loop < proxycount);

	if (i < 0 && loop >= proxycount)
		syslog(LOG_ERR, "No proxy on the list works. You lose.\n");

	/*
	 * We have to invalidate the cached connections if we moved to a different proxy
	 */
	if (parent_curr != proxycurr) {
		pthread_mutex_lock(&connection_mtx);
		plist_const_t list = connection_list;
		while (list) {
			plist_const_t tmp = list->next;
			close(list->key);
			list = tmp;
		}
		plist_free(connection_list);
		pthread_mutex_unlock(&connection_mtx);

		pthread_mutex_lock(&parent_mtx);
		parent_curr = proxycurr;
		if (pac_initialized && paclist)
			paclist->proxycurr = proxycurr;
		pthread_mutex_unlock(&parent_mtx);
	}

	if (i >= 0 && credentials != NULL)
		copy_auth(credentials, g_creds, /* fullcopy */ !ntlmbasic);

	return i;
}

/*
 * Send request, read reply, if it contains NTLM challenge, generate final
 * NTLM auth message and insert it into the original client header,
 * which is then processed by caller himself.
 *
 * If response is present, we fill in proxy's reply. Caller can tell
 * if auth was required or not from response->code. If not, caller has
 * a full reply to forward to client.
 *
 * Return 0 in case of network error, 1 when proxy replies
 *
 * Caller must init & free "request" and "response" (if supplied)
 *
 */
int proxy_authenticate(int *sd, rr_data_t request, rr_data_t response, struct auth_s *credentials) {
	char *tmp;
	char *buf;
	char *challenge;
	rr_data_t auth;
	int len;

	int pretend407 = 0;
	int rc = 0;
	size_t bufsize = BUFSIZE;
	buf = zmalloc(bufsize);

#if config_gss == 1
	if(g_creds->haskrb && acquire_kerberos_token(curr_proxy->hostname, credentials, &buf, &bufsize)) {
		//pre auth, we try to authenticate directly with kerberos, without to ask if auth is needed
		//we assume that if kdc releases a ticket for the proxy, then the proxy is configured for kerberos auth
		//drawback is that later in the code cntlm logs that no auth is required because we have already authenticated
		if (debug)
			printf("Using Negotiation ...\n");
	}
	else {
#endif

		strlcpy(buf, "NTLM ", bufsize);
		len = ntlm_request(&tmp, credentials);
		if (len) {
			to_base64(MEM(buf, uint8_t, 5), MEM(tmp, uint8_t, 0), len, bufsize-5);
			free(tmp);
		}

#if config_gss == 1
	}
#endif

	auth = dup_rr_data(request);
	auth->headers = hlist_mod(auth->headers, "Proxy-Authorization", buf, 1);

	if (HEAD(request) || http_has_body(request, response) != 0) {
		/*
		 * There's a body - make this request just a probe. Do not send any body. If no auth
		 * is required, we let our caller send the reply directly to the client to avoid
		 * another duplicate request later (which traditionally finishes the 2nd part of
		 * NTLM handshake). Without auth, there's no need for the final request.
		 *
		 * However, if client has a body, we make this request without it and let caller do
		 * the second request in full. If we did it here, we'd have to cache the request
		 * body in memory (even chunked) and carry it around. Not practical.
		 *
		 * When caller sees 407, he makes the second request. That's why we pretend a 407
		 * in this situation. Without it, caller wouldn't make it, sending the client a
		 * reply to our PROBE, not the real request.
		 *
		 * The same for HEAD requests - at least one ISA doesn't allow making auth
		 * request using HEAD!!
		 */
		if (debug)
			printf("Will send just a probe request.\n");
		pretend407 = 1;
	}

	/*
	 * For broken ISA's that don't accept HEAD in auth request
	 */
	if (HEAD(request)) {
		free(auth->method);
		auth->method = strdup("GET");
	}

	auth->headers = hlist_mod(auth->headers, "Content-Length", "0", 1);
	auth->headers = hlist_del(auth->headers, "Transfer-Encoding");

	if (debug) {
		printf("\nSending PROXY auth request...\n");
		printf("HEAD: %s %s %s\n", auth->method, auth->url, auth->http);
		hlist_dump(auth->headers);
	}

	if (!headers_send(*sd, auth)) {
		close(*sd);
		goto bailout;
	}

	if (debug)
		printf("\nReading PROXY auth response...\n");

	/*
	 * Return response if requested. "auth" is used to get it,
	 * so make it point to the caller's structure.
	 */
	if (response) {
		free_rr_data(&auth);
		auth = response;
	}

	reset_rr_data(auth);
	if (!headers_recv(*sd, auth)) {
		close(*sd);
		goto bailout;
	}

	if (debug)
		hlist_dump(auth->headers);

	rc = 1;

	/*
	 * Auth required?
	 */
	if (auth->code == 407) {
		if (!http_body_drop(*sd, auth)) {				// FIXME: if below fails, we should forward what we drop here...
			rc = 0;
			close(*sd);
			goto bailout;
		}
		tmp = hlist_get(auth->headers, "Proxy-Authenticate");

		if (tmp) {
#if config_gss == 1
			if(g_creds->haskrb && strncasecmp(tmp, "NEGOTIATE", 9) == 0 && acquire_kerberos_token(curr_proxy->hostname, credentials, &buf, &bufsize)) {
				if (debug)
					printf("Using Negotiation ...\n");

				request->headers = hlist_mod(request->headers, "Proxy-Authorization", buf, 1);
			}
			else {
#endif
				challenge = zmalloc(strlen(tmp) + 5 + 1);
				len = from_base64(challenge, tmp + 5);
				if (len > NTLM_CHALLENGE_MIN) {
					tmp = NULL;
					len = ntlm_response(&tmp, challenge, len, credentials);
					if (len > 0) {
						strlcpy(buf, "NTLM ", bufsize);
						to_base64(MEM(buf, uint8_t, 5), MEM(tmp, uint8_t, 0), len, bufsize-5);
						request->headers = hlist_mod(request->headers, "Proxy-Authorization", buf, 1);
						free(tmp);
					} else {
						syslog(LOG_ERR, "No target info block. Cannot do NTLMv2!\n");
						free(challenge);
						free(tmp);
						close(*sd);
						goto bailout;
					}
				} else {
					syslog(LOG_ERR, "Proxy returning invalid challenge!\n");
					free(challenge);
					close(*sd);
					goto bailout;
				}

				free(challenge);
#if config_gss == 1
			}
#endif
		} else {
			syslog(LOG_WARNING, "No Proxy-Authenticate, NTLM/Negotiate not supported?\n");
		}
	} else if (pretend407) {
		if (debug)
			printf("Client %s - forcing second request.\n", HEAD(request) ? "sent HEAD" : "has a body");
		if (response)
			response->code = 407;				// See explanation above
		if (!http_body_drop(*sd, auth)) {
			rc = 0;
			close(*sd);
			goto bailout;
		}
	}

	/*
	 * Did proxy closed connection? It's our fault, reconnect for the caller.
	 */
	if (so_closed(*sd)) {
		if (debug)
			printf("Proxy closed on us, reconnect.\n");
		close(*sd);
		*sd = proxy_connect(credentials, request->url, request->hostname);
		if (*sd < 0) {
			rc = 0;
			goto bailout;
		}
	}

bailout:
	if (!response)
		free_rr_data(&auth);

	free(buf);

	return rc;
}
