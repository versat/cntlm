/*
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
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <string.h>
#include <strings.h>
#include <assert.h>

#include "forward.h"
#include "direct.h"
#include "globals.h"
#include "http.h"
#include "socket.h"
#include "scanner.h"
#include "pages.h"
#include "proxy.h"

/*
 * Forwarding thread. Connect to the proxy, process auth then
 * request. If pac_aux is non-null, use this proxy over the static
 * configured proxies.
 *
 * First read request, then call proxy_authenticate() which will send
 * the request. If proxy returns 407, it will compute NTLM reply and
 * return authenticated request to us. If proxy returns full response
 * (no auth needed), it returns the full reply. Then we just forward
 * the reply to client OR make the request again with properly auth'd
 * headers provided by proxy_authenticate().
 *
 * We loop while we see Connection: keep-alive, thus making sure clients
 * can have uninterrupted conversations with a web server. Proxy-Connection
 * is not our concern, it's handled in the caller, proxy_thread(). If it's
 * present, however, we cache the auth'd proxy connection for reuse.
 *
 * Some proxies return Connection: keep-alive even when not requested and
 * would make us loop indefinitely. Because of that, we remember which server
 * we're talking to and if that changes, we return the request to be processed
 * by our caller.
 *
 * Caller decides which URL's to forward and which to process directly, that's
 * also why we return the request if the server name changes.
 *
 * We return NULL when we're finished or a pointer to another request.
 * Returned request means server name has changed and needs to be checked
 * against NoProxy exceptions.
 *
 * thread_data is NOT freed
 * request is NOT freed
 * pac_aux is NOT freed
 */
rr_data_t forward_request(void *thread_data, rr_data_t request) {
	int i;
	int loop;
	int plugin;
	int retry = 0;
	int *rsocket[2];
	int *wsocket[2];
	rr_data_t data[2] = {NULL, NULL};
	rr_data_t rc = NULL;
	hlist_t tl;
	char *tmp;
	struct auth_s *tcreds = NULL;						/* Per-thread credentials */
	char *hostname = NULL;
	int proxy_alive;
	int conn_alive;
	int authok;
	int noauth;
	int was_cached;

	int sd;
	assert(thread_data != NULL);
	int cd = ((struct thread_arg_s *)thread_data)->fd;
	char saddr[INET6_ADDRSTRLEN] = {0};
	INET_NTOP(&((struct thread_arg_s *)thread_data)->addr, saddr, INET6_ADDRSTRLEN);

beginning:
	sd = 0;
	was_cached = noauth = authok = proxy_alive = 0;

	rsocket[0] = wsocket[1] = &cd;
	rsocket[1] = wsocket[0] = &sd;

	if (debug) {
		printf("Thread processing%s...\n", retry ? " (retry)" : "");
		pthread_mutex_lock(&connection_mtx);
		plist_dump(connection_list);
		pthread_mutex_unlock(&connection_mtx);
	}

	/*
	 * NTLM credentials for purposes of this thread (tcreds) are given to
	 * us by proxy_connect() or retrieved from connection cache.
	 *
	 * Ultimately, the source for creds is always proxy_connect(), but when
	 * we cache a connection, we store creds associated with it in the
	 * cache as well, in case we'll need them.
	 */
	pthread_mutex_lock(&connection_mtx);
	i = plist_pop(&connection_list, (void **)&tcreds);
	pthread_mutex_unlock(&connection_mtx);
	if (i) {
		if (debug)
			printf("Found authenticated connection %d!\n", i);
		sd = i;
		authok = 1;
		was_cached = 1;
	} else {
		tcreds = zmalloc(sizeof(struct auth_s));
		sd = proxy_connect(tcreds, request->url, request->hostname);
		if (sd == -2) {
			rc = (void *)-2;
			goto bailout;
		}
		if (sd < 0) {
			tmp = gen_502_page(request->http, "Parent proxy unreachable");
			(void) write_wrapper(cd, tmp, strlen(tmp));
			free(tmp);
			rc = (void *)-1;
			goto bailout;
		}
	}

	/*
	 * Each thread only serves req's for one hostname. If hostname changes,
	 * we return request to our caller for a new direct/forward decision.
	 */
	if (!hostname && request->hostname) {
		hostname = strdup(request->hostname);
	}

	do {
		/*
		 * data[0] is for the first loop pass
		 *   - first do {} loop iteration uses request passed from caller,
		 *     in subsequent iterations we read the request headers from the client
		 *   - if not already done, we try to authenticate the connection
		 *   - we send the request headers to the proxy with HTTP body, if present
		 *
		 * data[1] is for the second pass
		 *   - read proxy response
		 *   - forward it to the client with HTTP body, if present
		 *
		 * There is one goto to "beginning":
		 *   - jump here to retry request (when cached connection timed out
		 *     or we thought proxy was notauth, but got 407)
		 *
		 * During 1st iter. of inner loop (loop == 0), when we detect
		 * that auth isn't required by proxy, we set loop = 1 and
		 * the reply to our auth attempt (containing valid response) is sent to
		 * client directly without us making a request a second time.
		 */
		if (request) {
			if (retry)
				data[0] = request;				// Got from inside the loop = retry (must free ourselves)
			else
				data[0] = dup_rr_data(request);			// Got from caller (make a dup, caller will free)
			request = NULL;						// Next time, just alloc empty structure
		} else {
			data[0] = new_rr_data();
		}
		data[1] = new_rr_data();

		retry = 0;
		proxy_alive = 0;
		conn_alive = 0;
		loop = 0; // 0 = request from client; 1 = response from server

		while (loop < 2) {
			if (data[loop]->empty) {				// Isn't this the first loop with request supplied by caller?
				if (debug) {
					printf("\n******* Round %d C: %d, S: %d (authok=%d, noauth=%d) *******\n", loop+1, cd, sd, authok, noauth);
					printf("Reading headers (%d)...\n", *rsocket[loop]);
				}
				if (!headers_recv(*rsocket[loop], data[loop])) {
					free_rr_data(&data[0]);
					free_rr_data(&data[1]);
					rc = (void *)-1;
					/* error page */
					goto bailout;
				}
			}

			/*
			 * Check whether this new request still talks to the same server as previous.
			 * If no, return request to caller, he must decide on forward or direct
			 * approach.
			 *
			 * If we're here, previous request loop must have been proxy keep-alive
			 * (we're looping only if proxy_alive) or this is the first loop since
			 * we were called. If former, set proxy_alive=1 to cache the connection.
			 */
			if (loop == 0 && hostname && data[0]->hostname
					&& strcasecmp(hostname, data[0]->hostname) != 0) {
				if (debug)
					printf("\n******* F RETURN: %s *******\n", data[0]->url);
				if (authok && data[0]->http_version >= 11
						&& (hlist_subcmp(data[0]->headers, "Proxy-Connection", "keep-alive")
							|| hlist_subcmp(data[0]->headers, "Connection", "keep-alive")))
					proxy_alive = 1;

				rc = dup_rr_data(data[0]);
				free_rr_data(&data[0]);
				free_rr_data(&data[1]);
				goto bailout;
			}

			if (debug)
				hlist_dump(data[loop]->headers);

			if (loop == 0 && data[0]->req) {
				syslog(LOG_DEBUG, "%s %s %s", saddr, data[0]->method, data[0]->url);
			}

			/*
			 * Modify request headers.
			 *
			 * Try to request keep-alive for every client supporting HTTP/1.1+. We keep them in a pool
			 * for future reuse.
			 */
			if (loop == 0 && data[0]->req) {
				/*
				 * NTLM-to-Basic
				 */
				if (http_parse_basic(data[loop]->headers, "Proxy-Authorization", tcreds) > 0) {
					if (debug)
						printf("NTLM-to-basic: Credentials parsed: %s\\%s at %s\n",
								tcreds->domain, tcreds->user, tcreds->workstation);
				} else if (ntlmbasic) {
					if (debug)
						printf("NTLM-to-basic: Returning client auth request.\n");

					tmp = gen_407_page(data[loop]->http);
					(void) write_wrapper(cd, tmp, strlen(tmp));
					free(tmp);

					free_rr_data(&data[0]);
					free_rr_data(&data[1]);
					rc = (void *)-1;
					goto bailout;
				}

				/*
				 * Header replacement implementation
				 */
				tl = header_list;
				while (tl) {
					data[0]->headers = hlist_mod(data[0]->headers, tl->key, tl->value, 1);
					tl = tl->next;
				}

				/*
				 * Force proxy keep-alive if the client can handle it (HTTP >= 1.1)
				 */
				if (data[0]->http_version >= 11)
					data[0]->headers = hlist_mod(data[0]->headers, "Proxy-Connection", "keep-alive", 1);

				/*
				 * Also remove runaway P-A from the client (e.g. Basic from N-t-B), which might
				 * cause some ISAs to deny us, even if the connection is already auth'd.
				 */
				while (hlist_get(data[loop]->headers, "Proxy-Authorization")) {
					data[loop]->headers = hlist_del(data[loop]->headers, "Proxy-Authorization");
				}
			}

			/*
			 * Got request from client and connection is not yet authenticated?
			 * This can happen only with non-cached connections.
			 */
			if (loop == 0 && data[0]->req && !authok && !noauth) {
				if (!proxy_authenticate(wsocket[0], data[0], data[1], tcreds)) {
					if (debug)
						printf("Proxy auth connection error.\n");
					free_rr_data(&data[0]);
					free_rr_data(&data[1]);
					rc = (void *)-1;
					/* error page */
					goto bailout;
				}

				/*
				 * !!! data[1] is now filled by proxy_authenticate() !!!
				 * !!! with proxy's reply to our first (auth) req.   !!!
				 * !!! that's why we reset data[1] below             !!!
				 *
				 * Reply to auth request wasn't 407? Then auth is not required,
				 * let's set loop = 1 so that we forward reply to client
				 * Also just forward if proxy doesn't reply with keep-alive,
				 * because without it, NTLM auth wouldn't work anyway.
				 *
				 * Let's decide proxy doesn't want any auth if it returns a
				 * non-error reply. Next rounds will be faster.
				 */
				if (data[1]->code != 407) {		// || !hlist_subcmp(data[1]->headers, "Proxy-Connection", "keep-alive")) {
					if (debug)
						printf("Proxy auth not requested - just forwarding.\n");
					if (data[1]->code < 400)
						noauth = 1;
					loop = 1;
				} else {
					/*
					* If we're continuing normally, we have to free possible
					* auth response from proxy_authenticate() in data[1]
					*/
					reset_rr_data(data[1]);
				}
			}

			/*
			 * Is final reply from proxy still 407 denied? If this is a cached
			 * connection or we thought proxy was noauth (so we didn't auth), make a new
			 * connect and try to auth.
			 */
			if (loop == 1 && data[1]->code == 407 && (was_cached || noauth)) {
				if (debug)
					printf("\nFinal reply is 407 - retrying (cached=%d, noauth=%d).\n", was_cached, noauth);
				if (tcreds)
					free(tcreds);

				retry = 1;
				request = data[0];
				free_rr_data(&data[1]);
				close(sd);
				goto beginning;
			}

			/*
			 * Was the request first and did we authenticate with proxy?
			 * Remember not to authenticate this connection any more.
			 */
			if (loop == 1 && !noauth && data[1]->code != 407)
				authok = 1;

			/*
			 * This is to make the ISA AV scanner bullshit transparent. If the page
			 * returned is scan-progress-html-fuck instead of requested file/data, parse
			 * it, wait for completion, make a new request to ISA for the real data and
			 * substitute the result for the original response html-fuck response.
			 */
			plugin = PLUG_ALL;
			if (loop == 1 && scanner_plugin) {
				plugin = scanner_hook(data[0], data[1], tcreds, *wsocket[loop], rsocket[loop], scanner_plugin_maxsize);
			}

			/*
			 * Check if we should loop for another request.  Required for keep-alive
			 * connections, client might really need a non-interrupted conversation.
			 *
			 * We check only server reply for keep-alive, because client may want it,
			 * but it's not gonna happen unless server agrees.
			 */
			if (loop == 1) {
				conn_alive = hlist_subcmp(data[1]->headers, "Connection", "keep-alive");
				if (!conn_alive && !(CONNECT(data[0]) && data[1]->code == 200))
					data[1]->headers = hlist_mod(data[1]->headers, "Connection", "close", 1);

				/*
				 * Remove all Proxy-Authenticate headers from proxy
				 */
				while (hlist_get(data[loop]->headers, "Proxy-Authenticate")) {
					data[loop]->headers = hlist_del(data[loop]->headers, "Proxy-Authenticate");
				}

				/*
				 * Are we returning 407 to the client? Substitute his request
				 * by our BASIC translation request.
				 */
				if (data[1]->code == 407) {
					data[1]->headers = hlist_mod(data[1]->headers, "Proxy-Authenticate", "Basic realm=\"Auth failed, you can try other credentials\"", 1);
				}
			}

			if (plugin & PLUG_SENDHEAD) {
				if (debug) {
					printf("Sending headers (%d)...\n", *wsocket[loop]);
					if (loop == 0) {
						printf("HEAD: %s %s %s\n", data[loop]->method, data[loop]->url, data[loop]->http);
						hlist_dump(data[loop]->headers);
					}
				}

				/*
				 * Forward client's headers to the proxy and vice versa; proxy_authenticate()
				 * might have by now prepared 1st and 2nd auth steps and filled our headers with
				 * the 3rd, final, NTLM message.
				 */
				if (!headers_send(*wsocket[loop], data[loop])) {
					free_rr_data(&data[0]);
					free_rr_data(&data[1]);
					rc = (void *)-1;
					/* error page */
					goto bailout;
				}
			}

			/*
			 * Was the request CONNECT and proxy agreed?
			 */
			if (loop == 1 && CONNECT(data[0]) && data[1]->code == 200) {
				if (debug)
					printf("Ok CONNECT response. Tunneling...\n");

				tunnel(cd, sd);
				free_rr_data(&data[0]);
				free_rr_data(&data[1]);
				rc = (void *)-1;
				goto bailout;
			}

			if ((plugin & PLUG_SENDDATA) && !http_body_send(*wsocket[loop], *rsocket[loop], data[0], data[1])) {
				free_rr_data(&data[0]);
				free_rr_data(&data[1]);
				rc = (void *)-1;
				goto bailout;
			}

			/*
			 * Proxy-Connection: keep-alive is taken care of in our caller as I said,
			 * but we do return when we see proxy is closing. Next headers_recv() would
			 * fail and we'd exit anyway.
			 *
			 * This way, we also tell our caller that proxy keep-alive is impossible.
			 */
			if (loop == 1) {
				proxy_alive = hlist_subcmp(data[1]->headers, "Proxy-Connection", "keep-alive")
					&& data[0]->http_version >= 11;
				if (proxy_alive) {
					data[1]->headers = hlist_mod(data[1]->headers, "Proxy-Connection", "keep-alive", 1);
					data[1]->headers = hlist_mod(data[1]->headers, "Connection", "keep-alive", 1);
				} else {
					data[1]->headers = hlist_mod(data[1]->headers, "Proxy-Connection", "close", 1);
					data[1]->headers = hlist_mod(data[1]->headers, "Connection", "close", 1);
					if (debug)
						printf("PROXY CLOSING CONNECTION\n");
					rc = (void *)-1;
				}
			}

			++loop;
		}

		free_rr_data(&data[0]);
		free_rr_data(&data[1]);

	/*
	 * Checking conn_alive && proxy_alive is sufficient,
	 * so_closed() just eliminates loops that we know would fail.
	 */
	} while (conn_alive && proxy_alive && !so_closed(sd) && !so_closed(cd) && !serialize);

bailout:
	if (hostname)
		free(hostname);

	if (debug) {
		printf("forward_request: palive=%d, authok=%d, ntlm=%d, closed=%d\n", proxy_alive, authok, ntlmbasic, so_closed(sd));
		printf("\nThread finished.\n");
	}

	if (proxy_alive && authok && !ntlmbasic && !so_closed(sd)) {
		if (debug)
			printf("Storing the connection for reuse (%d:%d).\n", cd, sd);
		pthread_mutex_lock(&connection_mtx);
		connection_list = plist_add(connection_list, sd, (void *)tcreds);
		pthread_mutex_unlock(&connection_mtx);
	} else {
		free(tcreds);
		if (sd >= 0) {
			close(sd);
		}
	}

	return rc;
}

/*
 * Auth connection "sd" and try to return negotiated CONNECT
 * connection to a remote host:port (thost).
 *
 * Return 1 for success, 0 failure.
 */
int prepare_http_connect(int sd, struct auth_s *credentials, const char *thost) {
	rr_data_t data1;
	rr_data_t data2;
	int rc = 0;
	hlist_t tl;
	char *pos;

	if (!sd || !thost || !strlen(thost))
		return 0;

	data1 = new_rr_data();
	data2 = new_rr_data();

	data1->req = 1;
	data1->method = strdup("CONNECT");
	data1->url = strdup(thost);
	data1->hostname = strdup(thost);
	if ((pos = strchr(data1->hostname, ':')) != NULL) { // separate port
		*pos = 0;
		data1->port = atoi(pos + 1);
	}
	data1->http = strdup("HTTP/1.1");
	data1->headers = hlist_mod(data1->headers, "Proxy-Connection", "keep-alive", 1);

	/*
	 * Header replacement
	 */
	tl = header_list;
	while (tl) {
		data1->headers = hlist_mod(data1->headers, tl->key, tl->value, 1);
		tl = tl->next;
	}

	if (debug)
		printf("Starting authentication...\n");

	if (proxy_authenticate(&sd, data1, data2, credentials)) {
		/*
		 * Let's try final auth step, possibly changing data2->code
		 */
		if (data2->code == 407) {
			if (debug) {
				printf("Sending real request:\n");
				hlist_dump(data1->headers);
			}
			if (!headers_send(sd, data1)) {
				if (debug)
					printf("Sending request failed!\n");
				free_rr_data(&data1);
				free_rr_data(&data2);
				return rc;
			}

			if (debug)
				printf("\nReading real response:\n");
			reset_rr_data(data2);
			if (!headers_recv(sd, data2)) {
				if (debug)
					printf("Reading response failed!\n");
				free_rr_data(&data1);
				free_rr_data(&data2);
				return rc;
			}
			if (debug)
				hlist_dump(data2->headers);
		}

		if (data2->code == 200) {
			if (debug)
				printf("Ok CONNECT response. Tunneling...\n");
			rc = 1;
		} else if (data2->code == 407) {
			syslog(LOG_ERR, "Authentication for tunnel %s failed!\n", thost);
		} else {
			syslog(LOG_ERR, "Request for CONNECT to %s denied!\n", thost);
		}
	} else
		syslog(LOG_ERR, "Tunnel requests failed!\n");

	free_rr_data(&data1);
	free_rr_data(&data2);

	return rc;
}

int forward_tunnel(void *thread_data) {
	struct auth_s *tcreds;
	int sd;

	assert(thread_data != NULL);
	int cd = ((struct thread_arg_s *)thread_data)->fd;
	char *thost = ((struct thread_arg_s *)thread_data)->target;
	char *hostname = strdup(thost);
	char *pos;
	char saddr[INET6_ADDRSTRLEN] = {0};
	INET_NTOP(&((struct thread_arg_s *)thread_data)->addr, saddr, INET6_ADDRSTRLEN);

	tcreds = zmalloc(sizeof(struct auth_s));
	if ((pos = strchr(hostname, ':')) != NULL) // separate port
		*pos = 0;
	sd = proxy_connect(tcreds, thost, hostname);

	if (sd >= 0) {
		syslog(LOG_DEBUG, "%s TUNNEL %s", saddr, thost);

		if (debug)
			printf("Tunneling to %s for client %d...\n", thost, cd);

		if (prepare_http_connect(sd, tcreds, thost))
			tunnel(cd, sd);

		close(sd);
	}

	if (sd != -2) {
		close(cd);
	}

	free(tcreds);
	free(hostname);

	return sd;
}

#define MAGIC_TESTS	5

void magic_auth_detect(const char *url) {
	int nc;
	int ign = 0;
	int found = -1;
	rr_data_t req;
	rr_data_t res;
	const char *pos;
	char *host = NULL;

	struct auth_s *tcreds;
	const int prefs[MAGIC_TESTS][5] = {
		/* NT, LM, NTLMv2, Flags, index to authstr[] */
		{  0,  0,  1,      0,     0 },
		{  1,  1,  0,      0,     1 },
		{  0,  1,  0,      0,     2 },
		{  1,  0,  0,      0,     3 },
		{  2,  0,  0,      0,     4 }
	};

	tcreds = dup_auth(g_creds, /* fullcopy */ 1);

	if (   is_memory_all_zero(tcreds->passnt, ARRAY_SIZE(tcreds->passnt))
		|| is_memory_all_zero(tcreds->passlm, ARRAY_SIZE(tcreds->passlm))
		|| is_memory_all_zero(tcreds->passntlm2, ARRAY_SIZE(tcreds->passntlm2))) {
		printf("Cannot detect NTLM dialect - password or all its hashes must be defined, try -I\n");
		exit(1);
	}

	assert(url != NULL);
	pos = strstr(url, "://");
	if (pos) {
		const char * const tmp = strchr(pos+3, '/');
		host = substr(pos+3, 0, tmp ? (int)(tmp-pos-3) : 0);
	} else {
		fprintf(stderr, "Invalid URL (%s)\n", url);
		free(tcreds);
		return;
	}

	for (int i = 0; i < MAGIC_TESTS && found < 0; ++i) {
		int c;
		res = new_rr_data();
		req = new_rr_data();

		req->req = 1;
		req->method = strdup("GET");
		req->url = strdup(url);
		req->http = strdup("HTTP/1.1");
		req->headers = hlist_add(req->headers, "Proxy-Connection", "keep-alive", HLIST_ALLOC, HLIST_ALLOC);
		req->headers = hlist_add(req->headers, "Host", host, HLIST_ALLOC, HLIST_ALLOC);

		tcreds->hashnt = prefs[i][0];
		tcreds->hashlm = prefs[i][1];
		tcreds->hashntlm2 = prefs[i][2];
		tcreds->flags = prefs[i][3];

		printf("Config profile %2d/%d... ", i+1, MAGIC_TESTS);

		nc = proxy_connect(NULL, url, host);
		if (nc < 0) {
			printf("\nConnection to proxy failed, bailing out\n");
			free_rr_data(&res);
			free_rr_data(&req);
			free(host);
			return;
		}

		c = proxy_authenticate(&nc, req, res, tcreds);
		if (c && res->code != 407) {
			ign++;
			printf("Auth not required (HTTP code: %d)\n", res->code);
			free_rr_data(&res);
			free_rr_data(&req);
			close(nc);
			continue;
		}

		reset_rr_data(res);
		if (!headers_send(nc, req) || !headers_recv(nc, res)) {
			printf("Connection closed!? Proxy doesn't talk to us.\n");
		} else if (res->code == 407) {
			if (hlist_subcmp_all(res->headers, "Proxy-Authenticate", "NTLM") ) {
				printf("Credentials rejected (NTLM allowed)\n");
			} else if (hlist_subcmp_all(res->headers, "Proxy-Authenticate", "BASIC")) {
				printf("Proxy allows BASIC, Cntlm not required so it's not supported\n");
			} else {
				printf("Proxy doesn't allow NTLM, Cntlm won't help\n");
				free_rr_data(&res);
				free_rr_data(&req);
				close(nc);
				break;
			}
		} else {
			printf("OK (HTTP code: %d)\n", res->code);
			if (found < 0) {
				found = i;
			}
		}

		free_rr_data(&res);
		free_rr_data(&req);
		close(nc);
	}

	if (found > -1) {
		const char *authstr[5] = { "NTLMv2", "NTLM", "LM", "NT", "NTLM2SR" };
		printf("----------------------------[ Profile %2d ]------\n", found);
		printf("Auth            %s\n", authstr[prefs[found][4]]);
		if (prefs[found][3])
			printf("Flags           0x%x\n", prefs[found][3]);
		if (prefs[found][0]) {
			char * printbuf = printmem(tcreds->passnt, 16, 8);
			printf("PassNT          %s\n", printbuf);
			free(printbuf);
		}
		if (prefs[found][1]) {
			char * printbuf = printmem(tcreds->passlm, 16, 8);
			printf("PassLM          %s\n", printbuf);
			free(printbuf);
		}
		if (prefs[found][2]) {
			char * printbuf = printmem(tcreds->passntlm2, 16, 8);
			printf("PassNTLMv2      %s\n", printbuf);
			free(printbuf);
		}
		printf("------------------------------------------------\n");
	} else if (ign == MAGIC_TESTS) {
		printf("\nYour proxy is open, you don't need another proxy.\n");
	} else
		printf("\nWrong credentials, invalid URL or proxy doesn't support NTLM.\n");

	if (host)
		free(host);
}
