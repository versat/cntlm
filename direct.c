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

#include <sys/types.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <strings.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>

#include "utils.h"
#include "globals.h"
#include "auth.h"
#include "http.h"
#include "socket.h"
#include "ntlm.h"
#include "direct.h"
#include "pages.h"

int host_connect(const char *hostname, int port) {
	int fd;
	struct addrinfo *addresses;

	errno = 0;
	if (!so_resolv(&addresses, hostname, port)) {
		return -1;
	}

	fd = so_connect(addresses);
	freeaddrinfo(addresses);
	return fd;
}

int www_authenticate(int sd, int cd, rr_data_t request, rr_data_t response, struct auth_s *creds, int probe) {
	char *tmp;
	char *buf;
	char *challenge;
	rr_data_t auth;
	int len;

	int rc = 0;

	buf = zmalloc(BUFSIZE);

	strlcpy(buf, "NTLM ", BUFSIZE);
	len = ntlm_request(&tmp, creds);
	if (len) {
		to_base64(MEM(buf, uint8_t, 5), MEM(tmp, uint8_t, 0), len, BUFSIZE-5);
		free(tmp);
	}

	auth = dup_rr_data(request);
	auth->headers = hlist_mod(auth->headers, "Connection", "keep-alive", 1);
	auth->headers = hlist_mod(auth->headers, "Authorization", buf, 1);
	auth->headers = hlist_mod(auth->headers, "Content-Length", "0", 1);
	auth->headers = hlist_del(auth->headers, "Transfer-Encoding");

	/*
	 * Drop whatever error page server returned, only if we didn't send a HEAD request (probe)
	 * In this case the response can contain a Content-Length > 0 but anyway there is no body.
	 */
	if (!probe && !http_body_drop(sd, response))
		goto bailout;

	if (debug) {
		printf("\nSending WWW auth request...\n");
		hlist_dump(auth->headers);
	}

	if (!headers_send(sd, auth))
		goto bailout;

	if (debug)
		printf("\nReading WWW auth response...\n");

	/*
	 * Get NTLM challenge
	 */
	reset_rr_data(auth);
	if (!headers_recv(sd, auth)) {
		goto bailout;
	}

	if (debug)
		hlist_dump(auth->headers);

	/*
	 * Auth required?
	 */
	if (auth->code == 401) {
		if (!http_body_drop(sd, auth))
			goto bailout;

		tmp = hlist_get(auth->headers, "WWW-Authenticate");
		if (tmp && strlen(tmp) > 6 + 8) {
			challenge = zmalloc(strlen(tmp) + 5 + 1);
			len = from_base64(challenge, tmp + 5);
			if (len > NTLM_CHALLENGE_MIN) {
				tmp = NULL;
				len = ntlm_response(&tmp, challenge, len, creds);
				if (len > 0) {
					strlcpy(buf, "NTLM ", BUFSIZE);
					to_base64(MEM(buf, uint8_t, 5), MEM(tmp, uint8_t, 0), len, BUFSIZE-5);
					request->headers = hlist_mod(request->headers, "Authorization", buf, 1);
					free(tmp);
				} else {
					syslog(LOG_ERR, "No target info block. Cannot do NTLMv2!\n");
					response->errmsg = "Invalid NTLM challenge from web server";
					free(challenge);
					free(tmp);
					goto bailout;
				}
			} else {
				syslog(LOG_ERR, "Server returning invalid challenge!\n");
				response->errmsg = "Invalid NTLM challenge from web server";
				free(challenge);
				goto bailout;
			}

			free(challenge);
		} else {
			syslog(LOG_WARNING, "No challenge in WWW-Authenticate!\n");
			response->errmsg = "Web server reply missing NTLM challenge";
			goto bailout;
		}
	} else {
		goto bailout;
	}

	if (debug)
		printf("\nSending WWW auth...\n");

	if (!headers_send(sd, request)) {
		goto bailout;
	}

	/*
	 * If we sent a HEAD request (probe) this is the moment to send the body of
	 * the original request (we just sent headers with authorization)
	 */
	reset_rr_data(auth);
	if (probe && !http_body_send(sd, cd, request, auth)) {
		goto bailout;
	}

	if (debug)
		printf("\nReading final server response...\n");

	if (!headers_recv(sd, auth)) {
		goto bailout;
	}

	rc = 1;

	if (debug)
		hlist_dump(auth->headers);

bailout:
	if (rc)
		copy_rr_data(response, auth);
	free_rr_data(&auth);
	free(buf);

	return rc;
}

rr_data_t direct_request(void *cdata, rr_data_const_t request) {
	rr_data_t data[2] = { NULL, NULL };
	rr_data_t rc = NULL;
	struct auth_s *tcreds = NULL;
	int *rsocket[2];
	int *wsocket[2];
	int loop;
	int sd;
	char *tmp;
	int probe = 0;

	char *hostname = NULL;
	int port = 0;
	int conn_alive = 0;

	int cd = ((struct thread_arg_s *)cdata)->fd;
	char saddr[INET6_ADDRSTRLEN] = {0};
	INET_NTOP(&((struct thread_arg_s *)cdata)->addr, saddr, INET6_ADDRSTRLEN);

	if (debug)
		printf("Direct thread processing...\n");

	sd = host_connect(request->hostname, request->port);
	if (sd < 0) {
		syslog(LOG_WARNING, "Connection failed for %s:%d (%s)", request->hostname, request->port, strerror(errno));
		tmp = gen_502_page(request->http, strerror(errno));
		(void) write_wrapper(cd, tmp, strlen(tmp)); // We don't really care about the result
		free(tmp);
		rc = (void *)-1;
		goto bailout;
	}

	/*
	 * Now save NTLM credentials for purposes of this thread.
	 * If web auth fails, we'll rewrite them like with NTLM-to-Basic in proxy mode.
	 */
	tcreds = dup_auth(g_creds, /* fullcopy */ 1);

	if (request->hostname) {
		hostname = strdup(request->hostname);
		port = request->port;
	} else {
		tmp = gen_502_page(request->http, "Invalid request URL");
		(void) write_wrapper(cd, tmp, strlen(tmp));
		free(tmp);

		rc = (void *)-1;
		goto bailout;
	}

	do {
		if (request) {
			/*
			* If there's a body make this request just a probe (HEAD request), unless the
			* request is a CONNECT (in which case it is simply tunnelled between client and server).
			* Do not send any body. If no auth is required, then we simply send the original request.
			* If auth is required we send the request body in the 2nd and last part of the
			* NTLM handshake.
			*/
			probe = !CONNECT(request) && http_has_body(request, NULL);
			data[0] = dup_rr_data(request);
			request = NULL;
		} else {
			data[0] = new_rr_data();
		}
		data[1] = new_rr_data();

		rsocket[0] = wsocket[1] = &cd;
		rsocket[1] = wsocket[0] = &sd;

		conn_alive = 0;

		for (loop = 0; loop < 2; ++loop) {
			if (data[loop]->empty) {				// Isn't this the first loop with request supplied by caller?
				if (debug) {
					printf("\n******* Round %d C: %d, S: %d *******\n", loop+1, cd, sd);
					printf("Reading headers (%d)...\n", *rsocket[loop]);
				}
				if (!headers_recv(*rsocket[loop], data[loop])) {
					free_rr_data(&data[0]);
					free_rr_data(&data[1]);
					rc = (void *)-1;
					goto bailout;
				}
			}

			/*
			 * Check whether this new request still talks to the same server as previous.
			 * If no, return request to caller, he must decide on forward or direct
			 * approach.
			 */
			if (loop == 0 && hostname && data[0]->hostname
					&& (strcasecmp(hostname, data[0]->hostname) || port != data[0]->port)) {
				if (debug)
					printf("\n******* D RETURN: %s *******\n", data[0]->url);

				rc = dup_rr_data(data[0]);
				free_rr_data(&data[0]);
				free_rr_data(&data[1]);
				goto bailout;
			}

			if (debug)
				hlist_dump(data[loop]->headers);

			if (loop == 0 && data[0]->req) {
				syslog(LOG_DEBUG, "%s %s %s", saddr, data[0]->method, data[0]->url);

				/*
				 * Convert full proxy request URL into a relative URL
				 * Host header is already inserted by headers_recv()
				 */
				if (data[0]->rel_url) {
					if (data[0]->url)
						free(data[0]->url);
					data[0]->url = strdup(data[0]->rel_url);
				}

				/*
				 * Force proxy keep-alive if the client can handle it (HTTP >= 1.1)
				 */
				if (data[0]->http_version >= 11)
					data[0]->headers = hlist_mod(data[0]->headers, "Connection", "keep-alive", 1);

				/*
				 * Also remove runaway P-A from the client (e.g. Basic from N-t-B), which might
				 * cause some ISAs to deny us, even if the connection is already auth'd.
				 */
				while (hlist_get(data[loop]->headers, "Proxy-Authorization")) {
					data[loop]->headers = hlist_del(data[loop]->headers, "Proxy-Authorization");
				}

				/*
				 * Try to get auth from client if present
				 */
				if (http_parse_basic(data[0]->headers, "Authorization", tcreds) > 0 && debug)
					printf("NTLM-to-basic: Credentials parsed: %s\\%s at %s\n", tcreds->domain, tcreds->user, tcreds->workstation);
			}

			/*
			 * Is this a CONNECT request?
			 */
			if (loop == 0 && CONNECT(data[0])) {
				if (debug)
					printf("CONNECTing...\n");

				data[1]->empty = 0;
				data[1]->req = 0;
				data[1]->code = 200;
				data[1]->msg = strdup("Connection established");
				data[1]->http = strdup(data[0]->http);

				if (headers_send(cd, data[1]))
					tunnel(cd, sd);

				free_rr_data(&data[0]);
				free_rr_data(&data[1]);
				rc = (void *)-1;
				goto bailout;
			}

			if (loop == 1 && data[1]->code == 401 && hlist_subcmp_all(data[1]->headers, "WWW-Authenticate", "NTLM")) {
				/*
				 * Server closing the connection after 401?
				 * Should never happen.
				 */
				if (hlist_subcmp(data[1]->headers, "Connection", "close")) {
					if (debug)
						printf("Reconnect before WWW auth\n");
					close(sd);
					/*
					 * Make sure nobody tries to read the body, particularly http_body_drop():
					 * now that we closed the socket, it would wait indefinitely.
					 */
					data[1]->headers = hlist_mod(data[1]->headers, "Content-Length", "0", 1);
					sd = host_connect(data[0]->hostname, data[0]->port);
					if (sd < 0) {
						tmp = gen_502_page(data[0]->http, "WWW authentication reconnect failed");
						(void) write_wrapper(cd, tmp, strlen(tmp));
						free(tmp);

						free_rr_data(&data[0]);
						free_rr_data(&data[1]);

						rc = (void *)-1;
						goto bailout;
					}
				}
				if (!www_authenticate(*wsocket[0], *rsocket[0], data[0], data[1], tcreds, probe)) {
					if (debug)
						printf("WWW auth connection error.\n");

					tmp = gen_502_page(data[1]->http, data[1]->errmsg ? data[1]->errmsg : "Error during WWW-Authenticate");
					(void) write_wrapper(cd, tmp, strlen(tmp));
					free(tmp);

					free_rr_data(&data[0]);
					free_rr_data(&data[1]);

					rc = (void *)-1;
					goto bailout;
				} else if (data[1]->code == 401) {
					/*
					 * Server giving 401 after auth?
					 * Request basic auth
					 */
					tmp = gen_401_page(data[1]->http, data[0]->hostname, data[0]->port);
					(void) write_wrapper(cd, tmp, strlen(tmp));
					free(tmp);

					free_rr_data(&data[0]);
					free_rr_data(&data[1]);

					rc = (void *)-1;
					goto bailout;
				}
				probe = 0;
			}

			if (loop == 1 && probe) {
				/*
				 * Remote server did not require authentication, so we rewind and start again
				 * sending the original request. If the server closed the connection we must
				 * reopen it. We must also reset response data.
				 */
				if (so_closed(sd)) {
					close(sd);
					sd = host_connect(data[0]->hostname, data[0]->port);
					if (sd < 0) {
						tmp = gen_502_page(data[0]->http, "Connection to remote server failed");
						(void) write_wrapper(cd, tmp, strlen(tmp));
						free(tmp);

						free_rr_data(&data[0]);
						free_rr_data(&data[1]);

						rc = (void *)-1;
						goto bailout;
					}
					syslog(LOG_DEBUG, "server reconnect after probe");
				}
				reset_rr_data(data[1]);
				probe = 0;
				loop = 0;
			}

			/*
			 * Check if we should loop for another request.  Required for keep-alive
			 * connections, client might really need a non-interrupted conversation.
			 *
			 * We default to keep-alive server connections, unless server explicitly
			 * flags closing the connection or we detect a body with unknown size
			 * (end marked by server closing).
			 */
			if (loop == 1) {
				conn_alive = !hlist_subcmp(data[1]->headers, "Connection", "close")
					&& http_has_body(data[0], data[1]) != -1
					&& data[0]->http_version >= 11;
				if (conn_alive) {
					data[1]->headers = hlist_mod(data[1]->headers, "Proxy-Connection", "keep-alive", 1);
					data[1]->headers = hlist_mod(data[1]->headers, "Connection", "keep-alive", 1);
				} else {
					data[1]->headers = hlist_mod(data[1]->headers, "Proxy-Connection", "close", 1);
					data[1]->headers = hlist_mod(data[1]->headers, "Connection", "close", 1);
					rc = (void *)-1;
				}
			}

			if (debug) {
				printf("Sending headers (%d)...\n", *wsocket[loop]);
				if (loop == 0) {
					printf("HEAD: %s %s %s\n", data[loop]->method, data[loop]->url, data[loop]->http);
					hlist_dump(data[loop]->headers);
				}
			}

			if (loop == 0 && probe) {
				/*
				 * The first request has a body, so we must send a HEAD request (probe) first,
				 * to check if the remote server requires authentication, in that case
				 * the body is sent at the end of the NTLM challenge with the correct method
				 */
				rr_data_t auth = dup_rr_data(data[0]);
				free(auth->method);
				auth->method = strdup("HEAD");
				auth->headers = hlist_mod(auth->headers, "Content-Length", "0", 1);
				auth->headers = hlist_del(auth->headers, "Transfer-Encoding");

				if (!headers_send(*wsocket[0], auth)) {
					free_rr_data(&auth);
					free_rr_data(&data[0]);
					free_rr_data(&data[1]);
					rc = (void *)-1;
					goto bailout;
				}
				free_rr_data(&auth);
			} else {
				/*
				* Send headers
				*/
				if (!headers_send(*wsocket[loop], data[loop])) {
					free_rr_data(&data[0]);
					free_rr_data(&data[1]);
					rc = (void *)-1;
					goto bailout;
				}

				if (!http_body_send(*wsocket[loop], *rsocket[loop], data[0], data[1])) {
					free_rr_data(&data[0]);
					free_rr_data(&data[1]);
					rc = (void *)-1;
					goto bailout;
				}
			}
		}

		free_rr_data(&data[0]);
		free_rr_data(&data[1]);

	} while (conn_alive && !so_closed(sd) && !so_closed(cd) && !serialize);

bailout:
	if (tcreds)
		free(tcreds);
	if (hostname)
		free(hostname);

	if (sd >= 0) {
		close(sd);
	}

	return rc;
}

void direct_tunnel(void *thread_data) {
	int sd;
	int port = 0;
	char *pos;
	char *hostname;

	int cd = ((struct thread_arg_s *)thread_data)->fd;
	char *thost = ((struct thread_arg_s *)thread_data)->target;
	char saddr[INET6_ADDRSTRLEN] = {0};
	INET_NTOP(&((struct thread_arg_s *)thread_data)->addr, saddr, INET6_ADDRSTRLEN);

	hostname = strdup(thost);
	if ((pos = strchr(hostname, ':')) != NULL) {
		*pos = 0;
		port = atoi(++pos);
	}

	sd = host_connect(hostname, port);
	if (sd <= 0)
		goto bailout;

	syslog(LOG_DEBUG, "%s FORWARD %s", saddr, thost);

	if (debug)
		printf("Portforwarding to %s for client %d...\n", thost, cd);

	tunnel(cd, sd);

bailout:
	free(hostname);
	if(sd >= 0) {
		close(sd);
	}
	close(cd);

	return;
}
