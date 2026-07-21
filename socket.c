/*
 * These are socket routines for the main module of CNTLM
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

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <syslog.h>

#include "socket.h"

extern int debug;

/*
 * getaddrinfo() wrapper. Return 1 if OK, otherwise 0.
 * Important: Caller is responsible for freeing addresses via freeaddrinfo()!
 */
int so_resolv(struct addrinfo **addresses, const char *hostname, const int port) {
	struct addrinfo hints;
	char buf[6];

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;

	snprintf(buf, sizeof(buf), "%d", (uint16_t)port);
	int rc = getaddrinfo(hostname, buf, &hints, addresses);
	if (rc != 0) {
		if (debug)
			printf("so_resolv: %s failed: %s (%d)\n", hostname, gai_strerror(rc), rc);
		return 0;
	}

	if (debug) {
		char s[INET6_ADDRSTRLEN] = {0};
		printf("Resolve %s:\n", hostname);
		for (struct addrinfo *p = *addresses; p != NULL; p = p->ai_next) {
			INET_NTOP(p->ai_addr, s, INET6_ADDRSTRLEN);
			printf("     %s\n", s);
		}
	}

	return 1;
}

/*
 * getaddrinfo() wrapper, wildcard mode. If "gateway" is 0 the network address
 * will be set to the loopback interface address, otherwise it will contain
 * the "wildcard address" (gateway mode).
 * Important: Caller is responsible for freeing addresses via freeaddrinfo()!
 */
int so_resolv_wildcard(struct addrinfo **addresses, const int port, int gateway) {
	struct addrinfo hints;
	char buf[6];

	snprintf(buf, sizeof(buf), "%d", (uint16_t)port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	if (gateway) {
		hints.ai_flags = AI_PASSIVE;
	}

	return getaddrinfo(NULL, buf, &hints, addresses);
}

/*
 * Connect to a host.
 * Returns: socket descriptor
 */
int so_connect(struct addrinfo *addresses) {
	int fd = -1;
	int rc;
	char s[INET6_ADDRSTRLEN] = {0};

	for (struct addrinfo *p = addresses; p != NULL; p = p->ai_next) {
		int flags;
		if ((fd = socket(p->ai_family, SOCK_STREAM, 0)) < 0) {
			if (debug)
				printf("so_connect: create: %s\n", strerror(errno));
			return -1;
		}

		if (debug) {
			INET_NTOP(p->ai_addr, s, INET6_ADDRSTRLEN);
			unsigned short port = INET_PORT(p->ai_addr);

			printf("so_connect: %s : %i \n", s, ntohs(port));
		}

		if ((flags = fcntl(fd, F_GETFL, 0)) < 0) {
			if (debug)
				printf("so_connect: get flags: %s\n", strerror(errno));
			close(fd);
			continue;
		}

		rc = connect(fd, p->ai_addr, p->ai_addrlen);

		if (rc < 0) {
			if (debug)
				printf("so_connect: %s\n", strerror(errno));
			close(fd);
			fd = -1;
			continue;
		}

		if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) < 0) {
			if (debug)
				printf("so_connect: set blocking: %s\n", strerror(errno));
			close(fd);
			fd = -1;
			continue;
		}

		break;
	}

	return fd;
}

/*
 * Bind the specified port and listen on it.
 * Retruns: number of successful binds
 */
int so_listen(plist_t *list, struct addrinfo *addresses, void *aux) {
	socklen_t clen;
	char s[INET6_ADDRSTRLEN] = {0};
	int count = 0;

	for (struct addrinfo *p = addresses; p != NULL; p = p->ai_next) {
		int fd = socket(p->ai_family, SOCK_STREAM, 0);
		if (fd < 0) {
			if (debug)
				printf("so_listen: new socket: %s\n", strerror(errno));
			close(fd);
			continue;
		}

		clen = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &clen, sizeof(clen)) != 0) {
			syslog(LOG_WARNING, "setsockopt() (option: SO_REUSEADDR, value: 1) failed: %s\n", strerror(errno));
		}

		if (p->ai_family == AF_INET6) {
			clen = 1;
			if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &clen, sizeof(clen)) != 0) {
				syslog(LOG_WARNING, "setsockopt() (option: IPV6_V6ONLY, value: 1) failed: %s\n", strerror(errno));
			}
		}

		INET_NTOP(p->ai_addr, s, INET6_ADDRSTRLEN);
		unsigned short port = INET_PORT(p->ai_addr);

		if (bind(fd, p->ai_addr, p->ai_addrlen)) {
			syslog(LOG_ERR, "Cannot bind address %s port %d: %s!\n", s, ntohs(port), strerror(errno));
			close(fd);
			continue;
		}

		if (listen(fd, SOMAXCONN)) {
			close(fd);
			continue;
		}

		*list = plist_add(*list, fd, aux);
		syslog(LOG_INFO, "so_listen: listening on %s:%d\n", s, ntohs(port));
		++count;
	}

	return count;
}

/*
 * Return 1 if data is available on the socket,
 * 0 if connection was closed
 * -1 if error (errno is set)
 */
int so_recvtest(int fd) {
	char buf;
	int i;
#ifndef MSG_DONTWAIT
	unsigned int flags;

	flags = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	i = (int)recv(fd, &buf, 1, MSG_PEEK);
	fcntl(fd, F_SETFL, flags);
#else
	i = (int)recv(fd, &buf, 1, MSG_DONTWAIT | MSG_PEEK);
#endif

	return i;
}

/*
 * Return true if there are some data on the socket
 */
int so_dataready(int fd) {
	return so_recvtest(fd) > 0;
}

/*
 * Reliable way of finding out whether a connection was closed
 * on the remote end, without actually reading from it.
 */
int so_closed(int fd) {
	int i;

	if (fd == -1)
		return 1;

	i = so_recvtest(fd);
	return (i == 0 || (i == -1 && errno != EAGAIN && errno != ENOENT));   /* ENOENT, you ask? Perhaps AIX devels could explain! :-( */
}

/*
 * Receive a single line from the socket. This is no super-efficient
 * implementation, but more than we need to read in a few headers.
 * What's more, the data is actually recv'd from a socket buffer.
 *
 * I had to time this in comparison to recv with block read :) and
 * the performance was very similar. Given the fact that it keeps us
 * from creating a whole buffering scheme around the socket (HTTP
 * connection is both line and block oriented, switching back and forth),
 * it is actually OK.
 */
int so_recvln(int fd, char **buf, int *size) {
	int len = 0;
	int r = 1;
	char c = 0;
	char *tmp;

	while (len < *size-1 && c != '\n') {
		r = (int)read(fd, &c, 1);
		if (r <= 0)
			break;

		(*buf)[len++] = c;

		/*
		 * End of buffer, still no EOL? Resize the buffer
		 */
		if (len == *size-1 && c != '\n') {
			if (debug)
				printf("so_recvln(%d): realloc %d\n", fd, *size*2);
			*size *= 2;
			tmp = realloc(*buf, *size);
			if (tmp == NULL)
				return -1;
			else
				*buf = tmp;
		}
	}
	(*buf)[len] = 0;

	return r;
}
