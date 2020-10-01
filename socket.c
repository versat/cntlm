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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <syslog.h>

#include "utils.h"

extern int debug;

/*
 * gethostbyname() wrapper. Return 1 if OK, otherwise 0.
 */
int so_resolv(struct addrinfo **addresses, const char *hostname, const int port) {
	struct addrinfo hints, *p;
	char s[INET6_ADDRSTRLEN], buf[6];

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;

	sprintf(buf, "%d", port);
	int rc = getaddrinfo(hostname, buf, &hints, addresses);
	if (rc != 0) {
		if (debug)
			printf("so_resolv: %s failed: %s (%d)\n", hostname, gai_strerror(rc), rc);
		return 0;
	}

	if (debug) {
		printf("Resolve %s:\n", hostname);
		for (p = *addresses; p != NULL; p = p->ai_next) {
			switch (p->ai_family) {
				case AF_INET6:
					inet_ntop(p->ai_family, &((struct sockaddr_in6*)(p->ai_addr))->sin6_addr, s, INET6_ADDRSTRLEN);
					break;
				case AF_INET:
					inet_ntop(p->ai_family, &((struct sockaddr_in*)(p->ai_addr))->sin_addr, s, INET6_ADDRSTRLEN);
					break;
			}
			printf("     %s\n", s);
		}
	}

	return 1;
}

int so_resolv_wildcard(struct addrinfo **addresses, const int port, int gateway) {
	struct addrinfo hints, *p;
	char buf[6];

	sprintf(buf, "%d", port);

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
	int flags;
	int fd = -1;
	int rc;
	struct addrinfo *p;
	char s[INET6_ADDRSTRLEN];

	for (p = addresses; p != NULL; p = p->ai_next) {
		if ((fd = socket(p->ai_family, SOCK_STREAM, 0)) < 0) {
			if (debug)
				printf("so_connect: create: %s\n", strerror(errno));
			return -1;
		}

		if (debug) {
			u_short port;
			switch (p->ai_family) {
				case AF_INET6:
					port = ((struct sockaddr_in6*)(p->ai_addr))->sin6_port;
					inet_ntop(p->ai_family, &((struct sockaddr_in6*)(p->ai_addr))->sin6_addr, s, INET6_ADDRSTRLEN);
					break;
				case AF_INET:
					port = ((struct sockaddr_in*)(p->ai_addr))->sin_port;
					inet_ntop(p->ai_family, &((struct sockaddr_in*)(p->ai_addr))->sin_addr, s, INET6_ADDRSTRLEN);
					break;
			}
			printf("so_connect: %s : %i \n", s, ntohs(port));
		}

		if ((flags = fcntl(fd, F_GETFL, 0)) < 0) {
			if (debug)
				printf("so_connect: get flags: %s\n", strerror(errno));
			close(fd);
			continue;
		}

		/* NON-BLOCKING connect with timeout
		if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
			if (debug)
				printf("so_connect: set non-blocking: %s\n", strerror(errno));
			close(fd);
			continue;
		}
		*/

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
 */
int so_listen(plist_t *list, struct addrinfo *addresses, void *aux) {
	int fd;
	socklen_t clen;
	struct addrinfo *p;
	char s[INET6_ADDRSTRLEN];
	int retval;

	for (p = addresses; p != NULL; p = p->ai_next) {
		fd = socket(p->ai_family, SOCK_STREAM, 0);
		if (fd < 0) {
			if (debug)
				printf("so_listen: new socket: %s\n", strerror(errno));
			close(fd);
			return -1;
		}

		clen = 1;
		retval = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &clen, sizeof(clen));
		if (retval != 0) {
			syslog(LOG_WARNING, "setsockopt() (option: SO_REUSEADDR, value: 1) failed: %s\n", strerror(errno));
		}

		u_short port;
		switch (p->ai_family) {
			case AF_INET6:
				port = ((struct sockaddr_in6*)(p->ai_addr))->sin6_port;
				inet_ntop(p->ai_family, &((struct sockaddr_in6*)(p->ai_addr))->sin6_addr, s, INET6_ADDRSTRLEN);
				break;
			case AF_INET:
				port = ((struct sockaddr_in*)(p->ai_addr))->sin_port;
				inet_ntop(p->ai_family, &((struct sockaddr_in*)(p->ai_addr))->sin_addr, s, INET6_ADDRSTRLEN);
				break;
		}

		if (bind(fd, p->ai_addr, p->ai_addrlen)) {
			syslog(LOG_ERR, "Cannot bind address %s port %d: %s!\n", s, ntohs(port), strerror(errno));
			close(fd);
			return -1;
		} else if (debug) {
			printf("so_listen: %s : %u \n", s, ntohs(port));
		}

		if (listen(fd, SOMAXCONN)) {
			close(fd);
			return -1;
		}

		*list = plist_add(*list, fd, aux);
	}

	return 0;
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
	i = recv(fd, &buf, 1, MSG_PEEK);
	fcntl(fd, F_SETFL, flags);
#else
	i = recv(fd, &buf, 1, MSG_DONTWAIT | MSG_PEEK);
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
		r = read(fd, &c, 1);
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

