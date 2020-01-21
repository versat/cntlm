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
int so_resolv(struct in_addr *host, const char *name) {
/*
	struct hostent *resolv;

	resolv = gethostbyname(name);
	if (!resolv)
		return 0;

	memcpy(host, resolv->h_addr_list[0], resolv->h_length);
	return 1;
*/
	struct addrinfo hints;
	struct addrinfo *res;
	const struct addrinfo *p;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	int rc = getaddrinfo(name, NULL, &hints, &res);
	if (rc != 0) {
		if (debug)
			printf("so_resolv: %s failed: %s (%d)\n", name, gai_strerror(rc), rc);
		return 0;
	}

	if (debug)
		printf("Resolve %s:\n", name);
	int addr_set = 0;
	for (p = res; p != NULL; p = p->ai_next) {
		const struct sockaddr_in *ad = (struct sockaddr_in*)(p->ai_addr);
		if (ad == NULL) {
			freeaddrinfo(res);
			return 0;
		}
		if (!addr_set) {
			memcpy(host, &ad->sin_addr, sizeof(ad->sin_addr));
			addr_set = 1;
			if (debug)
				printf("  -> %s\n", inet_ntoa(ad->sin_addr));
		} else
			if (debug)
				printf("     %s\n", inet_ntoa(ad->sin_addr));
	}

	freeaddrinfo(res);

	return 1;
}

/*
 * Connect to a host. Host is required to be resolved
 * in the struct in_addr already.
 * Returns: socket descriptor
 */
int so_connect(struct in_addr host, int port) {
	int flags;
	int fd;
	int rc;
	struct sockaddr_in saddr;
	// struct timeval tv;
	// fd_set fds;

	if ((fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		if (debug)
			printf("so_connect: create: %s\n", strerror(errno));
		return -1;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);
	saddr.sin_addr = host;

	if ((flags = fcntl(fd, F_GETFL, 0)) < 0) {
		if (debug)
			printf("so_connect: get flags: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	/* NON-BLOCKING connect with timeout
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		if (debug)
			printf("so_connect: set non-blocking: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	*/

	rc = connect(fd, (struct sockaddr *)&saddr, sizeof(saddr));

	/*
	printf("connect = %d\n", rc);
	if (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS)) {
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		tv.tv_sec = 10;
		tv.tv_usec = 0;
		printf("select!\n");
		rc = select(fd+1, NULL, &fds, NULL, &tv) - 1;
		printf("select = %d\n", rc);
	}
	*/

	if (rc < 0) {
		if (debug)
			printf("so_connect: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) < 0) {
		if (debug)
			printf("so_connect: set blocking: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * Bind the specified port and listen on it.
 * Return socket descriptor if OK, otherwise 0.
 */
int so_listen(int port, struct in_addr source) {
	struct sockaddr_in saddr;
	int fd;
	socklen_t clen;
	int retval;

	fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		if (debug)
			printf("so_listen: new socket: %s\n", strerror(errno));
		return -1;
	}

	clen = 1;
	retval = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &clen, sizeof(clen));
	if (retval != 0) {
		syslog(LOG_WARNING, "setsockopt() (option: SO_REUSEADDR, value: 1) failed: %s\n", strerror(errno));
	}
	memset((void *)&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);
	saddr.sin_addr.s_addr = source.s_addr;

	if (bind(fd, (struct sockaddr *)&saddr, sizeof(saddr))) {
		syslog(LOG_ERR, "Cannot bind port %d: %s!\n", port, strerror(errno));
		close(fd);
		return -1;
	}

	if (listen(fd, SOMAXCONN)) {
		close(fd);
		return -1;
	}

	return fd;
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

