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

#ifndef SOCKET_H
#define SOCKET_H

#include <netinet/in.h>
#include <stdint.h>
#include <netdb.h>

#include "config/config.h"
#include "utils.h"

#if config_socklen_t != 1
#define socklen_t uint32_t
#endif

extern int so_resolv(struct addrinfo **addresses, const char *hostname, const int port);
extern int so_resolv_wildcard(struct addrinfo **addresses, const int port, int gateway);
extern int so_connect(struct addrinfo *adresses);
extern int so_listen(plist_t *list, struct addrinfo *adresses, void *aux);
extern int so_dataready(int fd);
extern int so_closed(int fd);
extern int so_recvln(int fd, char **buf, int *size);

#endif /* SOCKET_H */
