/*
 * These are ACL routines for the main module of CNTLM
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

#ifndef ACL_H
#define ACL_H

#include <netinet/in.h>

#include "utils.h"

/*
 * ACL rule datatypes.
 */
enum acl_t {
	ACL_ALLOW = 0,
	ACL_DENY
};

typedef struct {
	unsigned int ip;
	int mask;
} network_t;

extern int acl_add(plist_t *rules, char *spec, enum acl_t acl);
extern enum acl_t acl_check(plist_const_t rules, struct sockaddr *caddr);

#endif /* ACL_H */
