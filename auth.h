/*
 * Credentials related structures and routines for the main module of CNTLM
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

#ifndef AUTH_H
#define AUTH_H

#include <stdint.h>

#include "utils.h"
#ifdef __CYGWIN__
#include "sspi.h"
#endif

/*
 * Although I always prefer structs with pointer refs, I need direct storage
 * here to be able to alloc/free it in one go. It is used in a plist_t which
 * frees its items, but not recursively.
 */
struct auth_s {
	char user[MINIBUF_SIZE]; ///< username as string
	char domain[MINIBUF_SIZE]; ///< domain as string
	char workstation[MINIBUF_SIZE]; ///< workstation name as string
	char passlm[MINIBUF_SIZE]; ///< password/hash as binary data (no string)
	char passnt[MINIBUF_SIZE]; ///< password/hash as binary data (no string)
	char passntlm2[MINIBUF_SIZE]; ///< password/hash as binary data (no string)
	int hashntlm2;
	int hashnt;
	int hashlm;
#ifdef __CYGWIN__
	struct sspi_handle sspi;
#endif
#if config_gss == 1
	int haskrb;
#endif
	uint32_t flags;
};

#define auth_strcpy(creds, var, value) \
	if ((creds) && (value)) { \
		strlcpy(((creds)->var), (value), MINIBUF_SIZE); \
	}

#define auth_memcpy(creds, var, value, len) \
	if ((creds) && (value)) { \
		memcpy(((creds)->var), (value), MIN(len, MINIBUF_SIZE)); \
	}

extern struct auth_s *copy_auth(struct auth_s *dst, const struct auth_s *src, int fullcopy);
extern struct auth_s *dup_auth(const struct auth_s *creds, int fullcopy);
extern void dump_auth(const struct auth_s *creds);

#endif /* AUTH_H */
