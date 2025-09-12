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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "auth.h"

struct auth_s *copy_auth(struct auth_s *dst, const struct auth_s *src, int fullcopy) {
	dst->hashntlm2 = src->hashntlm2;
	dst->hashnt = src->hashnt;
	dst->hashlm = src->hashlm;
	dst->flags = src->flags;
#if config_gss == 1
	dst->haskrb = src->haskrb;
#endif

	strlcpy(dst->domain, src->domain, MINIBUF_SIZE);
	strlcpy(dst->workstation, src->workstation, MINIBUF_SIZE);

	if (fullcopy) {
		strlcpy(dst->user, src->user, MINIBUF_SIZE);
		memcpy(dst->passntlm2, src->passntlm2, MINIBUF_SIZE);
		memcpy(dst->passnt, src->passnt, MINIBUF_SIZE);
		memcpy(dst->passlm, src->passlm, MINIBUF_SIZE);
	} else {
		memset(dst->user, 0, MINIBUF_SIZE);
		memset(dst->passntlm2, 0, MINIBUF_SIZE);
		memset(dst->passnt, 0, MINIBUF_SIZE);
		memset(dst->passlm, 0, MINIBUF_SIZE);
	}

	return dst;
}

struct auth_s *dup_auth(const struct auth_s *creds, int fullcopy) {
	struct auth_s *tmp;

	tmp = zmalloc(sizeof(struct auth_s));
	return copy_auth(tmp, creds, fullcopy);
}

void dump_auth(const struct auth_s *creds) {
	char *tmp;

	printf("Credentials structure dump:\n");
	if (creds == NULL) {
		printf("Struct is not allocated!\n");
		return;
	}

	printf("User:       %s\n", creds->user);
	printf("Domain:     %s\n", creds->domain);
	printf("Wks:        %s\n", creds->workstation);
	printf("HashNTLMv2: %d\n", creds->hashntlm2);
	printf("HashNT:     %d\n", creds->hashnt);
	printf("HashLM:     %d\n", creds->hashlm);
	printf("Flags:      %X\n", creds->flags);

	if (!is_memory_all_zero(creds->passntlm2, ARRAY_SIZE(creds->passntlm2))) {
		tmp = printmem(creds->passntlm2, 16, 8);
		printf("PassNTLMv2: %s\n", tmp);
		free(tmp);
	}

	if (!is_memory_all_zero(creds->passnt, ARRAY_SIZE(creds->passnt))) {
		tmp = printmem(creds->passnt, 16, 8);
		printf("PassNT:     %s\n", tmp);
		free(tmp);
	}

	if (!is_memory_all_zero(creds->passlm, ARRAY_SIZE(creds->passlm))) {
		tmp = printmem(creds->passlm, 16, 8);
		printf("PassLM:     %s\n\n", tmp);
		free(tmp);
	}
}
