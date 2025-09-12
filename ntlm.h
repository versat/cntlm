/*
 * These are NTLM authentication routines for the main module of CNTLM
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

#ifndef NTLM_H
#define NTLM_H

#include "auth.h"

#define NTLM_BUFSIZE		1024
#define NTLM_CHALLENGE_MIN	40

extern char *ntlm_hash_lm_password(const char *password);
extern char *ntlm_hash_nt_password(const char *password);
extern char *ntlm2_hash_password(const char *username, const char *domain, const char *password);
extern int ntlm_request(char **dst, struct auth_s *creds);
extern int ntlm_response(char **dst, char *challenge, int challen, struct auth_s *creds);

#endif /* NTLM_H */
