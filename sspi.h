/*
 * These are SSPI authentication routines for the NTLM module of CNTLM
 * Used only on Win32/64 (Cygwin)
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
 * Copyright (c) 2013 Denis Galkin aka Evengard, David Kubicek
 *
 */

#ifndef SSPI_H
#define SSPI_H

#ifdef __CYGWIN__

#include "utils.h"

#define SECURITY_WIN32

#include <windows.h>
#include <sspi.h>

#define TOKEN_BUFSIZE 4096

struct sspi_handle
{
	CredHandle credentials;
	CtxtHandle context;
};

extern int sspi_enabled(void);
extern int sspi_set(char *mode);
extern int sspi_unset(void);

extern int sspi_request(char **dst, struct sspi_handle *sspi);
extern int sspi_response(char **dst, char *challenge, int challen, struct sspi_handle *sspi);

#endif /*  __CYGWIN__ */

#endif /* SSPI_H */
