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

/*
 * kerberos.h
 *
 *  Created on: 25/ago/2010
 *      Author: luca
 */

#ifndef KERBEROS_H_
#define KERBEROS_H_

#include "globals.h"
#include "auth.h"

//used in global auth flag
#define KRB_NO_CREDS				0
#define KRB_CREDENTIAL_AVAILABLE	1
#define KRB_FORCE_USE_KRB			2

//used while auth
#define KRB_NOT_TRIED 	0
#define KRB_OK 			1
#define KRB_KO 			4

/**
 * acquires a kerberos token for default credential using SPN HTTP@<thost>
 */
int acquire_kerberos_token(proxy_t* proxy, struct auth_s *credentials, char* buf);

/**
 * checks if a default cached credential is cached
 */
int check_credential();

int acquire_credential(struct auth_s *credentials);

#endif /* KERBEROS_H_ */
