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

//http://docs.oracle.com/cd/E18752_01/html/816-4863/sampleprogs-1.html
/*
 * Copyright 1994 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include "globals.h"
#include "auth.h"
#include "kerberos.h"

#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <gssapi/gssapi.h>
#include <stdlib.h>

/*
 * Function: display_ctx_flags
 *
 * Purpose: displays the flags returned by context initiation in
 *          a human-readable form
 *
 * Arguments:
 *
 *      int             ret_flags
 *
 * Effects:
 *
 * Strings corresponding to the context flags are printed on
 * stdout, preceded by "context flag: " and followed by a newline
 */

void display_ctx_flags(OM_uint32 flags) {
	if (flags & GSS_C_DELEG_FLAG)
		syslog(LOG_INFO, "context flag: GSS_C_DELEG_FLAG\n");
	if (flags & GSS_C_MUTUAL_FLAG)
		syslog(LOG_INFO, "context flag: GSS_C_MUTUAL_FLAG\n");
	if (flags & GSS_C_REPLAY_FLAG)
		syslog(LOG_INFO, "context flag: GSS_C_REPLAY_FLAG\n");
	if (flags & GSS_C_SEQUENCE_FLAG)
		syslog(LOG_INFO, "context flag: GSS_C_SEQUENCE_FLAG\n");
	if (flags & GSS_C_CONF_FLAG)
		syslog(LOG_INFO, "context flag: GSS_C_CONF_FLAG\n");
	if (flags & GSS_C_INTEG_FLAG)
		syslog(LOG_INFO, "context flag: GSS_C_INTEG_FLAG\n");
}

static void display_status_1(char *m, OM_uint32 code, int type) {
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc msg;
	OM_uint32 msg_ctx;

	msg_ctx = 0;
	while (1) {
		maj_stat = gss_display_status(&min_stat, code, type, GSS_C_NULL_OID,
				&msg_ctx, &msg);
		if (1)
			syslog(LOG_ERR, "GSS-API error %s: %s\n", m, (char *) msg.value);
		(void) gss_release_buffer(&min_stat, &msg);

		if (!msg_ctx)
			break;
	}
}

/*
 * Function: display_status
 *
 * Purpose: displays GSS-API messages
 *
 * Arguments:
 *
 *      msg             a string to be displayed with the message
 *      maj_stat        the GSS-API major status code
 *      min_stat        the GSS-API minor status code
 *
 * Effects:
 *
 * The GSS-API messages associated with maj_stat and min_stat are
 * displayed on stderr, each preceded by "GSS-API error <msg>: " and
 * followed by a newline.
 */
void display_status(char *msg, OM_uint32 maj_stat, OM_uint32 min_stat) {
	display_status_1(msg, maj_stat, GSS_C_GSS_CODE);
	if (maj_stat != GSS_S_COMPLETE)
		display_status_1(msg, min_stat, GSS_C_MECH_CODE);
}

void display_name(char* txt, gss_name_t *name) {
	gss_OID mechOid = GSS_C_NO_OID;
	OM_uint32 maj_stat;
	OM_uint32 min_stat;
	gss_buffer_desc out_name;

//	maj_stat = gss_display_name(&min_stat, *name, &out_name, &mechOid);
	maj_stat = gss_display_name(&min_stat, *name, &out_name, NULL);
	if (maj_stat != GSS_S_COMPLETE) {
		display_status("Display name", maj_stat, min_stat);
	}

	syslog(LOG_INFO, txt, (char *) out_name.value);

	(void) gss_release_buffer(&min_stat, &out_name);

	if (mechOid != GSS_C_NO_OID)
		(void) gss_release_oid(&min_stat, &mechOid);
}

int acquire_name(gss_name_t *target_name, char *service_name, gss_OID oid) {
	gss_buffer_desc tmp_tok;
	OM_uint32 maj_stat, min_stat;

	tmp_tok.value = service_name;
	tmp_tok.length = strlen(service_name) + 1;

	maj_stat = gss_import_name(&min_stat, &tmp_tok, oid, target_name);

	if (maj_stat != GSS_S_COMPLETE) {
		display_status("Parsing name", maj_stat, min_stat);
	} else if (debug){
		display_name("Acquired kerberos name %s\n", target_name);
	}
	return maj_stat;
}

/*
 * Function: client_establish_context
 *
 * Purpose: establishes a GSS-API context with a specified service and
 * returns the context handle
 *
 * Arguments:
 *
 *      service_name    (r) the ASCII service name of the service
 *      context         (w) the established GSS-API context
 *      ret_flags       (w) the returned flags from init_sec_context
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 *
 * service_name is imported as a GSS-API name and a GSS-API context is
 * established with the corresponding service; the service should be
 * listening on the TCP connection s.  The default GSS-API mechanism
 * is used, and mutual authentication and replay detection are
 * requested.
 *
 * If successful, the context handle is returned in context.  If
 * unsuccessful, the GSS-API error messages are displayed on stderr
 * and -1 is returned.
 */
int client_establish_context(char *service_name,
		OM_uint32 *ret_flags, gss_buffer_desc* send_tok) {
	gss_name_t target_name;
	gss_ctx_id_t gss_context = GSS_C_NO_CONTEXT;
	OM_uint32 maj_stat, min_stat, init_min_stat;

	if ((maj_stat = acquire_name(&target_name, service_name,
			GSS_C_NT_HOSTBASED_SERVICE)) != GSS_S_COMPLETE)
		return maj_stat;

	if (debug)
		display_name("SPN name %s\n", &target_name);

	maj_stat = gss_init_sec_context(&init_min_stat, GSS_C_NO_CREDENTIAL,
			&gss_context,
			target_name,
			GSS_C_NULL_OID,// use default mech
			0, 0, // no special flags requested, no time req
			GSS_C_NO_CHANNEL_BINDINGS, /* no channel bindings */
			GSS_C_NO_BUFFER, // no input buffer
			NULL, /* ignore mech type */
			send_tok, ret_flags, //the returned token, the token flags
			NULL /* ignore time_rec */
			);

	gss_release_name(&min_stat, &target_name);

	if (maj_stat != GSS_S_COMPLETE) {
		if(maj_stat == GSS_S_CONTINUE_NEEDED){
			//TODO
		}
		display_status("Initializing context", maj_stat, init_min_stat);

		if (gss_context == GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&min_stat, &gss_context, GSS_C_NO_BUFFER);
		return maj_stat;
	}

	if (debug)
		syslog(LOG_INFO, "Got token (size=%d)\n", (int) send_tok->length);

	maj_stat = gss_delete_sec_context(&min_stat, &gss_context, GSS_C_NO_BUFFER);
	if (maj_stat != GSS_S_COMPLETE) {
		display_status("Deleting context", maj_stat, min_stat);
	}
	return GSS_S_COMPLETE;//maj_stat;
}



/**
 * acquires a kerberos token for default credential using SPN HTTP@<thost>
 */
int acquire_kerberos_token(proxy_t* proxy, struct auth_s *credentials,
		char* buf) {
	char service_name[BUFSIZE], token[BUFSIZE];
	OM_uint32 ret_flags, min_stat;

	if (credentials->haskrb == KRB_KO) {
		if (debug)
			syslog(LOG_INFO, "Skipping already failed gss auth for %s\n",
					proxy->hostname);
		return 0;
	}

	if (!(credentials->haskrb & KRB_CREDENTIAL_AVAILABLE)) {
		//try to get credential
//		if(acquire_credential(credentials)){
			credentials->haskrb |= check_credential();
			if (!(credentials->haskrb & KRB_CREDENTIAL_AVAILABLE)){
				//no credential -> no token
				if (debug)
					syslog(LOG_INFO, "No valid credential available\n");
				return 0;
			}
//		}
	}

	gss_buffer_desc send_tok;

	strcpy(service_name, "HTTP@");
	strcat(service_name, proxy->hostname);

	int rc = client_establish_context(service_name, &ret_flags, &send_tok);

	if (rc == GSS_S_COMPLETE) {
		credentials->haskrb = KRB_OK;

		to_base64((unsigned char *) token, send_tok.value, send_tok.length,
				BUFSIZE);

		if (debug) {
			syslog(LOG_INFO, "Token B64 (size=%d)... %s\n",
					(int) strlen(token), token);
			display_ctx_flags(ret_flags);
		}

		strcpy(buf, "NEGOTIATE ");
		strcat(buf, token);

		rc=1;
	} else {
		credentials->haskrb = KRB_KO;

		if (debug)
			syslog(LOG_INFO, "No valid token acquired for %s\n", service_name);

		rc=0;
	}

	(void) gss_release_buffer(&min_stat, &send_tok);

	return rc;
}

/**
 * checks if a default cached credential is cached
 */
int check_credential() {
	OM_uint32 min_stat;
	gss_name_t name;
	OM_uint32 lifetime;
	gss_cred_usage_t cred_usage;
	gss_OID_set mechanisms;
	OM_uint32 maj_stat;

	maj_stat = gss_inquire_cred(&min_stat, GSS_C_NO_CREDENTIAL, &name,
			&lifetime, &cred_usage, &mechanisms);
	if (maj_stat != GSS_S_COMPLETE) {
		display_status("Inquire credential", maj_stat, min_stat);
		return 0;
	}
	(void) gss_release_oid_set(&min_stat, &mechanisms);

	if (name != NULL) {
		display_name("Available cached credential %s\n", &name);
		(void) gss_release_name(&min_stat, &name);
		return KRB_CREDENTIAL_AVAILABLE;
	}
	return 0;
}

int acquire_credential(struct auth_s *credentials) {
	OM_uint32 min_stat, maj_stat;
	gss_name_t target_name;
	OM_uint32 lifetime = GSS_C_INDEFINITE;
	gss_cred_id_t *id;

	char *password = credentials->passnt;

	//!(g_creds->haskrb & KRB_CREDENTIAL_AVAILABLE)
	if (credentials->user && password) {
		char name[BUFSIZ];
		strcpy(name, credentials->user);
		if (credentials->domain) {
			strcat(name, "@");
			strcat(name, credentials->domain);
		}

		if ((maj_stat = acquire_name(&target_name, name, GSS_C_NT_USER_NAME))
				!= GSS_S_COMPLETE)
			return KRB_NO_CREDS;

		//TODO
		maj_stat = gss_acquire_cred(&min_stat, target_name, lifetime,
				GSS_C_NO_OID_SET, GSS_C_INITIATE, id, NULL, NULL);
		if (maj_stat != GSS_S_COMPLETE) {
			display_status("Acquire credential", maj_stat, min_stat);
			return KRB_NO_CREDS;
		}

		(void) gss_release_cred(&min_stat, id);

		(void) gss_release_name(&min_stat, &target_name);

		return KRB_CREDENTIAL_AVAILABLE;
	}
	return KRB_NO_CREDS;
}
