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

#include <string.h>
#include <stdio.h>
#ifdef __APPLE__
#include <GSS/GSS.h>
#else
#include <gssapi/gssapi.h>
#endif
#include <stdlib.h>

#include "kerberos.h"
#include "globals.h"

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
		printf("context flag: GSS_C_DELEG_FLAG\n");
	if (flags & GSS_C_MUTUAL_FLAG)
		printf("context flag: GSS_C_MUTUAL_FLAG\n");
	if (flags & GSS_C_REPLAY_FLAG)
		printf("context flag: GSS_C_REPLAY_FLAG\n");
	if (flags & GSS_C_SEQUENCE_FLAG)
		printf("context flag: GSS_C_SEQUENCE_FLAG\n");
	if (flags & GSS_C_CONF_FLAG)
		printf("context flag: GSS_C_CONF_FLAG\n");
	if (flags & GSS_C_INTEG_FLAG)
		printf("context flag: GSS_C_INTEG_FLAG\n");
}

static void display_status_1(char *m, OM_uint32 code, int type) {
	OM_uint32 maj_stat;
	OM_uint32 min_stat;
	gss_buffer_desc msg;
	OM_uint32 msg_ctx;

	msg_ctx = 0;
	while (1) {
		maj_stat = gss_display_status(&min_stat, code, type, GSS_C_NULL_OID,
				&msg_ctx, &msg);
		if (maj_stat == GSS_S_COMPLETE)
			printf("GSS-API error %s: %s\n", m, (char *) msg.value);
		else if (maj_stat == GSS_S_BAD_MECH)
			printf("GSS-API error that could not be translated due to a bad mechanism (GSS_S_BAD_MECH)\n");
		else if (maj_stat == GSS_S_BAD_STATUS)
			printf("GSS-API error that is unknown (or this function was called with a wrong status type) (GSS_S_BAD_STATUS)\n");
		else if (maj_stat == GSS_S_FAILURE)
			printf("GSS-API error and gss_display_status failed with minor status code %lo (GSS_S_FAILURE)\n", (long unsigned int)min_stat);
		else
			printf("GSS-API error unrecognized return value from gss_display_status\n");
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
	OM_uint32 maj_stat;
	OM_uint32 min_stat;
	gss_buffer_desc out_name;

	maj_stat = gss_display_name(&min_stat, *name, &out_name, NULL);
	if (maj_stat != GSS_S_COMPLETE && debug) {
		display_status("Display name", maj_stat, min_stat);
	}

	printf("%s %s\n", txt, (char *)out_name.value);

	(void) gss_release_buffer(&min_stat, &out_name);
}

int acquire_name(gss_name_t *target_name, char *service_name, gss_OID oid) {
	gss_buffer_desc tmp_tok;
	OM_uint32 maj_stat;
	OM_uint32 min_stat;

	tmp_tok.value = service_name;
	tmp_tok.length = strlen(service_name) + 1;

	maj_stat = gss_import_name(&min_stat, &tmp_tok, oid, target_name);

	if (debug) {
		if (maj_stat != GSS_S_COMPLETE) {
			display_status("Parsing name", maj_stat, min_stat);
		} else {
			display_name("Acquired kerberos name", target_name);
		}
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
	OM_uint32 maj_stat;
	OM_uint32 min_stat;
	OM_uint32 init_min_stat;

	if ((maj_stat = acquire_name(&target_name, service_name,
			GSS_C_NT_HOSTBASED_SERVICE)) != GSS_S_COMPLETE)
		return maj_stat;

	if (debug) {
		display_name("SPN name", &target_name);
	}

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
		if (debug) {
			display_status("Initializing context", maj_stat, init_min_stat);
		}
		if (gss_context == GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&min_stat, &gss_context, GSS_C_NO_BUFFER);
		return maj_stat;
	}

	if (debug) {
		printf("Got token (size=%d)\n", (int) send_tok->length);
	}
	maj_stat = gss_delete_sec_context(&min_stat, &gss_context, GSS_C_NO_BUFFER);
	if (maj_stat != GSS_S_COMPLETE && debug) {
		display_status("Deleting context", maj_stat, min_stat);
	}
	return GSS_S_COMPLETE;
}



/**
 * acquires a kerberos token for default credential using SPN HTTP@<thost>
 */
int acquire_kerberos_token(const char* hostname, struct auth_s *credentials,
		char** buf, size_t *bufsize) {
	char service_name[BUFSIZE];
	OM_uint32 ret_flags;
	OM_uint32 min_stat;

	if (credentials->haskrb == KRB_KO) {
		if (debug)
			printf("Skipping already failed gss auth for %s\n", hostname);
		return 0;
	}

	if (!(credentials->haskrb & KRB_CREDENTIAL_AVAILABLE)) {
		credentials->haskrb |= check_credential();
		if (!(credentials->haskrb & KRB_CREDENTIAL_AVAILABLE)){
			//no credential -> no token
			if (debug)
				printf("No valid credential available\n");
			return 0;
		}
	}

	gss_buffer_desc send_tok;

	strlcpy(service_name, "HTTP@", BUFSIZE);
	strlcat(service_name, hostname, BUFSIZE);

	int rc = client_establish_context(service_name, &ret_flags, &send_tok);

	if (rc == GSS_S_COMPLETE) {
		char *token = NULL;
		size_t token_size;
		credentials->haskrb = KRB_OK;

		// approximately compute size of token in base64
		token_size = 4*send_tok.length;
		token_size /= 3;
		token_size += 4 + 4;
		if (token_size + 10 + 1 > *bufsize) {
			// *bufsize must be >= token_size + length of "NEGOTIATE " (10) + null terminator (1)
			*bufsize = token_size + 10 + 1;
			*buf = realloc(*buf, *bufsize);
		}

		strlcpy(*buf, "NEGOTIATE ", *bufsize);
		token = *buf + 10;

		to_base64((unsigned char *)token, send_tok.value, send_tok.length, token_size);

		if (debug) {
			printf("Token B64 (%d size=%d)... %s\n", (int)token_size, (int)strlen(token), token);
			display_ctx_flags(ret_flags);
		}

		rc=1;
	} else {
		credentials->haskrb = KRB_KO;

		if (debug)
			printf("No valid token acquired for %s\n", service_name);

		rc=0;
	}

	(void) gss_release_buffer(&min_stat, &send_tok);

	return rc;
}

/**
 * checks if a default cached credential is cached
 */
int check_credential(void) {
	OM_uint32 min_stat;
	gss_name_t name;
	OM_uint32 lifetime;
	gss_cred_usage_t cred_usage;
	gss_OID_set mechanisms;
	OM_uint32 maj_stat;

	maj_stat = gss_inquire_cred(&min_stat, GSS_C_NO_CREDENTIAL, &name,
			&lifetime, &cred_usage, &mechanisms);
	if (maj_stat != GSS_S_COMPLETE) {
		if (debug) {
			display_status("Inquire credential", maj_stat, min_stat);
		}
		return 0;
	}
	(void) gss_release_oid_set(&min_stat, &mechanisms);

	if (name != NULL) {
		if (debug) {
			display_name("Available cached credential", &name);
		}
		(void) gss_release_name(&min_stat, &name);
		return KRB_CREDENTIAL_AVAILABLE;
	}
	return 0;
}
