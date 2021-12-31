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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#include "ntlm.h"
#include "swap.h"
#include "xcrypt.h"
#include "utils.h"
#include "auth.h"
#ifdef __CYGWIN__
#include "sspi.h"
#endif

//TODO: move to header file






extern int debug;

static void ntlm_set_key(const unsigned char *src, gl_des_ctx *context) {
	char key[8];

	key[0] = src[0];
	key[1] = ((src[0] << 7) & 0xff) | (src[1] >> 1);
	key[2] = ((src[1] << 6) & 0xff) | (src[2] >> 2);
	key[3] = ((src[2] << 5) & 0xff) | (src[3] >> 3);
	key[4] = ((src[3] << 4) & 0xff) | (src[4] >> 4);
	key[5] = ((src[4] << 3) & 0xff) | (src[5] >> 5);
	key[6] = ((src[5] << 2) & 0xff) | (src[6] >> 6);
	key[7] = (src[6] << 1) & 0xff;

	gl_des_setkey(context, key);
}

static int ntlm_calc_resp(char **dst, char *keys, const char *challenge) {
	gl_des_ctx context;

	*dst = zmalloc(24 + 1);

	ntlm_set_key(MEM(keys, unsigned char, 0), &context);
	gl_des_ecb_encrypt(&context, challenge, *dst);

	ntlm_set_key(MEM(keys, unsigned char, 7), &context);
	gl_des_ecb_encrypt(&context, challenge, *dst+8);

	ntlm_set_key(MEM(keys, unsigned char, 14), &context);
	gl_des_ecb_encrypt(&context, challenge, *dst+16);

	return 24;
}

static void ntlm2_calc_resp(char **nthash, int *ntlen, char **lmhash, int *lmlen,
		const char *passnt2, char *challenge, char* userDom, int userDomLen) {
	char *tmp;
	char *blob;
	char *nonce;
	char *buf;
	int64_t tw;
	int blen;

	nonce = zmalloc(8 + 1);
	VAL(nonce, uint64_t, 0) = getrandom64();
	tw = ((uint64_t)time(NULL) + 11644473600LLU) * 10000000LLU;

	if (debug) {
		tmp = printmem(nonce, 8, 7);
#ifdef PRId64
		printf("NTLMv2:\n\t    Nonce: %s\n\tTimestamp: %"PRId64"\n", tmp, tw);
#else
		printf("NTLMv2:\n\t    Nonce: %s\n\tTimestamp: %ld\n", tmp, tw);
#endif
		free(tmp);
	}

	blob = zmalloc(4+4+8+8+4+userDomLen+4 + 1);
	VAL(blob, uint32_t, 0) = U32LE(0x00000101);
	VAL(blob, uint32_t, 4) = U32LE(0);
	VAL(blob, uint64_t, 8) = U64LE(tw);
	VAL(blob, uint64_t, 16) = U64LE(VAL(nonce, uint64_t, 0));
	VAL(blob, uint32_t, 24) = U32LE(0);
	memcpy(blob+28, userDom, userDomLen);
	memset(blob+28+userDomLen, 0, 4);
	blen = 28+userDomLen+4;

	if (0 && debug) {
		tmp = printmem(blob, blen, 7);
		printf("\t     Blob: %s (%d)\n", tmp, blen);
		free(tmp);
	}

	*ntlen = 16+blen;
	*nthash = zmalloc(*ntlen + 1);
	buf = zmalloc(8+blen + 1);
	memcpy(buf, MEM(challenge, char, 24), 8);
	memcpy(buf+8, blob, blen);
	hmac_md5(passnt2, 16, buf, 8+blen, *nthash);
	memcpy(*nthash+16, blob, blen);
	free(buf);

	*lmlen = 24;
	*lmhash = zmalloc(*lmlen + 1);
	buf = zmalloc(16 + 1);
	memcpy(buf, MEM(challenge, char, 24), 8);
	memcpy(buf+8, nonce, 8);
	hmac_md5(passnt2, 16, buf, 16, *lmhash);
	memcpy(*lmhash+16, nonce, 8);
	free(buf);

	free(blob);
	free(nonce);
	return;
}

static void ntlm2sr_calc_rest(char **nthash, int *ntlen, char **lmhash, int *lmlen, char *passnt, char *challenge) {
	char *sess;
	char *nonce;
	char *buf;

	nonce = zmalloc(8 + 1);
	VAL(nonce, uint64_t, 0) = getrandom64();

	*lmlen = 24;
	*lmhash = zmalloc(*lmlen + 1);
	memcpy(*lmhash, nonce, 8);
	memset(*lmhash+8, 0, 16);

	buf = zmalloc(16 + 1);
	sess = zmalloc(16 + 1);
	memcpy(buf, MEM(challenge, char, 24), 8);
	memcpy(buf+8, nonce, 8);
	md5_buffer(buf, 16, sess);
	free(buf);

	*ntlen = 24;
	ntlm_calc_resp(nthash, passnt, sess);

	free(sess);
	free(nonce);
	return;
}

char *ntlm_hash_lm_password(const char *password) {
	char magic[8] = {0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25};
	gl_des_ctx context;
	char *keys;
	char *pass;

	keys = zmalloc(21 + 1);
	pass = zmalloc(14 + 1);
	uppercase(strncpy(pass, password, MIN(14, strlen(password))));

	ntlm_set_key(MEM(pass, unsigned char, 0), &context);
	gl_des_ecb_encrypt(&context, magic, keys);

	ntlm_set_key(MEM(pass, unsigned char, 7), &context);
	gl_des_ecb_encrypt(&context, magic, keys+8);

	memset(keys+16, 0, 5);
	memset(pass, 0, 14);
	free(pass);

	return keys;
}

char *ntlm_hash_nt_password(const char *password) {
	char *u16;
	char *keys;
	int len;

	keys = zmalloc(21 + 1);
	len = unicode(&u16, password);
	md4_buffer(u16, len, keys);

	memset(keys+16, 0, 5);
	memset(u16, 0, len);
	free(u16);

	return keys;
}

char *ntlm2_hash_password(const char *username, const char *domain, const char *password) {
	char *tmp;
	char *buf;
	char *passnt;
	char *passnt2;
	int len;

	passnt = ntlm_hash_nt_password(password);

	const size_t buf_len = strlen(username) + strlen(domain) + 1;
	buf = zmalloc(buf_len);
	strlcat(buf, username, buf_len);
	strlcat(buf, domain, buf_len);
	uppercase(buf);
	len = unicode(&tmp, buf);

	passnt2 = zmalloc(16 + 1);
	hmac_md5(passnt, 16, tmp, len, passnt2);

	free(passnt);
	free(tmp);
	free(buf);

	return passnt2;
}


int ntlm_request(char **dst, struct auth_s *creds) {
#ifdef __CYGWIN__
	if (sspi_enabled())
	{
		return sspi_request(dst, &creds->sspi);
	}
#endif
	char *buf;
	char *tmp;
	int dlen;
	int hlen;
    negotiation_flags flags;

	*dst = NULL;
	dlen = strlen(creds->domain);
	hlen = strlen(creds->workstation);

	if (!creds->flags) {
		if (creds->hashntlm2)
			flags.bits = 0xa208b205;
		else if (creds->hashnt == 2)
			flags.bits = 0xa208b207;
		else if (creds->hashnt && creds->hashlm)
			flags.bits = 0xb207;
		else if (creds->hashnt)
			flags.bits = 0xb205;
		else if (creds->hashlm)
			flags.bits = 0xb206;
		else {
			if (debug) {
				printf("You're requesting with empty auth_s?!\n");
				dump_auth(creds);
			}
			return 0;
		}
	} else
		flags.bits = creds->flags;

	if (debug) {
		printf("NTLM Request:\n");
		printf("\t   Domain: %s\n", creds->domain);
		printf("\t Hostname: %s\n", creds->workstation);
		printf("\t    Flags: 0x%X\n", (int)flags.bits);
	}


    int payload_pos = 64 + 16;
    buf = zmalloc(NTLM_BUFSIZE);
    char* msg_pointer = buf;

    int payload_workstation_name_pos=payload_pos;
    int payload_domain_pos=payload_workstation_name_pos+dlen;
    // Signature (8 bytes): An 8-byte character array that MUST contain the ASCII string ('N', 'T', 'L', 'M',
    //'S', 'S', 'P', '\0').
	memcpy(buf, signature, 8);
    msg_pointer += sizeof(signature);
    //MessageType (4 bytes): A 32-bit unsigned integer that indicates the message type. This field MUST
    //be set to 0x00000001.
	VAL(buf, uint32_t, (int)(msg_pointer-buf)) = NEGOTIATE_MESSAGE;
    msg_pointer += sizeof(NEGOTIATE_MESSAGE);
    //NegotiateFlags (4 bytes): A NEGOTIATE structure that contains a set of flags, as defined in
    //section 2.2.2.5. The client sets flags to indicate options it supports.
	VAL(buf, uint32_t, (int)(msg_pointer-buf)) = U32LE(flags.bits);
    msg_pointer += sizeof(negotiation_flags);

    //DomainNameLen (2 bytes): A 16-bit unsigned integer that defines the size, in bytes, of
    //DomainName in the Payload.
    domain_name_fields domainNameFields = {
            .fields = {
                    .len = dlen,
                    .max_len = domainNameFields.fields.len,
                    .buffer_offset = 40 + hlen
            }
    };
    VAL(buf, uint64_t, (int)(msg_pointer-buf)) = U16LE(domainNameFields.bits);
    msg_pointer += sizeof(domainNameFields);

    //WorkstationLen (2 bytes): A 16-bit unsigned integer that defines the size, in bytes, of
    //WorkStationName in the Payload.
    workstation_fields workstationFields = {
            .fields = {
                    .len = hlen,
                    .max_len = workstationFields.fields.len,
                    .buffer_offset = 40
            }
    };
    VAL(buf, uint64_t, (int)(msg_pointer-buf)) = U16LE(workstationFields.bits);
    msg_pointer += sizeof(workstationFields);

    version version1 = {
            .fields = {
                    .product_build = 1,
                    .product_major_version = 1,
                    .product_minor_version = 1,
                    .ntlm_revison_current = 0x0F
            }
    };
    VAL(buf, uint64_t, (int)(msg_pointer-buf)) = version1.bits;
    msg_pointer += sizeof(version1);

    //VAL(buf, uint64_t , 36) = U64LE(version1.bits);


	tmp = uppercase(strdup(creds->workstation));
	memcpy(buf+payload_workstation_name_pos, tmp, hlen);
	free(tmp);

	tmp = uppercase(strdup(creds->domain));
	memcpy(buf+payload_domain_pos, tmp, dlen);
	free(tmp);

	*dst = buf;
	return 40+dlen+hlen;
}

static char *printuc(const char *src, int len) {
	char *tmp;
	int i;

	tmp = zmalloc((len+1)/2 + 1);
	for (i = 0; i < len/2; ++i) {
		tmp[i] = src[i*2];
	}

	return tmp;
}

/*
void dump(char *src, int len) {
	int i, j;
	char *tmp;

	tmp = new(len*3+4);
	for (i = 0; i < len; ++i) {
		snprintf(tmp+i*3, 4, "%0hhX   ", src[i]);
		printf("%c ", src[i]);
	}
	printf("\n%s\n", tmp);
	free(tmp);
}
*/


int ntlm_response(char **dst, char *challenge, int challen, struct auth_s *creds) {
#ifdef __CYGWIN__
	if (sspi_enabled())
	{
		return sspi_response(dst, challenge, challen, &creds->sspi);
	}
#endif
	char *buf;
	char *udomain;
    char *target;
	char *uuser;
	char *uhost;
	char *tmp;
	int dlen;
	int ulen;
	int hlen;
	uint16_t tpos;
	uint16_t tlen;
	uint16_t ttype = -1;
	uint16_t tbofs = 0;
	uint16_t tblen = 0;
	char *lmhash = NULL;
	char *nthash = NULL;
	int lmlen = 0;
	int ntlen = 0;
    negotiation_flags flags;

	if (debug) {
		printf("NTLM Challenge:\n");
		tmp = printmem(MEM(challenge, char, 24), 8, 7);
		printf("\tChallenge: %s (len: %d)\n", tmp, challen);
		free(tmp);
		printf("\t    Flags: 0x%X\n", U32LE(VAL(challenge, uint32_t, 20)));
	}

    udomain = creds->domain;

	if (challen >= NTLM_CHALLENGE_MIN) {
        memcpy(&flags.bits,challenge+20,4);
        if(creds->hashntlm2){

        }else{
            tbofs = tpos = U16LE(VAL(challenge, uint16_t, 44));
            while (tpos+4 <= challen && (ttype = U16LE(VAL(challenge, uint16_t, tpos)))) {
                tlen = U16LE(VAL(challenge, uint16_t, tpos+2));
                if (tpos+4+tlen > challen)
                    break;

                if (debug) {
                    switch (ttype) {
                        case 0x1:
                            printf("\t   Server: ");
                            break;
                        case 0x2:
                            printf("\tNT domain: ");
                            break;
                        case 0x3:
                            printf("\t     FQDN: ");
                            break;
                        case 0x4:
                            printf("\t   Domain: ");
                            break;
                        case 0x5:
                            printf("\t      TLD: ");
                            break;
                        default:
                            printf("\t      %3d: ", ttype);
                            break;
                    }
                    tmp = printuc(MEM(challenge, char, tpos+4), tlen);
                    printf("%s\n", tmp);
                    free(tmp);
                }

                tpos += 4+tlen;
                tblen += 4+tlen;
            }
        }

		if (tblen && ttype == 0)
			tblen += 4;

		if (debug) {
			printf("\t    TBofs: %d\n\t    TBlen: %d\n\t    ttype: %d\n", tbofs, tblen, ttype);
		}
	}

    int udomlen = strlen(creds->domain);
	if (creds->hashntlm2 && !udomlen) {
            return 0;
	}

	if (creds->hashntlm2) {
		ntlm2_calc_resp(&nthash, &ntlen, &lmhash, &lmlen, creds->passntlm2, challenge, creds->domain, udomlen);
	}

	if (creds->hashnt == 2) {
		ntlm2sr_calc_rest(&nthash, &ntlen, &lmhash, &lmlen, creds->passnt, challenge);
	}

	if (creds->hashnt == 1) {
		ntlen = ntlm_calc_resp(&nthash, creds->passnt, MEM(challenge, char, 24));
	}

	if (creds->hashlm) {
		lmlen = ntlm_calc_resp(&lmhash, creds->passlm, MEM(challenge, char, 24));
	}

	if (creds->hashnt || creds->hashntlm2) {
		tmp = uppercase(strdup(creds->domain));
		dlen = unicode(&udomain, tmp);
		free(tmp);
		ulen = unicode(&uuser, creds->user);
		tmp = uppercase(strdup(creds->workstation));
		hlen = unicode(&uhost, tmp);
		free(tmp);
	} else {
		udomain = uppercase(strdup(creds->domain));
		uuser = uppercase(strdup(creds->user));
		uhost = uppercase(strdup(creds->workstation));

		dlen = strlen(creds->domain);
		ulen = strlen(creds->user);
		hlen = strlen(creds->workstation);
	}

	if (debug) {
		printf("NTLM Response:\n");
		printf("\t Hostname: '%s'\n", creds->workstation);
		printf("\t   Domain: '%s'\n", creds->domain);
		printf("\t Username: '%s'\n", creds->user);
		if (ntlen) {
			tmp = printmem(nthash, ntlen, 7);
			printf("\t Response: '%s' (%d)\n", tmp, ntlen);
			free(tmp);
		}
		if (lmlen) {
			tmp = printmem(lmhash, lmlen, 7);
			printf("\t Response: '%s' (%d)\n", tmp, lmlen);
			free(tmp);
		}
	}


    int payload_pos = 64 + 16 + 8;
    buf = zmalloc(NTLM_BUFSIZE);
    char* msg_pointer = buf;

    int payload_domain_pos=payload_pos;
    int payload_username_pos=payload_domain_pos+dlen;
    int payload_workstation_name_pos=payload_username_pos+ulen;
    int payload_lm_challenge_response_pos=payload_workstation_name_pos+hlen;
    int payload_nt_challenge_response_pos=payload_lm_challenge_response_pos+lmlen;
    int payload_encrypted_random_session_key_fields=payload_nt_challenge_response_pos+ntlen;

    int package_end= payload_encrypted_random_session_key_fields;


    /* signature */
	memcpy(msg_pointer, signature, 8);
    msg_pointer += sizeof(signature);

    /* message type */
    message_type type;
    type.type = AUTHENTICATION_MESSAGE;
	VAL(buf, uint32_t, 8) = U32LE(type.bits);
    msg_pointer += sizeof(type);

	/* LM */
    lm_challenge_response_fields lmChallengeResponseFields = {
        .fields = {
                .len =  lmlen,
                .max_len = lmChallengeResponseFields.fields.len,
                .buffer_offset = payload_lm_challenge_response_pos
        }
    };

    VAL(buf, uint64_t, (int)(msg_pointer-buf)) = U64LE(lmChallengeResponseFields.bits);
    msg_pointer += sizeof(lmChallengeResponseFields);

	/* NT */
    nt_challenge_response_fields ntChallengeResponseFields = {
            .fields = {
                    .len = ntlen,
                    .max_len = ntChallengeResponseFields.fields.len,
                    .buffer_offset = payload_nt_challenge_response_pos
            }
    };
    VAL(buf, uint64_t, (int)(msg_pointer-buf)) = U64LE(ntChallengeResponseFields.bits);
    msg_pointer += sizeof(ntChallengeResponseFields);

	/* Domain */
    domain_name_fields domainNameFields = {
        .fields= {
            .len = dlen,
            .max_len = domainNameFields.fields.len,
            .buffer_offset = payload_domain_pos
        }
    };
	VAL(buf, uint64_t, (int)(msg_pointer-buf)) = U64LE(domainNameFields.bits);
    msg_pointer += sizeof(domainNameFields);

	/* Username */
    username_fields usernameFields = {
            .fields = {
                    .len = ulen,
                    .max_len = usernameFields.fields.len,
                    .buffer_offset = payload_username_pos
            }
    };
    VAL(buf, uint64_t, (int)(msg_pointer-buf)) = U64LE(usernameFields.bits);
    msg_pointer += sizeof(usernameFields);

	/* Hostname */
    username_fields workstationFields = {
            .fields = {
                    .len = hlen,
                    .max_len = workstationFields.fields.len,
                    .buffer_offset = payload_workstation_name_pos
            }
    };
    VAL(buf, uint64_t, (int)(msg_pointer-buf)) = U64LE(workstationFields.bits);
    msg_pointer += sizeof(workstationFields);

	/* Session */
    encrypted_random_session_key_fields encryptedRandomSessionKeyFields = {
            .fields = {
                    .len = 0,
                    .max_len = encryptedRandomSessionKeyFields.fields.len,
                    .buffer_offset = payload_encrypted_random_session_key_fields
            }
    };
	VAL(buf, uint64_t, (int)(msg_pointer-buf)) = U64LE(encryptedRandomSessionKeyFields.bits);
    msg_pointer += sizeof(encryptedRandomSessionKeyFields);

	/* Flags */
	VAL(buf, uint32_t, (int)(msg_pointer-buf)) = U32LE(flags.bits);
    msg_pointer += sizeof(flags);

    /* Version */
    version version1 = {
            .fields = {
                    .product_build = 1,
                    .product_major_version = 1,
                    .product_minor_version = 1,
                    .ntlm_revison_current = 0x0F
            }
    };
    VAL(buf, uint64_t, (int)(msg_pointer-buf)) = version1.bits;
    msg_pointer += sizeof(version1);

    /* MIC */
    VAL(buf, uint64_t, (int)(msg_pointer-buf)) = 0;
    msg_pointer += sizeof(uint64_t);
    VAL(buf, uint64_t, (int)(msg_pointer-buf)) = 0;
    msg_pointer += sizeof(uint64_t);

	memcpy(MEM(buf, char, payload_domain_pos), udomain, dlen);
	memcpy(MEM(buf, char, payload_username_pos), uuser, ulen);
	memcpy(MEM(buf, char, payload_workstation_name_pos), uhost, hlen);
	if (lmhash)
		memcpy(MEM(buf, char, payload_lm_challenge_response_pos), lmhash, lmlen);
	if (nthash)
		memcpy(MEM(buf, char, payload_nt_challenge_response_pos), nthash, ntlen);

	if (nthash)
		free(nthash);
	if (lmhash)
		free(lmhash);

	free(uhost);
	free(uuser);
	free(udomain);

	*dst = buf;
	return package_end;
}
