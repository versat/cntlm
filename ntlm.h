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

#ifndef _NTLM_H
#define _NTLM_H

#include "xcrypt.h"
#include "auth.h"

#define NTLM_BUFSIZE		1024
#define NTLM_CHALLENGE_MIN	40
typedef union {
    struct {
        unsigned int negotiate_56:1;
        unsigned int negotiate_key_exchange:1;
        unsigned int negotiate_128:1;
        unsigned int negotiate_0x10000000:1;
        unsigned int negotiate_0x08000000:1;
        unsigned int negotiate_0x04000000:1;
        unsigned int negotiate_version:1;
        unsigned int negotiate_0x01000000:1;
        unsigned int negotiate_target_info:1;
        unsigned int request_non_nt_session:1;
        unsigned int negotiate_0x00200000:1;
        unsigned int negotiate_identify:1;
        unsigned int negotiate_extended_security:1;
        unsigned int target_type_share:1;
        unsigned int target_type_server:1;
        unsigned int target_type_domain:1;
        unsigned int negotiate_always_sign_in:1;
        unsigned int negotiate_0x00004000:1;
        unsigned int negotiate_oem_workstation_supplied:1;
        unsigned int negotiate_oem_domain_supplied:1;
        unsigned int negotiate_anonymous:1;
        unsigned int negotiate_nt_only:1;
        unsigned int negotiate_ntlm_key:1;
        unsigned int negotiate_0x00001000:1;
        unsigned int negotiate_lan_manager_key:1;
        unsigned int negotiate_datagram:1;
        unsigned int negotiate_seal:1;
        unsigned int negotiate_sign:1;
        unsigned int request_0x00000008:1;
        unsigned int request_target:1;
        unsigned int negotiate_oem:1;
        unsigned int negotiate_unicode:1;
    } flags;
    uint32_t bits;
} negotiation_flags;

typedef union {
    struct {
        uint8_t product_major_version;
        uint8_t product_minor_version;
        uint16_t product_build;
        const uint8_t reserved[3];
        uint8_t ntlm_revison_current;
    } fields;
    uint64_t bits;
} version;



enum message_types{
    NEGOTIATE_MESSAGE=       0x00000001,
    CHALLENGE_MESSAGE =      0x00000002,
    AUTHENTICATION_MESSAGE = 0x00000003
};

typedef union{
    enum message_types type;
    uint32_t bits;
}message_type;

typedef union {
    struct {
        uint16_t len;
        uint16_t max_len;
        uint32_t buffer_offset;
    } fields;
    uint64_t bits;
} payload_content_definition;

typedef payload_content_definition domain_name_fields;
typedef payload_content_definition workstation_fields;
typedef payload_content_definition username_fields;
typedef payload_content_definition encrypted_random_session_key_fields;
typedef payload_content_definition lm_challenge_response_fields;
typedef payload_content_definition nt_challenge_response_fields;

static const char signature[8] = "NTLMSSP";

extern char *ntlm_hash_lm_password(const char *password);
extern char *ntlm_hash_nt_password(const char *password);
extern char *ntlm2_hash_password(const char *username, const char *domain, const char *password);
extern int ntlm_request(char **dst, struct auth_s *creds);
extern int ntlm_response(char **dst, char *challenge, int challen, struct auth_s *creds);



#endif /* _NTLM_H */
