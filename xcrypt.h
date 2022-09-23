/* des.c --- DES and Triple-DES encryption/decryption Algorithm
 * Copyright (C) 1998, 1999, 2001, 2002, 2003, 2004, 2005, 2006, 2007
 *    Free Software Foundation, Inc.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this file; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * ----------------------------------------------------------------------
 * Functions to compute MD4 message digest of files or memory blocks.
 * according to the definition of MD4 in RFC 1320 from April 1992.  Copyright
 * (C) 1995,1996,1997,1999,2000,2001,2002,2003,2005,2006 Free Software
 * Foundation, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef XCRYPT_H
#define XCRYPT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#define MD5_DIGEST_SIZE	16
#define MD5_BLOCK_SIZE	64
#define IPAD		0x36
#define OPAD		0x5c

#define gl_des_ecb_encrypt(ctx, from, to)  gl_des_ecb_crypt(ctx, from, to, 0)
#define gl_des_ecb_decrypt(ctx, from, to)  gl_des_ecb_crypt(ctx, from, to, 1)

/*
 * Encryption/Decryption context of DES
 */
typedef struct {
	uint32_t encrypt_subkeys[32];
	uint32_t decrypt_subkeys[32];
} gl_des_ctx;

/* Structures to save state of computation between the single steps.  */
struct md4_ctx {
	uint32_t A;
	uint32_t B;
	uint32_t C;
	uint32_t D;

	uint32_t total[2];
	uint32_t buflen;
	uint32_t buffer[32];
};

struct md5_ctx {
	uint32_t A;
	uint32_t B;
	uint32_t C;
	uint32_t D;

	uint32_t total[2];
	uint32_t buflen;
	uint32_t buffer[32];
};

extern bool gl_des_is_weak_key(const char * key);
extern void gl_des_setkey(gl_des_ctx *ctx, const char * key);
extern bool gl_des_makekey(gl_des_ctx *ctx, const char * key, size_t keylen);
extern void gl_des_ecb_crypt(gl_des_ctx *ctx, const char * _from, char * _to, int mode);

extern void md4_process_block (const void *buffer, size_t len, struct md4_ctx *ctx);
extern void md4_init_ctx (struct md4_ctx *ctx);
extern void *md4_read_ctx (const struct md4_ctx *ctx, void *resbuf);
extern void *md4_finish_ctx (struct md4_ctx *ctx, void *resbuf);
extern void md4_process_bytes (const void *buffer, size_t len, struct md4_ctx *ctx);
extern int md4_stream(FILE * stream, void *resblock);
extern void *md4_buffer (const char *buffer, size_t len, void *resblock);

extern int hmac_md5 (const void *key, size_t keylen, const void *in, size_t inlen, void *resbuf);

extern void md5_init_ctx (struct md5_ctx *ctx);
extern void md5_process_block (const void *buffer, size_t len, struct md5_ctx *ctx);
extern void md5_process_bytes (const void *buffer, size_t len, struct md5_ctx *ctx);
extern void *md5_finish_ctx (struct md5_ctx *ctx, void *resbuf);
extern void *md5_read_ctx (const struct md5_ctx *ctx, void *resbuf);
extern int md5_stream (FILE *stream, void *resblock);
extern void *md5_buffer (const char *buffer, size_t len, void *resblock);

#endif /* XCRYPT_H */
