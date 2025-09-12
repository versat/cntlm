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

#include <string.h>
#include <assert.h>

#include "xcrypt.h"
#include "swap.h"

#define SWAP(n) U32LE(n)

#define BLOCKSIZE 4096
#if BLOCKSIZE % 64 != 0
# error "invalid BLOCKSIZE"
#endif

/*
 * To check alignment gcc has an appropriate operator.  Other compilers don't.
 */
# if __GNUC__ >= 2
#  define UNALIGNED_P(p) (((uintptr_t) p) % __alignof__ (uint32_t) != 0)
# else
#  define alignof(type) offsetof (struct { char c; type x; }, x)
#  define UNALIGNED_P(p) (((size_t) p) % alignof (uint32_t) != 0)
# endif

# define MD4_DIGEST_SIZE 16

/* MD4 round constants */
#define K1 0x5a827999
#define K2 0x6ed9eba1

/* Round functions.  */
#define F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define rol(x, n) (((x) << (n)) | ((uint32_t) (x) >> (32 - (n))))
#define R1(a,b,c,d,k,s) a=rol(a+F(b,c,d)+x[k],s);
#define R2(a,b,c,d,k,s) a=rol(a+G(b,c,d)+x[k]+K1,s);
#define R3(a,b,c,d,k,s) a=rol(a+H(b,c,d)+x[k]+K2,s);

/* This array contains the bytes used to pad the buffer to the next
   64-byte boundary.  (RFC 1320, 3.1: Step 1)  */
static const unsigned char fillbuf[64] = { 0x80, 0 /* , 0, 0, ...  */  };

/*
 * The s-box values are permuted according to the 'primitive function P'
 * and are rotated one bit to the left.
 */
static const uint32_t sbox1[64] = {
  0x01010400, 0x00000000, 0x00010000, 0x01010404, 0x01010004, 0x00010404,
  0x00000004, 0x00010000, 0x00000400, 0x01010400, 0x01010404, 0x00000400,
  0x01000404, 0x01010004, 0x01000000, 0x00000004, 0x00000404, 0x01000400,
  0x01000400, 0x00010400, 0x00010400, 0x01010000, 0x01010000, 0x01000404,
  0x00010004, 0x01000004, 0x01000004, 0x00010004, 0x00000000, 0x00000404,
  0x00010404, 0x01000000, 0x00010000, 0x01010404, 0x00000004, 0x01010000,
  0x01010400, 0x01000000, 0x01000000, 0x00000400, 0x01010004, 0x00010000,
  0x00010400, 0x01000004, 0x00000400, 0x00000004, 0x01000404, 0x00010404,
  0x01010404, 0x00010004, 0x01010000, 0x01000404, 0x01000004, 0x00000404,
  0x00010404, 0x01010400, 0x00000404, 0x01000400, 0x01000400, 0x00000000,
  0x00010004, 0x00010400, 0x00000000, 0x01010004
};

static const uint32_t sbox2[64] = {
  0x80108020, 0x80008000, 0x00008000, 0x00108020, 0x00100000, 0x00000020,
  0x80100020, 0x80008020, 0x80000020, 0x80108020, 0x80108000, 0x80000000,
  0x80008000, 0x00100000, 0x00000020, 0x80100020, 0x00108000, 0x00100020,
  0x80008020, 0x00000000, 0x80000000, 0x00008000, 0x00108020, 0x80100000,
  0x00100020, 0x80000020, 0x00000000, 0x00108000, 0x00008020, 0x80108000,
  0x80100000, 0x00008020, 0x00000000, 0x00108020, 0x80100020, 0x00100000,
  0x80008020, 0x80100000, 0x80108000, 0x00008000, 0x80100000, 0x80008000,
  0x00000020, 0x80108020, 0x00108020, 0x00000020, 0x00008000, 0x80000000,
  0x00008020, 0x80108000, 0x00100000, 0x80000020, 0x00100020, 0x80008020,
  0x80000020, 0x00100020, 0x00108000, 0x00000000, 0x80008000, 0x00008020,
  0x80000000, 0x80100020, 0x80108020, 0x00108000
};

static const uint32_t sbox3[64] = {
  0x00000208, 0x08020200, 0x00000000, 0x08020008, 0x08000200, 0x00000000,
  0x00020208, 0x08000200, 0x00020008, 0x08000008, 0x08000008, 0x00020000,
  0x08020208, 0x00020008, 0x08020000, 0x00000208, 0x08000000, 0x00000008,
  0x08020200, 0x00000200, 0x00020200, 0x08020000, 0x08020008, 0x00020208,
  0x08000208, 0x00020200, 0x00020000, 0x08000208, 0x00000008, 0x08020208,
  0x00000200, 0x08000000, 0x08020200, 0x08000000, 0x00020008, 0x00000208,
  0x00020000, 0x08020200, 0x08000200, 0x00000000, 0x00000200, 0x00020008,
  0x08020208, 0x08000200, 0x08000008, 0x00000200, 0x00000000, 0x08020008,
  0x08000208, 0x00020000, 0x08000000, 0x08020208, 0x00000008, 0x00020208,
  0x00020200, 0x08000008, 0x08020000, 0x08000208, 0x00000208, 0x08020000,
  0x00020208, 0x00000008, 0x08020008, 0x00020200
};

static const uint32_t sbox4[64] = {
  0x00802001, 0x00002081, 0x00002081, 0x00000080, 0x00802080, 0x00800081,
  0x00800001, 0x00002001, 0x00000000, 0x00802000, 0x00802000, 0x00802081,
  0x00000081, 0x00000000, 0x00800080, 0x00800001, 0x00000001, 0x00002000,
  0x00800000, 0x00802001, 0x00000080, 0x00800000, 0x00002001, 0x00002080,
  0x00800081, 0x00000001, 0x00002080, 0x00800080, 0x00002000, 0x00802080,
  0x00802081, 0x00000081, 0x00800080, 0x00800001, 0x00802000, 0x00802081,
  0x00000081, 0x00000000, 0x00000000, 0x00802000, 0x00002080, 0x00800080,
  0x00800081, 0x00000001, 0x00802001, 0x00002081, 0x00002081, 0x00000080,
  0x00802081, 0x00000081, 0x00000001, 0x00002000, 0x00800001, 0x00002001,
  0x00802080, 0x00800081, 0x00002001, 0x00002080, 0x00800000, 0x00802001,
  0x00000080, 0x00800000, 0x00002000, 0x00802080
};

static const uint32_t sbox5[64] = {
  0x00000100, 0x02080100, 0x02080000, 0x42000100, 0x00080000, 0x00000100,
  0x40000000, 0x02080000, 0x40080100, 0x00080000, 0x02000100, 0x40080100,
  0x42000100, 0x42080000, 0x00080100, 0x40000000, 0x02000000, 0x40080000,
  0x40080000, 0x00000000, 0x40000100, 0x42080100, 0x42080100, 0x02000100,
  0x42080000, 0x40000100, 0x00000000, 0x42000000, 0x02080100, 0x02000000,
  0x42000000, 0x00080100, 0x00080000, 0x42000100, 0x00000100, 0x02000000,
  0x40000000, 0x02080000, 0x42000100, 0x40080100, 0x02000100, 0x40000000,
  0x42080000, 0x02080100, 0x40080100, 0x00000100, 0x02000000, 0x42080000,
  0x42080100, 0x00080100, 0x42000000, 0x42080100, 0x02080000, 0x00000000,
  0x40080000, 0x42000000, 0x00080100, 0x02000100, 0x40000100, 0x00080000,
  0x00000000, 0x40080000, 0x02080100, 0x40000100
};

static const uint32_t sbox6[64] = {
  0x20000010, 0x20400000, 0x00004000, 0x20404010, 0x20400000, 0x00000010,
  0x20404010, 0x00400000, 0x20004000, 0x00404010, 0x00400000, 0x20000010,
  0x00400010, 0x20004000, 0x20000000, 0x00004010, 0x00000000, 0x00400010,
  0x20004010, 0x00004000, 0x00404000, 0x20004010, 0x00000010, 0x20400010,
  0x20400010, 0x00000000, 0x00404010, 0x20404000, 0x00004010, 0x00404000,
  0x20404000, 0x20000000, 0x20004000, 0x00000010, 0x20400010, 0x00404000,
  0x20404010, 0x00400000, 0x00004010, 0x20000010, 0x00400000, 0x20004000,
  0x20000000, 0x00004010, 0x20000010, 0x20404010, 0x00404000, 0x20400000,
  0x00404010, 0x20404000, 0x00000000, 0x20400010, 0x00000010, 0x00004000,
  0x20400000, 0x00404010, 0x00004000, 0x00400010, 0x20004010, 0x00000000,
  0x20404000, 0x20000000, 0x00400010, 0x20004010
};

static const uint32_t sbox7[64] = {
  0x00200000, 0x04200002, 0x04000802, 0x00000000, 0x00000800, 0x04000802,
  0x00200802, 0x04200800, 0x04200802, 0x00200000, 0x00000000, 0x04000002,
  0x00000002, 0x04000000, 0x04200002, 0x00000802, 0x04000800, 0x00200802,
  0x00200002, 0x04000800, 0x04000002, 0x04200000, 0x04200800, 0x00200002,
  0x04200000, 0x00000800, 0x00000802, 0x04200802, 0x00200800, 0x00000002,
  0x04000000, 0x00200800, 0x04000000, 0x00200800, 0x00200000, 0x04000802,
  0x04000802, 0x04200002, 0x04200002, 0x00000002, 0x00200002, 0x04000000,
  0x04000800, 0x00200000, 0x04200800, 0x00000802, 0x00200802, 0x04200800,
  0x00000802, 0x04000002, 0x04200802, 0x04200000, 0x00200800, 0x00000000,
  0x00000002, 0x04200802, 0x00000000, 0x00200802, 0x04200000, 0x00000800,
  0x04000002, 0x04000800, 0x00000800, 0x00200002
};

static const uint32_t sbox8[64] = {
  0x10001040, 0x00001000, 0x00040000, 0x10041040, 0x10000000, 0x10001040,
  0x00000040, 0x10000000, 0x00040040, 0x10040000, 0x10041040, 0x00041000,
  0x10041000, 0x00041040, 0x00001000, 0x00000040, 0x10040000, 0x10000040,
  0x10001000, 0x00001040, 0x00041000, 0x00040040, 0x10040040, 0x10041000,
  0x00001040, 0x00000000, 0x00000000, 0x10040040, 0x10000040, 0x10001000,
  0x00041040, 0x00040000, 0x00041040, 0x00040000, 0x10041000, 0x00001000,
  0x00000040, 0x10040040, 0x00001000, 0x00041040, 0x10001000, 0x00000040,
  0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x00040000, 0x10001040,
  0x00000000, 0x10041040, 0x00040040, 0x10000040, 0x10040000, 0x10001000,
  0x10001040, 0x00000000, 0x10041040, 0x00041000, 0x00041000, 0x00001040,
  0x00001040, 0x00040040, 0x10000000, 0x10041000
};

/*
 * These two tables are part of the 'permuted choice 1' function.
 * In this implementation several speed improvements are done.
 */
static const uint32_t leftkey_swap[16] = {
  0x00000000, 0x00000001, 0x00000100, 0x00000101,
  0x00010000, 0x00010001, 0x00010100, 0x00010101,
  0x01000000, 0x01000001, 0x01000100, 0x01000101,
  0x01010000, 0x01010001, 0x01010100, 0x01010101
};

static const uint32_t rightkey_swap[16] = {
  0x00000000, 0x01000000, 0x00010000, 0x01010000,
  0x00000100, 0x01000100, 0x00010100, 0x01010100,
  0x00000001, 0x01000001, 0x00010001, 0x01010001,
  0x00000101, 0x01000101, 0x00010101, 0x01010101,
};

/*
 * Numbers of left shifts per round for encryption subkeys.  To
 * calculate the decryption subkeys we just reverse the ordering of
 * the calculated encryption subkeys, so there is no need for a
 * decryption rotate tab.
 */
static const unsigned char encrypt_rotate_tab[16] = {
  1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

/*
 * Table with weak DES keys sorted in ascending order.  In DES there
 * are 64 known keys which are weak. They are weak because they
 * produce only one, two or four different subkeys in the subkey
 * scheduling process.  The keys in this table have all their parity
 * bits cleared.
 */
static const unsigned char weak_keys[64][8] = {
  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},     /*w */
  {0x00, 0x00, 0x1e, 0x1e, 0x00, 0x00, 0x0e, 0x0e},
  {0x00, 0x00, 0xe0, 0xe0, 0x00, 0x00, 0xf0, 0xf0},
  {0x00, 0x00, 0xfe, 0xfe, 0x00, 0x00, 0xfe, 0xfe},
  {0x00, 0x1e, 0x00, 0x1e, 0x00, 0x0e, 0x00, 0x0e},     /*sw */
  {0x00, 0x1e, 0x1e, 0x00, 0x00, 0x0e, 0x0e, 0x00},
  {0x00, 0x1e, 0xe0, 0xfe, 0x00, 0x0e, 0xf0, 0xfe},
  {0x00, 0x1e, 0xfe, 0xe0, 0x00, 0x0e, 0xfe, 0xf0},
  {0x00, 0xe0, 0x00, 0xe0, 0x00, 0xf0, 0x00, 0xf0},     /*sw */
  {0x00, 0xe0, 0x1e, 0xfe, 0x00, 0xf0, 0x0e, 0xfe},
  {0x00, 0xe0, 0xe0, 0x00, 0x00, 0xf0, 0xf0, 0x00},
  {0x00, 0xe0, 0xfe, 0x1e, 0x00, 0xf0, 0xfe, 0x0e},
  {0x00, 0xfe, 0x00, 0xfe, 0x00, 0xfe, 0x00, 0xfe},     /*sw */
  {0x00, 0xfe, 0x1e, 0xe0, 0x00, 0xfe, 0x0e, 0xf0},
  {0x00, 0xfe, 0xe0, 0x1e, 0x00, 0xfe, 0xf0, 0x0e},
  {0x00, 0xfe, 0xfe, 0x00, 0x00, 0xfe, 0xfe, 0x00},
  {0x1e, 0x00, 0x00, 0x1e, 0x0e, 0x00, 0x00, 0x0e},
  {0x1e, 0x00, 0x1e, 0x00, 0x0e, 0x00, 0x0e, 0x00},     /*sw */
  {0x1e, 0x00, 0xe0, 0xfe, 0x0e, 0x00, 0xf0, 0xfe},
  {0x1e, 0x00, 0xfe, 0xe0, 0x0e, 0x00, 0xfe, 0xf0},
  {0x1e, 0x1e, 0x00, 0x00, 0x0e, 0x0e, 0x00, 0x00},
  {0x1e, 0x1e, 0x1e, 0x1e, 0x0e, 0x0e, 0x0e, 0x0e},     /*w */
  {0x1e, 0x1e, 0xe0, 0xe0, 0x0e, 0x0e, 0xf0, 0xf0},
  {0x1e, 0x1e, 0xfe, 0xfe, 0x0e, 0x0e, 0xfe, 0xfe},
  {0x1e, 0xe0, 0x00, 0xfe, 0x0e, 0xf0, 0x00, 0xfe},
  {0x1e, 0xe0, 0x1e, 0xe0, 0x0e, 0xf0, 0x0e, 0xf0},     /*sw */
  {0x1e, 0xe0, 0xe0, 0x1e, 0x0e, 0xf0, 0xf0, 0x0e},
  {0x1e, 0xe0, 0xfe, 0x00, 0x0e, 0xf0, 0xfe, 0x00},
  {0x1e, 0xfe, 0x00, 0xe0, 0x0e, 0xfe, 0x00, 0xf0},
  {0x1e, 0xfe, 0x1e, 0xfe, 0x0e, 0xfe, 0x0e, 0xfe},     /*sw */
  {0x1e, 0xfe, 0xe0, 0x00, 0x0e, 0xfe, 0xf0, 0x00},
  {0x1e, 0xfe, 0xfe, 0x1e, 0x0e, 0xfe, 0xfe, 0x0e},
  {0xe0, 0x00, 0x00, 0xe0, 0xf0, 0x00, 0x00, 0xf0},
  {0xe0, 0x00, 0x1e, 0xfe, 0xf0, 0x00, 0x0e, 0xfe},
  {0xe0, 0x00, 0xe0, 0x00, 0xf0, 0x00, 0xf0, 0x00},     /*sw */
  {0xe0, 0x00, 0xfe, 0x1e, 0xf0, 0x00, 0xfe, 0x0e},
  {0xe0, 0x1e, 0x00, 0xfe, 0xf0, 0x0e, 0x00, 0xfe},
  {0xe0, 0x1e, 0x1e, 0xe0, 0xf0, 0x0e, 0x0e, 0xf0},
  {0xe0, 0x1e, 0xe0, 0x1e, 0xf0, 0x0e, 0xf0, 0x0e},     /*sw */
  {0xe0, 0x1e, 0xfe, 0x00, 0xf0, 0x0e, 0xfe, 0x00},
  {0xe0, 0xe0, 0x00, 0x00, 0xf0, 0xf0, 0x00, 0x00},
  {0xe0, 0xe0, 0x1e, 0x1e, 0xf0, 0xf0, 0x0e, 0x0e},
  {0xe0, 0xe0, 0xe0, 0xe0, 0xf0, 0xf0, 0xf0, 0xf0},     /*w */
  {0xe0, 0xe0, 0xfe, 0xfe, 0xf0, 0xf0, 0xfe, 0xfe},
  {0xe0, 0xfe, 0x00, 0x1e, 0xf0, 0xfe, 0x00, 0x0e},
  {0xe0, 0xfe, 0x1e, 0x00, 0xf0, 0xfe, 0x0e, 0x00},
  {0xe0, 0xfe, 0xe0, 0xfe, 0xf0, 0xfe, 0xf0, 0xfe},     /*sw */
  {0xe0, 0xfe, 0xfe, 0xe0, 0xf0, 0xfe, 0xfe, 0xf0},
  {0xfe, 0x00, 0x00, 0xfe, 0xfe, 0x00, 0x00, 0xfe},
  {0xfe, 0x00, 0x1e, 0xe0, 0xfe, 0x00, 0x0e, 0xf0},
  {0xfe, 0x00, 0xe0, 0x1e, 0xfe, 0x00, 0xf0, 0x0e},
  {0xfe, 0x00, 0xfe, 0x00, 0xfe, 0x00, 0xfe, 0x00},     /*sw */
  {0xfe, 0x1e, 0x00, 0xe0, 0xfe, 0x0e, 0x00, 0xf0},
  {0xfe, 0x1e, 0x1e, 0xfe, 0xfe, 0x0e, 0x0e, 0xfe},
  {0xfe, 0x1e, 0xe0, 0x00, 0xfe, 0x0e, 0xf0, 0x00},
  {0xfe, 0x1e, 0xfe, 0x1e, 0xfe, 0x0e, 0xfe, 0x0e},     /*sw */
  {0xfe, 0xe0, 0x00, 0x1e, 0xfe, 0xf0, 0x00, 0x0e},
  {0xfe, 0xe0, 0x1e, 0x00, 0xfe, 0xf0, 0x0e, 0x00},
  {0xfe, 0xe0, 0xe0, 0xfe, 0xfe, 0xf0, 0xf0, 0xfe},
  {0xfe, 0xe0, 0xfe, 0xe0, 0xfe, 0xf0, 0xfe, 0xf0},     /*sw */
  {0xfe, 0xfe, 0x00, 0x00, 0xfe, 0xfe, 0x00, 0x00},
  {0xfe, 0xfe, 0x1e, 0x1e, 0xfe, 0xfe, 0x0e, 0x0e},
  {0xfe, 0xfe, 0xe0, 0xe0, 0xfe, 0xfe, 0xf0, 0xf0},
  {0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe}      /*w */
};


bool gl_des_is_weak_key (const char * key) {
  char work[8];
  int i, left, right, middle, cmp_result;

  /* clear parity bits */
  for (i = 0; i < 8; ++i)
    work[i] = ((unsigned char)key[i]) & 0xfe;

  /* binary search in the weak key table */
  left = 0;
  right = 63;
  while (left <= right)
    {
      middle = (left + right) / 2;

      if (!(cmp_result = memcmp (work, weak_keys[middle], 8)))
        return -1;

      if (cmp_result > 0)
        left = middle + 1;
      else
        right = middle - 1;
    }

  return 0;
}

/*
 * Macro to swap bits across two words.
 */
#define DO_PERMUTATION(a, temp, b, offset, mask)        \
    temp = ((a>>offset) ^ b) & mask;                    \
    b ^= temp;                                          \
    a ^= temp<<offset;


/*
 * This performs the 'initial permutation' of the data to be encrypted
 * or decrypted. Additionally the resulting two words are rotated one bit
 * to the left.
 */
#define INITIAL_PERMUTATION(left, temp, right)          \
    DO_PERMUTATION(left, temp, right, 4, 0x0f0f0f0f)    \
    DO_PERMUTATION(left, temp, right, 16, 0x0000ffff)   \
    DO_PERMUTATION(right, temp, left, 2, 0x33333333)    \
    DO_PERMUTATION(right, temp, left, 8, 0x00ff00ff)    \
    right =  (right << 1) | (right >> 31);              \
    temp  =  (left ^ right) & 0xaaaaaaaa;               \
    right ^= temp;                                      \
    left  ^= temp;                                      \
    left  =  (left << 1) | (left >> 31);

/*
 * The 'inverse initial permutation'.
 */
#define FINAL_PERMUTATION(left, temp, right)            \
    left  =  (left << 31) | (left >> 1);                \
    temp  =  (left ^ right) & 0xaaaaaaaa;               \
    left  ^= temp;                                      \
    right ^= temp;                                      \
    right  =  (right << 31) | (right >> 1);             \
    DO_PERMUTATION(right, temp, left, 8, 0x00ff00ff)    \
    DO_PERMUTATION(right, temp, left, 2, 0x33333333)    \
    DO_PERMUTATION(left, temp, right, 16, 0x0000ffff)   \
    DO_PERMUTATION(left, temp, right, 4, 0x0f0f0f0f)


/*
 * A full DES round including 'expansion function', 'sbox substitution'
 * and 'primitive function P' but without swapping the left and right word.
 * Please note: The data in 'from' and 'to' is already rotated one bit to
 * the left, done in the initial permutation.
 */
#define DES_ROUND(from, to, work, subkey)               \
    work = from ^ *subkey++;                            \
    to ^= sbox8[  work      & 0x3f ];                   \
    to ^= sbox6[ (work>>8)  & 0x3f ];                   \
    to ^= sbox4[ (work>>16) & 0x3f ];                   \
    to ^= sbox2[ (work>>24) & 0x3f ];                   \
    work = ((from << 28) | (from >> 4)) ^ *subkey++;    \
    to ^= sbox7[  work      & 0x3f ];                   \
    to ^= sbox5[ (work>>8)  & 0x3f ];                   \
    to ^= sbox3[ (work>>16) & 0x3f ];                   \
    to ^= sbox1[ (work>>24) & 0x3f ];

/*
 * Macros to convert 8 bytes from/to 32bit words.
 */
#define READ_64BIT_DATA(data, left, right)                                 \
    left  = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];  \
    right = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];

#define WRITE_64BIT_DATA(data, left, right)                                \
    data[0] = (left >> 24) &0xff; data[1] = (left >> 16) &0xff;            \
    data[2] = (left >> 8) &0xff; data[3] = left &0xff;                     \
    data[4] = (right >> 24) &0xff; data[5] = (right >> 16) &0xff;          \
    data[6] = (right >> 8) &0xff; data[7] = right &0xff;

/*
 * des_key_schedule():    Calculate 16 subkeys pairs (even/odd) for
 *                        16 encryption rounds.
 *                        To calculate subkeys for decryption the caller
 *                        have to reorder the generated subkeys.
 *
 *    rawkey:       8 Bytes of key data
 *    subkey:       Array of at least 32 uint32_ts. Will be filled
 *                  with calculated subkeys.
 *
 */
static void des_key_schedule (const char * _rawkey, uint32_t * subkey) {
  const unsigned char *rawkey = (const unsigned char *) _rawkey;
  uint32_t left, right, work;
  int round;

  READ_64BIT_DATA (rawkey, left, right)
    DO_PERMUTATION (right, work, left, 4, 0x0f0f0f0f)
    DO_PERMUTATION (right, work, left, 0, 0x10101010)
    left = ((leftkey_swap[(left >> 0) & 0xf] << 3)
            | (leftkey_swap[(left >> 8) & 0xf] << 2)
            | (leftkey_swap[(left >> 16) & 0xf] << 1)
            | (leftkey_swap[(left >> 24) & 0xf])
            | (leftkey_swap[(left >> 5) & 0xf] << 7)
            | (leftkey_swap[(left >> 13) & 0xf] << 6)
            | (leftkey_swap[(left >> 21) & 0xf] << 5)
            | (leftkey_swap[(left >> 29) & 0xf] << 4));

  left &= 0x0fffffff;

  right = ((rightkey_swap[(right >> 1) & 0xf] << 3)
           | (rightkey_swap[(right >> 9) & 0xf] << 2)
           | (rightkey_swap[(right >> 17) & 0xf] << 1)
           | (rightkey_swap[(right >> 25) & 0xf])
           | (rightkey_swap[(right >> 4) & 0xf] << 7)
           | (rightkey_swap[(right >> 12) & 0xf] << 6)
           | (rightkey_swap[(right >> 20) & 0xf] << 5)
           | (rightkey_swap[(right >> 28) & 0xf] << 4));

  right &= 0x0fffffff;

  for (round = 0; round < 16; ++round)
    {
      left = ((left << encrypt_rotate_tab[round])
              | (left >> (28 - encrypt_rotate_tab[round]))) & 0x0fffffff;
      right = ((right << encrypt_rotate_tab[round])
               | (right >> (28 - encrypt_rotate_tab[round]))) & 0x0fffffff;

      *subkey++ = (((left << 4) & 0x24000000)
                   | ((left << 28) & 0x10000000)
                   | ((left << 14) & 0x08000000)
                   | ((left << 18) & 0x02080000)
                   | ((left << 6) & 0x01000000)
                   | ((left << 9) & 0x00200000)
                   | ((left >> 1) & 0x00100000)
                   | ((left << 10) & 0x00040000)
                   | ((left << 2) & 0x00020000)
                   | ((left >> 10) & 0x00010000)
                   | ((right >> 13) & 0x00002000)
                   | ((right >> 4) & 0x00001000)
                   | ((right << 6) & 0x00000800)
                   | ((right >> 1) & 0x00000400)
                   | ((right >> 14) & 0x00000200)
                   | (right & 0x00000100)
                   | ((right >> 5) & 0x00000020)
                   | ((right >> 10) & 0x00000010)
                   | ((right >> 3) & 0x00000008)
                   | ((right >> 18) & 0x00000004)
                   | ((right >> 26) & 0x00000002)
                   | ((right >> 24) & 0x00000001));

      *subkey++ = (((left << 15) & 0x20000000)
                   | ((left << 17) & 0x10000000)
                   | ((left << 10) & 0x08000000)
                   | ((left << 22) & 0x04000000)
                   | ((left >> 2) & 0x02000000)
                   | ((left << 1) & 0x01000000)
                   | ((left << 16) & 0x00200000)
                   | ((left << 11) & 0x00100000)
                   | ((left << 3) & 0x00080000)
                   | ((left >> 6) & 0x00040000)
                   | ((left << 15) & 0x00020000)
                   | ((left >> 4) & 0x00010000)
                   | ((right >> 2) & 0x00002000)
                   | ((right << 8) & 0x00001000)
                   | ((right >> 14) & 0x00000808)
                   | ((right >> 9) & 0x00000400)
                   | ((right) & 0x00000200)
                   | ((right << 7) & 0x00000100)
                   | ((right >> 7) & 0x00000020)
                   | ((right >> 3) & 0x00000011)
                   | ((right << 2) & 0x00000004)
                   | ((right >> 21) & 0x00000002));
    }
}

void gl_des_setkey (gl_des_ctx *ctx, const char * key) {
  int i;

  des_key_schedule (key, ctx->encrypt_subkeys);

  for (i = 0; i < 32; i += 2)
    {
      ctx->decrypt_subkeys[i] = ctx->encrypt_subkeys[30 - i];
      ctx->decrypt_subkeys[i + 1] = ctx->encrypt_subkeys[31 - i];
    }
}

bool gl_des_makekey (gl_des_ctx *ctx, const char * key, size_t keylen) {
  if (keylen != 8)
    return false;

  gl_des_setkey (ctx, key);

  return !gl_des_is_weak_key (key);
}

void gl_des_ecb_crypt (gl_des_ctx *ctx, const char * _from, char * _to, int mode) {
  const unsigned char *from = (const unsigned char *) _from;
  unsigned char *to = (unsigned char *) _to;
  uint32_t left, right, work;
  uint32_t *keys;

  keys = mode ? ctx->decrypt_subkeys : ctx->encrypt_subkeys;

  READ_64BIT_DATA (from, left, right)
    INITIAL_PERMUTATION (left, work, right)
    DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
    DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
    DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
    DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
    DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
    DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
    DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
    DES_ROUND (right, left, work, keys) DES_ROUND (left, right, work, keys)
    FINAL_PERMUTATION (right, work, left)
    WRITE_64BIT_DATA (to, right, left)
}

/* Process LEN bytes of BUFFER, accumulating context into CTX.
   It is assumed that LEN % 64 == 0.  */
void md4_process_block (const void *buffer, size_t len, struct md4_ctx *ctx) {
  const uint32_t *words = buffer;
  size_t nwords = len / sizeof (uint32_t);
  const uint32_t *endp = words + nwords;
  uint32_t x[16];
  uint32_t A = ctx->A;
  uint32_t B = ctx->B;
  uint32_t C = ctx->C;
  uint32_t D = ctx->D;

  /* First increment the byte count.  RFC 1320 specifies the possible
     length of the file up to 2^64 bits.  Here we only compute the
     number of bytes.  Do a double word increment.  */
  ctx->total[0] += len;
  if (ctx->total[0] < len)
    ++ctx->total[1];

  /* Process all bytes in the buffer with 64 bytes in each round of
     the loop.  */
  while (words < endp)
    {
      int t;
      for (t = 0; t < 16; t++)
        {
          x[t] = SWAP (*words);
          words++;
        }

      /* Round 1.  */
      R1 (A, B, C, D, 0, 3);
      R1 (D, A, B, C, 1, 7);
      R1 (C, D, A, B, 2, 11);
      R1 (B, C, D, A, 3, 19);
      R1 (A, B, C, D, 4, 3);
      R1 (D, A, B, C, 5, 7);
      R1 (C, D, A, B, 6, 11);
      R1 (B, C, D, A, 7, 19);
      R1 (A, B, C, D, 8, 3);
      R1 (D, A, B, C, 9, 7);
      R1 (C, D, A, B, 10, 11);
      R1 (B, C, D, A, 11, 19);
      R1 (A, B, C, D, 12, 3);
      R1 (D, A, B, C, 13, 7);
      R1 (C, D, A, B, 14, 11);
      R1 (B, C, D, A, 15, 19);

      /* Round 2.  */
      R2 (A, B, C, D, 0, 3);
      R2 (D, A, B, C, 4, 5);
      R2 (C, D, A, B, 8, 9);
      R2 (B, C, D, A, 12, 13);
      R2 (A, B, C, D, 1, 3);
      R2 (D, A, B, C, 5, 5);
      R2 (C, D, A, B, 9, 9);
      R2 (B, C, D, A, 13, 13);
      R2 (A, B, C, D, 2, 3);
      R2 (D, A, B, C, 6, 5);
      R2 (C, D, A, B, 10, 9);
      R2 (B, C, D, A, 14, 13);
      R2 (A, B, C, D, 3, 3);
      R2 (D, A, B, C, 7, 5);
      R2 (C, D, A, B, 11, 9);
      R2 (B, C, D, A, 15, 13);

      /* Round 3.  */
      R3 (A, B, C, D, 0, 3);
      R3 (D, A, B, C, 8, 9);
      R3 (C, D, A, B, 4, 11);
      R3 (B, C, D, A, 12, 15);
      R3 (A, B, C, D, 2, 3);
      R3 (D, A, B, C, 10, 9);
      R3 (C, D, A, B, 6, 11);
      R3 (B, C, D, A, 14, 15);
      R3 (A, B, C, D, 1, 3);
      R3 (D, A, B, C, 9, 9);
      R3 (C, D, A, B, 5, 11);
      R3 (B, C, D, A, 13, 15);
      R3 (A, B, C, D, 3, 3);
      R3 (D, A, B, C, 11, 9);
      R3 (C, D, A, B, 7, 11);
      R3 (B, C, D, A, 15, 15);

      A = ctx->A += A;
      B = ctx->B += B;
      C = ctx->C += C;
      D = ctx->D += D;
    }
}

/* Initialize structure containing state of computation.
   (RFC 1320, 3.3: Step 3)  */
void md4_init_ctx (struct md4_ctx *ctx) {
  ctx->A = 0x67452301;
  ctx->B = 0xefcdab89;
  ctx->C = 0x98badcfe;
  ctx->D = 0x10325476;

  ctx->total[0] = ctx->total[1] = 0;
  ctx->buflen = 0;
}

/* Put result from CTX in first 16 bytes following RESBUF.  The result
   must be in little endian byte order.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
void * md4_read_ctx (const struct md4_ctx *ctx, void *resbuf) {
  ((uint32_t *) resbuf)[0] = SWAP (ctx->A);
  ((uint32_t *) resbuf)[1] = SWAP (ctx->B);
  ((uint32_t *) resbuf)[2] = SWAP (ctx->C);
  ((uint32_t *) resbuf)[3] = SWAP (ctx->D);

  return resbuf;
}

/* Process the remaining bytes in the internal buffer and the usual
   prolog according to the standard and write the result to RESBUF.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
void * md4_finish_ctx (struct md4_ctx *ctx, void *resbuf) {
  /* Take yet unprocessed bytes into account.  */
  uint32_t bytes = ctx->buflen;
  size_t pad;

  /* Now count remaining bytes.  */
  ctx->total[0] += bytes;
  if (ctx->total[0] < bytes)
    ++ctx->total[1];

  pad = bytes >= 56 ? 64 + 56 - bytes : 56 - bytes;
  memcpy (&((char*)ctx->buffer)[bytes], fillbuf, pad);

  /* Put the 64-bit file length in *bits* at the end of the buffer.  */
  ctx->buffer[(bytes + pad) / 4] = SWAP (ctx->total[0] << 3);
  ctx->buffer[(bytes + pad) / 4 + 1] = SWAP ((ctx->total[1] << 3) |
                                             (ctx->total[0] >> 29));

  /* Process last bytes.  */
  md4_process_block (ctx->buffer, bytes + pad + 8, ctx);

  return md4_read_ctx (ctx, resbuf);
}

void md4_process_bytes (const void *buffer, size_t len, struct md4_ctx *ctx) {
  /* When we already have some bits in our internal buffer concatenate
     both inputs first.  */
  if (ctx->buflen != 0)
    {
      size_t left_over = ctx->buflen;
      size_t add = 128 - left_over > len ? len : 128 - left_over;

      memcpy (&((char*)ctx->buffer)[left_over], buffer, add);
      ctx->buflen += add;

      if (ctx->buflen > 64)
        {
          md4_process_block (ctx->buffer, ctx->buflen & ~63, ctx);

          ctx->buflen &= 63;
          /* The regions in the following copy operation cannot overlap.  */
          memcpy (ctx->buffer, &((char*)ctx->buffer)[(left_over + add) & ~63],
                  ctx->buflen);
        }

      buffer = (const char *) buffer + add;
      len -= add;
    }

  /* Process available complete blocks.  */
  if (len >= 64)
    {
#if !_STRING_ARCH_unaligned
      if (UNALIGNED_P (buffer))
        while (len > 64)
          {
            md4_process_block (memcpy (ctx->buffer, buffer, 64), 64, ctx);
            buffer = (const char *) buffer + 64;
            len -= 64;
          }
      else
#endif
        {
          md4_process_block (buffer, len & ~63, ctx);
          buffer = (const char *) buffer + (len & ~63);
          len &= 63;
        }
    }

  /* Move remaining bytes in internal buffer.  */
  if (len > 0)
    {
      size_t left_over = ctx->buflen;

      memcpy (&((char*)ctx->buffer)[left_over], buffer, len);
      left_over += len;
      if (left_over >= 64)
        {
          md4_process_block (ctx->buffer, 64, ctx);
          left_over -= 64;
          memcpy (ctx->buffer, &ctx->buffer[16], left_over);
        }
      ctx->buflen = left_over;
    }
}

/* Compute MD4 message digest for bytes read from STREAM.  The
   resulting message digest number will be written into the 16 bytes
   beginning at RESBLOCK.  */
int md4_stream (FILE * stream, void *resblock) {
  struct md4_ctx ctx;
  char buffer[BLOCKSIZE + 72];
  size_t sum;

  /* Initialize the computation context.  */
  md4_init_ctx (&ctx);

  /* Iterate over full file contents.  */
  while (1)
    {
      /* We read the file in blocks of BLOCKSIZE bytes.  One call of the
         computation function processes the whole buffer so that with the
         next round of the loop another block can be read.  */
      size_t n;
      sum = 0;

      /* Read block.  Take care for partial reads.  */
      while (1)
        {
          n = fread (buffer + sum, 1, BLOCKSIZE - sum, stream);

          sum += n;

          if (sum == BLOCKSIZE)
            break;

          if (n == 0)
            {
              /* Check for the error flag IFF N == 0, so that we don't
                 exit the loop after a partial read due to e.g., EAGAIN
                 or EWOULDBLOCK.  */
              if (ferror (stream))
                return 1;
              goto process_partial_block;
            }

          /* We've read at least one byte, so ignore errors.  But always
             check for EOF, since feof may be true even though N > 0.
             Otherwise, we could end up calling fread after EOF.  */
          if (feof (stream))
            goto process_partial_block;
        }

      /* Process buffer with BLOCKSIZE bytes.  Note that
         BLOCKSIZE % 64 == 0
       */
      md4_process_block (buffer, BLOCKSIZE, &ctx);
    }

process_partial_block:;

  /* Process any remaining bytes.  */
  if (sum > 0)
    md4_process_bytes (buffer, sum, &ctx);

  /* Construct result in desired memory.  */
  md4_finish_ctx (&ctx, resblock);
  return 0;
}

/* Compute MD4 message digest for LEN bytes beginning at BUFFER.  The
   result is always in little endian byte order, so that a byte-wise
   output yields to the wanted ASCII representation of the message
   digest.  */
void * md4_buffer (const char *buffer, size_t len, void *resblock) {
  struct md4_ctx ctx;

  /* Initialize the computation context.  */
  md4_init_ctx (&ctx);

  /* Process whole buffer but last len % 64 bytes.  */
  md4_process_bytes (buffer, len, &ctx);

  /* Put result in desired memory area.  */
  return md4_finish_ctx (&ctx, resblock);
}

void * memxor (void *dest, const void *src, size_t n) {
  char const *s = src;
  char *d = dest;

  assert((dest != NULL && src != NULL) || n == 0);

  for (; n > 0; n--)
    *d++ ^= *s++;

  return dest;
}

int hmac_md5 (const void *key, size_t keylen, const void *in, size_t inlen, void *resbuf)
{
  struct md5_ctx inner;
  struct md5_ctx outer;
  char optkeybuf[16];
  char block[64];
  char innerhash[16];

  /* Reduce the key's size, so that it becomes <= 64 bytes large.  */

  if (keylen > 64)
    {
      struct md5_ctx keyhash;

      md5_init_ctx (&keyhash);
      md5_process_bytes (key, keylen, &keyhash);
      md5_finish_ctx (&keyhash, optkeybuf);

      key = optkeybuf;
      keylen = 16;
    }

  /* Compute INNERHASH from KEY and IN.  */

  md5_init_ctx (&inner);

  memset (block, IPAD, sizeof (block));
  memxor (block, key, keylen);

  md5_process_block (block, 64, &inner);
  md5_process_bytes (in, inlen, &inner);

  md5_finish_ctx (&inner, innerhash);

  /* Compute result from KEY and INNERHASH.  */

  md5_init_ctx (&outer);

  memset (block, OPAD, sizeof (block));
  memxor (block, key, keylen);

  md5_process_block (block, 64, &outer);
  md5_process_bytes (innerhash, 16, &outer);

  md5_finish_ctx (&outer, resbuf);

  return 0;
}



/* Initialize structure containing state of computation.
   (RFC 1321, 3.3: Step 3)  */
void
md5_init_ctx (struct md5_ctx *ctx)
{
  assert(ctx != NULL);
  ctx->A = 0x67452301;
  ctx->B = 0xefcdab89;
  ctx->C = 0x98badcfe;
  ctx->D = 0x10325476;

  ctx->total[0] = ctx->total[1] = 0;
  ctx->buflen = 0;
}

/* Put result from CTX in first 16 bytes following RESBUF.  The result
   must be in little endian byte order.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32-bit value.  */
void *
md5_read_ctx (const struct md5_ctx *ctx, void *resbuf)
{
  assert(ctx != NULL);
  assert(resbuf != NULL);
  ((uint32_t *) resbuf)[0] = SWAP (ctx->A);
  ((uint32_t *) resbuf)[1] = SWAP (ctx->B);
  ((uint32_t *) resbuf)[2] = SWAP (ctx->C);
  ((uint32_t *) resbuf)[3] = SWAP (ctx->D);

  return resbuf;
}

/* Process the remaining bytes in the internal buffer and the usual
   prolog according to the standard and write the result to RESBUF.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32-bit value.  */
void *
md5_finish_ctx (struct md5_ctx *ctx, void *resbuf)
{
  assert(ctx != NULL);
  assert(resbuf != NULL);
  /* Take yet unprocessed bytes into account.  */
  uint32_t bytes = ctx->buflen;
  size_t size = (bytes < 56) ? 64 / 4 : 64 * 2 / 4;

  /* Now count remaining bytes.  */
  ctx->total[0] += bytes;
  if (ctx->total[0] < bytes)
    ++ctx->total[1];

  /* Put the 64-bit file length in *bits* at the end of the buffer.  */
  ctx->buffer[size - 2] = SWAP (ctx->total[0] << 3);
  ctx->buffer[size - 1] = SWAP ((ctx->total[1] << 3) | (ctx->total[0] >> 29));

  memcpy (&((char *) ctx->buffer)[bytes], fillbuf, (size - 2) * 4 - bytes);

  /* Process last bytes.  */
  md5_process_block (ctx->buffer, size * 4, ctx);

  return md5_read_ctx (ctx, resbuf);
}

/* Compute MD5 message digest for bytes read from STREAM.  The
   resulting message digest number will be written into the 16 bytes
   beginning at RESBLOCK.  */
int
md5_stream (FILE *stream, void *resblock)
{
  struct md5_ctx ctx;
  char buffer[BLOCKSIZE + 72];
  size_t sum;

  /* Initialize the computation context.  */
  md5_init_ctx (&ctx);

  /* Iterate over full file contents.  */
  while (1)
    {
      /* We read the file in blocks of BLOCKSIZE bytes.  One call of the
         computation function processes the whole buffer so that with the
         next round of the loop another block can be read.  */
      size_t n;
      sum = 0;

      /* Read block.  Take care for partial reads.  */
      while (1)
        {
          n = fread (buffer + sum, 1, BLOCKSIZE - sum, stream);

          sum += n;

          if (sum == BLOCKSIZE)
            break;

          if (n == 0)
            {
              /* Check for the error flag IFF N == 0, so that we don't
                 exit the loop after a partial read due to e.g., EAGAIN
                 or EWOULDBLOCK.  */
              if (ferror (stream))
                return 1;
              goto process_partial_block;
            }

          /* We've read at least one byte, so ignore errors.  But always
             check for EOF, since feof may be true even though N > 0.
             Otherwise, we could end up calling fread after EOF.  */
          if (feof (stream))
            goto process_partial_block;
        }

      /* Process buffer with BLOCKSIZE bytes.  Note that
         BLOCKSIZE % 64 == 0
       */
      md5_process_block (buffer, BLOCKSIZE, &ctx);
    }

process_partial_block:

  /* Process any remaining bytes.  */
  if (sum > 0)
    md5_process_bytes (buffer, sum, &ctx);

  /* Construct result in desired memory.  */
  md5_finish_ctx (&ctx, resblock);
  return 0;
}

/* Compute MD5 message digest for LEN bytes beginning at BUFFER.  The
   result is always in little endian byte order, so that a byte-wise
   output yields to the wanted ASCII representation of the message
   digest.  */
void *
md5_buffer (const char *buffer, size_t len, void *resblock)
{
  struct md5_ctx ctx;

  /* Initialize the computation context.  */
  md5_init_ctx (&ctx);

  /* Process whole buffer but last len % 64 bytes.  */
  md5_process_bytes (buffer, len, &ctx);

  /* Put result in desired memory area.  */
  return md5_finish_ctx (&ctx, resblock);
}


void
md5_process_bytes (const void *buffer, size_t len, struct md5_ctx *ctx)
{
  /* When we already have some bits in our internal buffer concatenate
     both inputs first.  */
  if (ctx->buflen != 0)
    {
      size_t left_over = ctx->buflen;
      size_t add = 128 - left_over > len ? len : 128 - left_over;

      memcpy (&((char *) ctx->buffer)[left_over], buffer, add);
      ctx->buflen += add;

      if (ctx->buflen > 64)
        {
          md5_process_block (ctx->buffer, ctx->buflen & ~63, ctx);

          ctx->buflen &= 63;
          /* The regions in the following copy operation cannot overlap.  */
          memcpy (ctx->buffer,
                  &((char *) ctx->buffer)[(left_over + add) & ~63],
                  ctx->buflen);
        }

      buffer = (const char *) buffer + add;
      len -= add;
    }

  /* Process available complete blocks.  */
  if (len >= 64)
    {
#if !_STRING_ARCH_unaligned
      if (UNALIGNED_P (buffer))
        while (len > 64)
          {
            md5_process_block (memcpy (ctx->buffer, buffer, 64), 64, ctx);
            buffer = (const char *) buffer + 64;
            len -= 64;
          }
      else
#endif
        {
          md5_process_block (buffer, len & ~63, ctx);
          buffer = (const char *) buffer + (len & ~63);
          len &= 63;
        }
    }

  /* Move remaining bytes in internal buffer.  */
  if (len > 0)
    {
      size_t left_over = ctx->buflen;

      memcpy (&((char *) ctx->buffer)[left_over], buffer, len);
      left_over += len;
      if (left_over >= 64)
        {
          md5_process_block (ctx->buffer, 64, ctx);
          left_over -= 64;
          memcpy (ctx->buffer, &ctx->buffer[16], left_over);
        }
      ctx->buflen = left_over;
    }
}


/* These are the four functions used in the four steps of the MD5 algorithm
   and defined in the RFC 1321.  The first function is a little bit optimized
   (as found in Colin Plumbs public domain implementation).  */
/* #define FF(b, c, d) ((b & c) | (~b & d)) */
#define FF(b, c, d) (d ^ (b & (c ^ d)))
#define FG(b, c, d) FF (d, b, c)
#define FH(b, c, d) (b ^ c ^ d)
#define FI(b, c, d) (c ^ (b | ~d))

/* Process LEN bytes of BUFFER, accumulating context into CTX.
   It is assumed that LEN % 64 == 0.  */

void
md5_process_block (const void *buffer, size_t len, struct md5_ctx *ctx)
{
  uint32_t correct_words[16];
  const uint32_t *words = buffer;
  size_t nwords = len / sizeof (uint32_t);
  const uint32_t *endp = words + nwords;
  uint32_t A = ctx->A;
  uint32_t B = ctx->B;
  uint32_t C = ctx->C;
  uint32_t D = ctx->D;

  /* First increment the byte count.  RFC 1321 specifies the possible
     length of the file up to 2^64 bits.  Here we only compute the
     number of bytes.  Do a double word increment.  */
  ctx->total[0] += len;
  if (ctx->total[0] < len)
    ++ctx->total[1];

  /* Process all bytes in the buffer with 64 bytes in each round of
     the loop.  */
  while (words < endp)
    {
      uint32_t *cwp = correct_words;
      uint32_t A_save = A;
      uint32_t B_save = B;
      uint32_t C_save = C;
      uint32_t D_save = D;

      /* First round: using the given function, the context and a constant
         the next context is computed.  Because the algorithms processing
         unit is a 32-bit word and it is determined to work on words in
         little endian byte order we perhaps have to change the byte order
         before the computation.  To reduce the work for the next steps
         we store the swapped words in the array CORRECT_WORDS.  */

#define OP(a, b, c, d, s, T)                                            \
      do                                                                \
        {                                                               \
          a += FF (b, c, d) + (*cwp++ = SWAP (*words)) + T;             \
          ++words;                                                      \
          CYCLIC (a, s);                                                \
          a += b;                                                       \
        }                                                               \
      while (0)

      /* It is unfortunate that C does not provide an operator for
         cyclic rotation.  Hope the C compiler is smart enough.  */
#define CYCLIC(w, s) (w = (w << s) | (w >> (32 - s)))

      /* Before we start, one word to the strange constants.
         They are defined in RFC 1321 as

         T[i] = (int) (4294967296.0 * fabs (sin (i))), i=1..64

         Here is an equivalent invocation using Perl:

         perl -e 'foreach(1..64){printf "0x%08x\n", int (4294967296 * abs (sin $_))}'
       */

      /* Round 1.  */
      OP (A, B, C, D, 7, 0xd76aa478);
      OP (D, A, B, C, 12, 0xe8c7b756);
      OP (C, D, A, B, 17, 0x242070db);
      OP (B, C, D, A, 22, 0xc1bdceee);
      OP (A, B, C, D, 7, 0xf57c0faf);
      OP (D, A, B, C, 12, 0x4787c62a);
      OP (C, D, A, B, 17, 0xa8304613);
      OP (B, C, D, A, 22, 0xfd469501);
      OP (A, B, C, D, 7, 0x698098d8);
      OP (D, A, B, C, 12, 0x8b44f7af);
      OP (C, D, A, B, 17, 0xffff5bb1);
      OP (B, C, D, A, 22, 0x895cd7be);
      OP (A, B, C, D, 7, 0x6b901122);
      OP (D, A, B, C, 12, 0xfd987193);
      OP (C, D, A, B, 17, 0xa679438e);
      OP (B, C, D, A, 22, 0x49b40821);

      /* For the second to fourth round we have the possibly swapped words
         in CORRECT_WORDS.  Redefine the macro to take an additional first
         argument specifying the function to use.  */
#undef OP
#define OP(f, a, b, c, d, k, s, T)                                      \
      do                                                                \
        {                                                               \
          a += f (b, c, d) + correct_words[k] + T;                      \
          CYCLIC (a, s);                                                \
          a += b;                                                       \
        }                                                               \
      while (0)

      /* Round 2.  */
      OP (FG, A, B, C, D, 1, 5, 0xf61e2562);
      OP (FG, D, A, B, C, 6, 9, 0xc040b340);
      OP (FG, C, D, A, B, 11, 14, 0x265e5a51);
      OP (FG, B, C, D, A, 0, 20, 0xe9b6c7aa);
      OP (FG, A, B, C, D, 5, 5, 0xd62f105d);
      OP (FG, D, A, B, C, 10, 9, 0x02441453);
      OP (FG, C, D, A, B, 15, 14, 0xd8a1e681);
      OP (FG, B, C, D, A, 4, 20, 0xe7d3fbc8);
      OP (FG, A, B, C, D, 9, 5, 0x21e1cde6);
      OP (FG, D, A, B, C, 14, 9, 0xc33707d6);
      OP (FG, C, D, A, B, 3, 14, 0xf4d50d87);
      OP (FG, B, C, D, A, 8, 20, 0x455a14ed);
      OP (FG, A, B, C, D, 13, 5, 0xa9e3e905);
      OP (FG, D, A, B, C, 2, 9, 0xfcefa3f8);
      OP (FG, C, D, A, B, 7, 14, 0x676f02d9);
      OP (FG, B, C, D, A, 12, 20, 0x8d2a4c8a);

      /* Round 3.  */
      OP (FH, A, B, C, D, 5, 4, 0xfffa3942);
      OP (FH, D, A, B, C, 8, 11, 0x8771f681);
      OP (FH, C, D, A, B, 11, 16, 0x6d9d6122);
      OP (FH, B, C, D, A, 14, 23, 0xfde5380c);
      OP (FH, A, B, C, D, 1, 4, 0xa4beea44);
      OP (FH, D, A, B, C, 4, 11, 0x4bdecfa9);
      OP (FH, C, D, A, B, 7, 16, 0xf6bb4b60);
      OP (FH, B, C, D, A, 10, 23, 0xbebfbc70);
      OP (FH, A, B, C, D, 13, 4, 0x289b7ec6);
      OP (FH, D, A, B, C, 0, 11, 0xeaa127fa);
      OP (FH, C, D, A, B, 3, 16, 0xd4ef3085);
      OP (FH, B, C, D, A, 6, 23, 0x04881d05);
      OP (FH, A, B, C, D, 9, 4, 0xd9d4d039);
      OP (FH, D, A, B, C, 12, 11, 0xe6db99e5);
      OP (FH, C, D, A, B, 15, 16, 0x1fa27cf8);
      OP (FH, B, C, D, A, 2, 23, 0xc4ac5665);

      /* Round 4.  */
      OP (FI, A, B, C, D, 0, 6, 0xf4292244);
      OP (FI, D, A, B, C, 7, 10, 0x432aff97);
      OP (FI, C, D, A, B, 14, 15, 0xab9423a7);
      OP (FI, B, C, D, A, 5, 21, 0xfc93a039);
      OP (FI, A, B, C, D, 12, 6, 0x655b59c3);
      OP (FI, D, A, B, C, 3, 10, 0x8f0ccc92);
      OP (FI, C, D, A, B, 10, 15, 0xffeff47d);
      OP (FI, B, C, D, A, 1, 21, 0x85845dd1);
      OP (FI, A, B, C, D, 8, 6, 0x6fa87e4f);
      OP (FI, D, A, B, C, 15, 10, 0xfe2ce6e0);
      OP (FI, C, D, A, B, 6, 15, 0xa3014314);
      OP (FI, B, C, D, A, 13, 21, 0x4e0811a1);
      OP (FI, A, B, C, D, 4, 6, 0xf7537e82);
      OP (FI, D, A, B, C, 11, 10, 0xbd3af235);
      OP (FI, C, D, A, B, 2, 15, 0x2ad7d2bb);
      OP (FI, B, C, D, A, 9, 21, 0xeb86d391);

      /* Add the starting values of the context.  */
      A += A_save;
      B += B_save;
      C += C_save;
      D += D_save;
    }

  /* Put checksum in context given as argument.  */
  ctx->A = A;
  ctx->B = B;
  ctx->C = C;
  ctx->D = D;
}
