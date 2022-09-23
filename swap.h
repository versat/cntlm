/*
 * These are little/big endian routines for the main module of CNTLM
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

#ifndef SWAP_H
#define SWAP_H

#include <stdint.h>

#include "config/config.h"

#define swap16(x) \
	((uint16_t)( \
		(((uint16_t)(x) & (uint16_t)0x00ffU) << 8) | \
		(((uint16_t)(x) & (uint16_t)0xff00U) >> 8) ))

#define swap32(x) \
	((uint32_t)( \
		(((uint32_t)(x) & (uint32_t)0x000000ffUL) << 24) | \
		(((uint32_t)(x) & (uint32_t)0x0000ff00UL) <<  8) | \
		(((uint32_t)(x) & (uint32_t)0x00ff0000UL) >>  8) | \
		(((uint32_t)(x) & (uint32_t)0xff000000UL) >> 24) ))

#define swap64(x) \
	((uint64_t)( \
		(((uint64_t)(x) & (uint64_t)0xff00000000000000ULL) >> 56) | \
		(((uint64_t)(x) & (uint64_t)0x00ff000000000000ULL) >> 40) | \
		(((uint64_t)(x) & (uint64_t)0x0000ff0000000000ULL) >> 24) | \
		(((uint64_t)(x) & (uint64_t)0x000000ff00000000ULL) >> 8) | \
		(((uint64_t)(x) & (uint64_t)0x00000000ff000000ULL) << 8) | \
		(((uint64_t)(x) & (uint64_t)0x0000000000ff0000ULL) << 24) | \
		(((uint64_t)(x) & (uint64_t)0x000000000000ff00ULL) << 40) | \
		(((uint64_t)(x) & (uint64_t)0x00000000000000ffULL) << 56) ))

#if config_endian == 0
# define U16LE(x)		swap16(x)
# define U32LE(x)		swap32(x)
# define U64LE(x)		swap64(x)
# define U16BE(x)		(x)
# define U32BE(x)		(x)
# define U64BE(x)		(x)
#else
# define U16LE(x)		(x)
# define U32LE(x)		(x)
# define U64LE(x)		(x)
# define U16BE(x)		swap16(x)
# define U32BE(x)		swap32(x)
# define U64BE(x)		swap64(x)
#endif

#endif /* SWAP_H */
