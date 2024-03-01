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

#ifndef SCANNER_H
#define SCANNER_H

#include "utils.h"
#include "auth.h"

/*
 * ISA plugin flags
 */
#define PLUG_NONE	0x0000
#define PLUG_SENDHEAD	0x0001
#define PLUG_SENDDATA	0x0002
#define PLUG_ERROR	0x8000
#define PLUG_ALL	0x7FFF

/*
 * Plugin download sample size
 */
#define SAMPLE		4096

extern int scanner_hook(rr_data_const_t request, rr_data_t response, struct auth_s *credentials, int cd, int *sd, long maxKBs);

#endif /* SCANNER_H */
