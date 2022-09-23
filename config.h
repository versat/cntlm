/*
 * These are very basic config file routines for the main module of CNTLM
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

#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>

#include "utils.h"

#define CFG_DEFAULT(cf, opt, var, size) { char *__tmp = NULL; if ((__tmp=config_pop(cf, opt)) && !strlen(var)) { strlcpy(var, __tmp, size); } if (__tmp) free(__tmp); }

typedef struct config_s *config_t;
struct config_s {
	hlist_t options;
};

extern config_t config_open(const char *fname);
extern void config_set(config_t cf, char *option, char *value);
extern char *config_pop(config_t cf, const char *option);
extern int config_count(config_t cf);
extern void config_close(config_t cf);

#endif /* CONFIG_H */
