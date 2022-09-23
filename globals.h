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
 * These are globals, mostly run-time options, defined and setup in main module
 * proxy.c
 */

#ifndef _GLOBALS_H
#define _GLOBALS_H

#include <pthread.h>

#include "utils.h"
#include "auth.h"

extern int debug;

extern struct auth_s *g_creds;			/* global NTLM credentials */

extern int ntlmbasic;				/* forward_request() */
extern int serialize;
extern int scanner_plugin;
extern long scanner_plugin_maxsize;

extern plist_t threads_list;
extern pthread_mutex_t threads_mtx;

extern plist_t connection_list;
extern pthread_mutex_t connection_mtx;

extern int pac_initialized;

extern hlist_t header_list;			/* forward_request() */
extern hlist_t users_list;			/* socks5_thread() */
extern plist_t scanner_agent_list;		/* scanner_hook() */
extern plist_t noproxy_list;			/* proxy_thread() */

#endif /* _GLOBALS_H */
