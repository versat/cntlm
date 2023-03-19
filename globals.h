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

extern int debug;						//skipcq: CXX-W2009

extern int request_logging_level;		//skipcq: CXX-W2009

extern struct auth_s *g_creds;			/* global NTLM credentials */	//skipcq: CXX-W2009, CXX-W2011

extern int ntlmbasic;					/* forward_request() */			//skipcq: CXX-W2009
extern int serialize;					//skipcq: CXX-W2009
extern int scanner_plugin;				//skipcq: CXX-W2009
extern long scanner_plugin_maxsize;		//skipcq: CXX-W2009

extern plist_t threads_list;			//skipcq: CXX-W2009
extern pthread_mutex_t threads_mtx;		//skipcq: CXX-W2009

extern plist_t connection_list;			//skipcq: CXX-W2009
extern pthread_mutex_t connection_mtx;	//skipcq: CXX-W2009

extern int pac_initialized;				//skipcq: CXX-W2009

extern hlist_t header_list;				/* forward_request() */	//skipcq: CXX-W2009
extern hlist_t users_list;				/* socks5_thread() */	//skipcq: CXX-W2009
extern plist_t scanner_agent_list;		/* scanner_hook() */	//skipcq: CXX-W2009
extern plist_t noproxy_list;			/* proxy_thread() */	//skipcq: CXX-W2009

#endif /* _GLOBALS_H */
