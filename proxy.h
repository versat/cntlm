/*
 * Management of parent proxies
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
 * Copyright (c) 2022 Francesco MDE aka fralken, David Kubicek
 *
 */

#ifndef PROXY_H
#define PROXY_H

extern int proxy_connect(struct auth_s *credentials, const char* url, const char* hostname);
extern int proxy_authenticate(int *sd, rr_data_t request, rr_data_t response, struct auth_s *creds);

extern int parent_add(const char *parent, int port);
extern int parent_available(void);
extern void parent_free(void);

#endif /* PROXY_H */
