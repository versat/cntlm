/*
 * These are ACL routines for the main module of CNTLM
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

#include <sys/types.h>
#include <sys/socket.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "acl.h"
#include "socket.h"
#include "swap.h"

/*
 * TODO: retest ACLs on big-endian
 */

/*
 * Add the rule spec to the ACL list.
 */
int acl_add(plist_t *rules, char *spec, enum acl_t acl) {
	struct in_addr source;
	network_t *aux;
	int i, mask = 32;
	char *tmp;

	if (rules == NULL)
		return 0;

	spec = strdup(spec);
	aux = (network_t *)zmalloc(sizeof(network_t));
	i = strcspn(spec, "/");
	if (i < strlen(spec)) {
		spec[i] = 0;
		mask = strtol(spec+i+1, &tmp, 10);
		if (mask < 0 || mask > 32 || spec[i+1] == 0 || *tmp != 0) {
			syslog(LOG_ERR, "ACL netmask for %s is invalid\n", spec);
			free(aux);
			free(spec);
			return 0;
		}
	}

	if (!strcmp("*", spec)) {
		source.s_addr = 0;
		mask = 0;
	} else {
		if (!strcmp("0", spec)) {
			source.s_addr = 0;
		} else if (!so_resolv(&source, spec)) {
			syslog(LOG_ERR, "ACL source address %s is invalid\n", spec);
			free(aux);
			free(spec);
			return 0;
		}
	}

	aux->ip = source.s_addr;
	aux->mask = mask;
	mask = swap32(~(((uint64_t)1 << (32-mask)) - 1));
	if ((source.s_addr & mask) != source.s_addr)
		syslog(LOG_WARNING, "Subnet definition might be incorrect: %s/%d\n", inet_ntoa(source), aux->mask);

	syslog(LOG_INFO, "New ACL rule: %s %s/%d\n", (acl == ACL_ALLOW ? "allow" : "deny"), inet_ntoa(source), aux->mask);
	*rules = plist_add(*rules, acl, (char *)aux);

	free(spec);
	return 1;
}

/*
 * Takes client IP address (network order) and walks the
 * ACL rules until a match is found, returning ACL_ALLOW
 * or ACL_DENY accordingly. If no rule matches, connection
 * is allowed (such is the case with no ACLs).
 *
 * Proper policy should always end with a default rule,
 * targetting either "*" or "0/0" to explicitly express
 * one's intentions.
 */
enum acl_t acl_check(plist_t rules, struct in_addr naddr) {
	network_t *aux;
	int mask;

	while (rules) {
		aux = (network_t *)rules->aux;
		mask = swap32(~(((uint64_t)1 << (32-aux->mask)) - 1));

		if ((naddr.s_addr & mask) == (aux->ip & mask))
			return ACL_DENY;

		rules = rules->next;
	}

	return ACL_ALLOW;
}
