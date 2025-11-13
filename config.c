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

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "config.h"
#include "globals.h"

config_t config_open(const char *fname) {
	config_t rc;
	FILE *fp;
	char *buf;
	char section[MINIBUF_SIZE] = "global";
	size_t i;
	size_t j;
	size_t slen;

	fp = fopen(fname, "r");
	if (!fp)
		return NULL;

	buf = zmalloc(BUFSIZE);
	rc = (config_t)zmalloc(sizeof(struct config_s));
	rc->options = NULL;

	while (!feof(fp)) {
		int quote = 0;
		const char *tmp = fgets(buf, BUFSIZE, fp);
		if (!tmp)
			break;

		const size_t len = MIN(BUFSIZE, strlen(buf));
		if (!len || feof(fp))
			continue;

		/*
		 * Find first non-empty character
		 */
		for (j = 0; j < len && isspace((u_char)buf[j]); ++j);

		/*
		 * Comment?
		 */
		if (j >= len || buf[j] == '#' || buf[j] == ';')
			continue;

		/*
		 * Find end of keyword
		 */
		for (i = j; j < len && isalnum((u_char)buf[j]); ++j);

		/*
		 * Malformed?
		 */
		if (j >= len)
			continue;

		/*
		 * Is it a section?
		 */
		if (buf[j] == '[') {
			for (++j; j < len && isspace((u_char)buf[j]); ++j);
			for (slen = j; j < len && j-slen < MINIBUF_SIZE-1 && buf[j] != ']' && !isspace((u_char)buf[j]); ++j);
			if (j-slen > 0) {
				strlcpy(section, buf+slen, j-slen+1);
			}
			continue;
		}

		/*
		 * It's an OK keyword
		 */
		char * key = substr(buf, (int)i, (int)(j-i));

		/*
		 * Find next non-empty character
		 */
		for (; j < len && isspace((u_char)buf[j]); ++j);
		if (j >= len || buf[j] == '#' || buf[j] == ';') {
			free(key);
			continue;
		}

		/*
		 * Is value quoted?
		 */
		if (buf[j] == '"') {
			quote = 1;
			for (i = ++j; j < len && buf[i] != '"'; ++i);
			if (i >= len) {
				free(key);
				continue;
			}
		} else
			i = len;

		/*
		 * Get value as quoted or until EOL/comment
		 */
		char * value = substr(buf, (int)j, (int)(i-j));
		if (!quote) {
			i = strcspn(value, "#");
			if (i != strlen(value))
				value[i] = 0;
			trimr(value);
		}

		if (debug)
			printf("section: %s, %s = '%s'\n", section, key, value);
		rc->options = hlist_add(rc->options, key, value, HLIST_NOALLOC, HLIST_NOALLOC);
	}

	free(buf);
	fclose(fp);

	return rc;
}

void config_set(config_t cf, char *option, char *value) {
	cf->options = hlist_mod(cf->options, option, value, 1);
}

char *config_pop(config_t cf, const char *option) {
	char *tmp;

	tmp = hlist_get(cf->options, option);
	if (tmp) {
		tmp = strdup(tmp);
		cf->options = hlist_del(cf->options, option);
	}

	return tmp;
}

int config_count(config_const_t cf) {
	return hlist_count(cf->options);
}

void config_close(config_t cf) {
	if (cf == NULL)
		return;

	cf->options = hlist_free(cf->options);
	free(cf);
}
