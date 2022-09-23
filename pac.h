/*
 * Parsing of pac files
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

#ifndef PAC_H
#define PAC_H

/// @brief Initializes pac parser.
/// @returns 0 on failure and 1 on success.
///
/// Initializes Duktape JavaScript engine and does few basic initializations specific
/// to pac.
int pac_init(void);

/// @brief Parses the given PAC file.
/// @param pacfile PAC file to parse.
/// @returns 0 on failure and 1 on success.
///
/// Reads the given PAC file and evaluates it in the JavaScript context created
/// by pac_init.
int pac_parse_file(const char *pacfile);       // PAC file to parse

/// @brief Parses the given PAC script string.
/// @param pacstring PAC string to parse.
/// @returns 0 on failure and 1 on success.
///
/// Evaulates the given PAC script string in the JavaScript context created
/// by pac_init.
int pac_parse_string(const char *pacstring);      // PAC string to parse

/// @brief Finds proxy for the given URL and Host.
/// @param url URL to find proxy for.
/// @param host Host part of the URL.
/// @returns proxy string on sucess and NULL on error.
///
/// Finds proxy for the given URL and Host. This function should be called only
/// after pac engine has been initialized (using pac_init) and pac
/// script has been parsed (using pac_parse_file or pac_parse_string).
const char *pac_find_proxy(const char *url,            // URL to find proxy for
                           const char *host);          // Host part of the URL

/// @brief Destroys JavaSctipt context.
///
/// This function should be called once you're done with using pac engine.
void pac_cleanup(void);

#endif /* PAC_H */
