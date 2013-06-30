/*
 * tor_pt.h: Tor Pluggable Transport related defintions
 * Yawning Angel <yawning at schwanenlied dot me>
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org/>
 */

#include "bstrlib.h"

#ifndef _TOR_PT_H_
#define _TOR_PT_H_

#define TOR_PT_STATE_LOCATION			"TOR_PT_STATE_LOCATION"
#define TOR_PT_MANAGED_TRANSPORT_VER		"TOR_PT_MANAGED_TRANSPORT_VER"

#define TOR_PT_CLIENT_TRANSPORTS		"TOR_PT_CLIENT_TRANSPORTS"

#define TOR_PT_EXTENDED_SERVER_PORT		"TOR_PT_EXTENDED_SERVER_PORT"
#define TOR_PT_ORPORT				"TOR_PT_ORPORT"
#define TOR_PT_SERVER_BIND_ADDR			"TOR_PT_BINDADDR"
#define TOR_PT_SERVER_TRANSPORTS		"TOR_PT_SERVER_TRANSPORTS"

#define TOR_PT_MANAGED_TRANSPORT_V1	"1"

typedef struct {
	struct bstrList *methods;
} tor_pt_client_config_t;

typedef struct {

} tor_pt_server_config_t;

typedef struct {
	bstring state_location;
	struct bstrList *transport_ver;

	int is_client;
	union {
		tor_pt_client_config_t client;
		tor_pt_server_config_t server;
	};
} tor_pt_config_t;

tor_pt_config_t	*tor_pt_get_config(void);
int		 tor_pt_check_config(const tor_pt_config_t *cfg,
	const bstring methodname);
void		 tor_pt_on_client_done(void);
void		 tor_pt_on_server_done(void);
void		 tor_pt_free_config(tor_pt_config_t *cfg);

#endif

