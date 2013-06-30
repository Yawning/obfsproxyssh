/*
 * tor_pt.c: Tor Pluggable Transport routines
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

#include <stdio.h>
#include <stdlib.h>

#include "tor_pt.h"

tor_pt_config_t *
tor_pt_get_config(void)
{
	tor_pt_config_t *cfg;
	char *s;
	bstring str;

	cfg = calloc(1, sizeof(tor_pt_config_t));
	if (NULL == cfg)
		goto error_nomem;

	cfg->state_location = bfromcstr(getenv(TOR_PT_STATE_LOCATION));
	str = bfromcstr(getenv(TOR_PT_MANAGED_TRANSPORT_VER));
	if (NULL != str) {
		cfg->transport_ver = bsplit(str, ',');
		if (NULL == cfg->transport_ver)
			goto error_nomem;
		bdestroy(str);
	} else {
		cfg->transport_ver = NULL;
	}

	cfg->is_client = (NULL != (s = getenv(TOR_PT_CLIENT_TRANSPORTS)));
	if (cfg->is_client) {
		str = bfromcstr(s);
		if (NULL == str)
			goto error_nomem;
		cfg->client.methods = bsplit(str, ',');
		bdestroy(str);
	} else {
		/* Server */
	}

	return cfg;

error_nomem:
	fprintf(stdout, "ENV-ERROR Memory allocation failed\n");
	exit(-1);
}

int
tor_pt_check_config(const tor_pt_config_t *cfg, const bstring methodname)
{
	struct tagbstring supported_ver = bsStatic(TOR_PT_MANAGED_TRANSPORT_V1);
	struct tagbstring all_methods = bsStatic("*");
	int i;

	if (cfg->transport_ver == NULL) {
		fprintf(stdout, "ENV-ERROR No Managed Transport Version specified\n");
		return -1;
	}

	for (i = 0; i < cfg->transport_ver->qty; i++) {
		if (0 == bstrcmp(&supported_ver, cfg->transport_ver->entry[i]))
			goto found_compatible_version;
	}

	fprintf(stdout, "VERSION-ERROR no-version\n");

	return -1;

found_compatible_version:
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress"
	fprintf(stdout, "VERSION %s\n", bdata(&supported_ver));
#pragma GCC diagnostic pop

	if (cfg->is_client) {
		for (i = 0; i < cfg->client.methods->qty; i++) {
			if (0 == bstrcmp(&all_methods,
						cfg->client.methods->entry[i]))
				goto found_compatible_method;

			if (0 == bstrcmp(methodname,
						cfg->client.methods->entry[i]))
				goto found_compatible_method;
		}

		tor_pt_on_client_done();

		return -1;
	} else {
		/* Validate the server options */
	}

found_compatible_method:
	return 0;
}

void
tor_pt_on_client_done(void)
{
	fprintf(stdout, "CMETHODS DONE\n");
}

void
tor_pt_on_server_done(void)
{
	fprintf(stdout, "SMETHODS DONE\n");
}

void
tor_pt_free_config(tor_pt_config_t *cfg)
{
	bdestroy(cfg->state_location);
	bstrListDestroy(cfg->transport_ver);

	if (cfg->is_client) {
		bstrListDestroy(cfg->client.methods);
	} else {
		/* Free the server bits */
	}

	free(cfg);
}

