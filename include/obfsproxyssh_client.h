/*
 * obfsproxyssh_client.h: Client state for obfsproxyssh
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

#include "obfsproxyssh.h"

#include "libssh2.h"

#ifndef _OBFSPROXYSSH_CLIENT_H_
#define _OBFSPROXYSSH_CLIENT_H_

#define OBFSPROXYSSH_CLIENT_BIND_ADDR		"127.0.0.1"
#define OBFSPROXYSSH_CLIENT_CMETHOD_ARGS	"ARGS=hostkey-rsa,hostkey-dsa,user,privkey,orport"

#define OBFSPROXYSSH_CLIENT_MAX_SOCKS_REQ	4096
#define OBFSPROXYSSH_CLIENT_WRITE_SZ		32768
#define OBFSPROXYSSH_CLIENT_READ_SZ		32768
#define OBFSPROXYSSH_CLIENT_MD5_FP_LEN		47
#define OBFSPROXYSSH_CLIENT_SHA1_FP_LEN		59
#define OBFSPROXYSSH_PEM_HDR			"-----BEGIN RSA PRIVATE KEY-----\n"
#define OBFSPROXYSSH_PEM_FTR			"-----END RSA PRIVATE KEY-----"

typedef struct obfsproxyssh_client obfsproxyssh_client_t;
typedef struct obfsproxyssh_client_args obfsproxyssh_client_args_t;
typedef struct obfsproxyssh_client_session obfsproxyssh_client_session_t;

struct obfsproxyssh_client {
	obfsproxyssh_t *state;

	struct evconnlistener *listener;
	LIST_HEAD(session_list, obfsproxyssh_client_session) sessions;

	LIST_HEAD(arg_list, obfsproxyssh_client_args) arg_cache;
};

struct obfsproxyssh_client_args {
	bstring addr;
	bstring args;

	LIST_ENTRY(obfsproxyssh_client_args) entries;
};

struct obfsproxyssh_client_session {
	obfsproxyssh_client_t *client;

	struct bufferevent *socks_ev;
	int socks_is_valid;
	bstring socks_addr;

	struct bufferevent *ssh_ev;
	int ssh_is_valid;
	bstring ssh_addr;
	void (*libssh2_cb)(obfsproxyssh_client_session_t *);

	LIBSSH2_SESSION *ssh_session;
	LIBSSH2_CHANNEL *ssh_channel;

	bstring hostkey_rsa;
	bstring hostkey_dss;
	bstring user;
	bstring privkey_pem;
	uint16_t orport;
	void *privkey;

	char ssh_rx_buf[OBFSPROXYSSH_CLIENT_READ_SZ];

	LIST_ENTRY(obfsproxyssh_client_session) entries;
};

int	obfsproxyssh_client_init(obfsproxyssh_t *state);

#endif
