/*
 * obfsproxyssh_client.c: obfsproxyssh client
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

#include <sys/socket.h>
#include <netinet/in.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "obfsproxyssh_client.h"
#include "libssh2_helpers.h"
#include "socks4.h"

/*
 * With debug builds of libssh2 this will add ssh protocol diagnostics to the
 * log file.
 *
 * Note: This includes hexdumps of cleartext, so should ONLY be used when
 * debugging.
 */
/* #define TRACE_LIBSSH2 1 */

/*
 * TODO: (In rough order of priority)
 *  * When libssh2 supports ECDSA, add code to handle the fingerprint.
 *  * Add timeout code to the connect phase (Tor does give up after a while and
 *    just closes the connection, so not strictly needed).
 *  * Instead of buffering client->server and server->client data indefinately
 *    I should attempt to apply backpressure.  Not sure if this matters since
 *    Tor itself is fairly bad wrt end to end congestion notification.
 *  * Some parts of the code assume IPv4.  This is perfectly fine for now, but
 *    the correct thing to do would be to go and change that in preparation for
 *    the day that this code can use SOCKS 5.
 *  * Someone that's not me should do the minimal work required to make this
 *    run on Windows.
 *  * The SOCKS 4 implementation is rather rude and just closes the connection
 *    instead of sending failure responses.  It should be nicer, but I'm not
 *    sure if Tor actually cares about that.
 *  * When the Tor people decide on how to make passing config parameters to
 *    PTs better, switch the proxy protocol to SOCKS 5 so that I can support
 *    IPv6.
 *  * It's probably possible to re-use ssh connections to particular peers by
 *    opening multiple channels.  Per mikeperry Tor only opens a new connection
 *    to a bridge when there is an astronomical number of circuits so it's more
 *    than likely not worth the reward.
 *  * Consider ditching libssh2 and just writing our own ssh wire protocol
 *    library at some point.  It would need to mimic OpenSSH/Putty so it may
 *    not be worth the effort.
 *  * Should I support DSA keys?
 *  * What should I do about the Iran use case?  Having to add my own
 *    reliability layer is kind of lame and will have negative impact on
 *    performance, but it's the only solution to that sort of behavior that
 *    will allow for transparent reconnection.  They probably don't allow
 *    outgoing ssh anyway, so not something that needs to be done in the short
 *    run.
 *  * I should try to break up the ssh packet sizes as well, unless Tor
 *    tunnelled over SSH doesn't look noticiably distinctive.
 */

/*
 * SSH client profiles
 */

typedef struct obfsproxyssh_client_profile obfsproxyssh_client_profile_t;

struct obfsproxyssh_client_profile {
	const char *client_name;

	const char *banner;
	const int enable_compression;

	/* Key exchange related constants */
	const char *kex_methods[LIBSSH2_METHOD_LANG_SC + 1];

	/* Disconnect msg */
	const char *disconnect_msg;
};

static const obfsproxyssh_client_profile_t ssh_client_profile_putty = {
	"PuTTY",
	"SSH-2.0-PuTTY_Release_0.62",
	1,

	{
		"diffie-hellman-group-exchange-sha256,"
		"diffie-hellman-group-exchange-sha1,"
		"diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,"
		"rsa2048-sha256,rsa1024-sha1",

		"ssh-rsa,ssh-dss",

		"aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-ctr,"
		"aes192-cbc,blowfish-ctr,blowfish-cbc,3des-ctr,3des-cbc,"
		"arcfour256,arcfour128",

		"aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-ctr,"
		"aes192-cbc,blowfish-ctr,blowfish-cbc,3des-ctr,3des-cbc,"
		"arcfour256,arcfour128",

		"hmac-sha1,hmac-sha1-96,hmac-md5",

		"hmac-sha1,hmac-sha1-96,hmac-md5",

		"none,zlib",

		"none,zlib",

		NULL,

		NULL
	},

	NULL,
};

static const obfsproxyssh_client_profile_t ssh_client_profile_putty_insecure = {
	"PuTTY",
	"SSH-2.0-PuTTY_Release_0.62",
	1,

	{
		"diffie-hellman-group-exchange-sha1,"
		"diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",

		"ssh-rsa,ssh-dss",

		"aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-ctr,"
		"aes192-cbc,blowfish-cbc,3des-cbc,arcfour128",

		"aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-ctr,"
		"aes192-cbc,blowfish-cbc,3des-cbc,arcfour128",

		"hmac-sha1,hmac-sha1-96,hmac-md5",

		"hmac-sha1,hmac-sha1-96,hmac-md5",

		"none,zlib",

		"none,zlib",

		NULL,

		NULL
	},

	NULL,
};

static const obfsproxyssh_client_profile_t *ssh_client_profile_current = NULL;

static void	client_on_shutdown(obfsproxyssh_t *state, int arg);
static void	client_error_cb(struct evconnlistener *lis, void *ptr);

static char	*client_arg_cache(obfsproxyssh_client_t *client, bstring addr,
	const char *arg);

static void	socks_accept_cb(struct evconnlistener *lis, evutil_socket_t fd,
	struct sockaddr *addr, int len, void *ptr);
static void	socks_read_cb(struct bufferevent *bev, void *ptr);
static void	socks_event_cb(struct bufferevent *bev, short what, void *ptr);
static void	socks_relay_cb(struct bufferevent *bev, void *ptr);
static void 	socks_relay_teardown_cb(struct bufferevent *bev, void *ptr);

static int	ssh_new_connection(obfsproxyssh_client_session_t *session,
	struct sockaddr_in *addr, const char *args);
static int	ssh_parse_args(obfsproxyssh_client_session_t *session, const
	char * args);
static bstring	ssh_arg_to_privkey(const bstring argkey);
static int	ssh_validate_hostkey(obfsproxyssh_client_session_t *session);

static void	ssh_event_cb(struct bufferevent *bev, short what, void *ptr);
static void	ssh_read_cb(struct bufferevent *bev, void *ptr);
static void	ssh_write_cb(struct bufferevent *bev, void *ptr);
static void	ssh_handshake_cb(obfsproxyssh_client_session_t *session);
static void	ssh_auth_cb(obfsproxyssh_client_session_t *session);
static void	ssh_channel_cb(obfsproxyssh_client_session_t *session);
static void	ssh_relay_event_cb(struct bufferevent *bev, short what,
	void *ptr);
static void	ssh_relay_cb(obfsproxyssh_client_session_t *session);
static void	ssh_relay_teardown_cb(obfsproxyssh_client_session_t *session);

static LIBSSH2_RECV_FUNC(libssh2_recv_cb);
static LIBSSH2_SEND_FUNC(libssh2_send_cb);
#ifdef TRACE_LIBSSH2
static void libssh2_trace_cb(LIBSSH2_SESSION *session, void *context,
	const char *data, size_t length);
#endif

static void	session_free(obfsproxyssh_client_session_t *session);

static int	ssh_client_profile_init(obfsproxyssh_client_t *client);
static int	ssh_client_profile_set(obfsproxyssh_client_session_t
	*session);
static const char	*ssh_client_profile_get_disconnect_msg(void);

int
obfsproxyssh_client_init(obfsproxyssh_t *state)
{
	obfsproxyssh_client_t *client;
	struct sockaddr_storage addr;
	evutil_socket_t sock;
	uint16_t port;
	int rval, len;

	client = calloc(1, sizeof(obfsproxyssh_client_t));
	if (NULL == client) {
		fprintf(stdout, "CMETHOD-ERROR %s Out of memory allocating state\n",
						OBFSPROXYSSH_METHOD);
		return -1;
	}
	client->state = state;

	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);
	evutil_parse_sockaddr_port(OBFSPROXYSSH_CLIENT_BIND_ADDR ":8080",
					(struct sockaddr *) &addr, &len);
	((struct sockaddr_in *) &addr)->sin_port = 0;	/* Use ephemeral port */
	client->listener = evconnlistener_new_bind(state->base,
			socks_accept_cb, client,
			LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
			-1, (struct sockaddr *) &addr, len);
	if (NULL == client->listener) {
		fprintf(stdout, "CMETHOD-ERROR %s Failed to bind SOCKS socket\n",
						OBFSPROXYSSH_METHOD);
		goto out_error;
	}
	evconnlistener_set_error_cb(client->listener, client_error_cb);

	sock = evconnlistener_get_fd(client->listener);
	len = sizeof(addr);
	rval = getsockname(sock, (struct sockaddr *) &addr, (socklen_t *) &len);
	if (rval) {
		fprintf(stdout, "CMETHOD-ERROR %s Failed to get SOCKS socket addr %d\n",
						OBFSPROXYSSH_METHOD, rval);
		goto out_free_listener;
	}
	port = htons(((struct sockaddr_in *) &addr)->sin_port);

	rval = libssh2_init(0);
	if (rval) {
		fprintf(stdout, "CMETHOD-ERROR %s Failed to initialize libssh2 (%d)\n",
						OBFSPROXYSSH_METHOD, rval);
		goto out_free_listener;
	}

	rval = ssh_client_profile_init(client);
	if (rval) {
		fprintf(stdout, "CMETHOD-ERROR %s Failed to initialize libssh2 algorithms (%d)\n",
						OBFSPROXYSSH_METHOD, rval);
		goto out_free_listener;
	}

	if (0 == state->unsafe_logging)
		log_f(state, "SOCKS: Listening on: TCP port %d", port);
	else
		log_f(state, "SOCKS: Listening on: %s:%d",
				OBFSPROXYSSH_CLIENT_BIND_ADDR, port);

	fprintf(stdout, "CMETHOD %s socks4 %s:%d %s\n", OBFSPROXYSSH_METHOD,
			OBFSPROXYSSH_CLIENT_BIND_ADDR, port,
			OBFSPROXYSSH_CLIENT_CMETHOD_ARGS);

	LIST_INIT(&client->sessions);
	LIST_INIT(&client->arg_cache);
	state->ctxt = client;
	state->shutdown_fn = client_on_shutdown;
	return 0;

out_free_listener:
	evconnlistener_free(client->listener);
out_error:
	free(client);
	return -1;
}

static void
client_on_shutdown(obfsproxyssh_t *state, int arg)
{
	obfsproxyssh_client_t *client = state->ctxt;
	obfsproxyssh_client_session_t *session, *tmp;
	obfsproxyssh_client_args_t *p;

	if (NULL != client->listener) {
		log_f(state, "SOCKS: Stopped accepting new connections");
		evconnlistener_free(client->listener);
		client->listener = NULL;

		while(!LIST_EMPTY(&client->arg_cache)) {
			p = LIST_FIRST(&client->arg_cache);
			LIST_REMOVE(p, entries);
			bdestroy(p->addr);
			bdestroy(p->args);
			free(p);
		}
	}

	if (OBFSPROXYSSH_SHUTDOWN_LISTENER == arg)
		return;

	session = LIST_FIRST(&client->sessions);
	while (session != NULL) {
		tmp = LIST_NEXT(session, entries);
		bufferevent_disable(tmp->socks_ev, EV_READ);
		socks_event_cb(tmp->socks_ev, BEV_ERROR, tmp);
		session = tmp;
	}

	if (OBFSPROXYSSH_SHUTDOWN_SESSIONS == arg)
		return;

	libssh2_exit();

	free(client);
	state->ctxt = NULL;
	state->shutdown_fn = NULL;
}

static void
client_error_cb(struct evconnlistener *lis, void *ptr)
{
	obfsproxyssh_client_t *client = ptr;
	obfsproxyssh_t *state = client->state;
	int err;

	assert(lis == client->listener);

	err = EVUTIL_SOCKET_ERROR();
	log_f(state, "SOCKS: Error: Error on listen socket (%d)", err);

	evconnlistener_free(lis);
	client->listener = NULL;
}

static char *
client_arg_cache(obfsproxyssh_client_t *client, bstring addr, const char *arg)
{
	obfsproxyssh_t *state = client->state;
	obfsproxyssh_client_args_t *p;

	/*
	 * Versions of Tor that don't have asn's patch will forget bridge
	 * arguments and send no connect argument.  Work around this by caching
	 * the last valid argument per remote ip/port pair and using that when
	 * we don't receive anything.
	 *
	 * Versions of Tor that are sufficiently old flat out don't support
	 * bridge arguments so there's an option to take it from the command
	 * line as well.
	 *
	 * Note: Yes, lookup is O(n).  No it does not matter since "n" is small.
	 */

	p = LIST_FIRST(&client->arg_cache);
	while (NULL != p) {
		if (0 != bstrcmp(addr, p->addr)) {
			p = LIST_NEXT(p, entries);
			continue;
		}

		if (NULL == arg || '\0' == *arg) {
			log_f(state, "SOCKS: Warn: Client sent 0 length argument (cache hit)");
			return bdata(p->args);
		}

		/* Update the cache entry and return */
		bdestroy(p->args);
		p->args = bfromcstr(arg);

		return bdata(p->args);
	}

	/* Cache miss */

	if (NULL == arg || '\0' == *arg) {
		if (NULL != state->default_client_args) {
			log_f(state, "SOCKS: Error: Client sent 0 length argument for a unknown bridge (Using command line args)");
			arg = state->default_client_args;
			goto do_cache;
		}

		/* We are screwed at this point */
		log_f(state, "SOCKS: Error: Client sent 0 length argument for a unknown bridge");
		return NULL;
	}

do_cache:
	p = malloc(sizeof(obfsproxyssh_client_args_t));
	p->addr = bstrcpy(addr);
	p->args = bfromcstr(arg);

	LIST_INSERT_HEAD(&client->arg_cache, p, entries);

	return bdata(p->args);
}

static void
socks_accept_cb(struct evconnlistener *lis, evutil_socket_t fd,
	struct sockaddr *addr, int len, void *ptr)
{
	obfsproxyssh_client_t *client = ptr;
	obfsproxyssh_t *state = client->state;
	obfsproxyssh_client_session_t *session;
	struct sockaddr_in *sa;
	char addr_buf[INET_ADDRSTRLEN];
	uint32_t tmp;

	assert(lis == client->listener);

	/*
	 * It is possible to defer allocating the session object till after the
	 * SOCKS protocol handling is done, but there isn't much point in doing
	 * so.
	 */

	session = calloc(1, sizeof(obfsproxyssh_client_session_t));
	if (NULL == session) {
		log_f(state, "SOCKS: Error: Failed to allocate session");
		goto out_close;
	}

	session->socks_ev = bufferevent_socket_new(state->base, fd,
					BEV_OPT_CLOSE_ON_FREE);
	if (NULL == session->socks_ev) {
		log_f(state, "SOCKS: Error: Failed to allocate bev");
		free(session);
		goto out_close;
	}
	bufferevent_setcb(session->socks_ev, socks_read_cb, NULL,
			socks_event_cb, session);
	bufferevent_enable(session->socks_ev, EV_READ | EV_WRITE);

	sa = (struct sockaddr_in *) addr;
	if (0 == state->unsafe_logging) {
		tmp = ntohl(sa->sin_addr.s_addr);
		tmp &= 0x000000ff;
		session->socks_addr = bformat("xxx.xxx.xxx.%d:%d", tmp,
			ntohs(sa->sin_port));
	} else {
		evutil_inet_ntop(AF_INET, &sa->sin_addr, addr_buf,
				INET_ADDRSTRLEN);
		session->socks_addr = bformat("%s:%d", addr_buf,
				ntohs(sa->sin_port));
	}
	/* TODO: Set the timeout */

	LIST_INSERT_HEAD(&client->sessions, session, entries);
	session->client = client;

	log_f(state, "SOCKS: %s Connect", bdata(session->socks_addr));

	return;

out_close:
	evutil_closesocket(fd);
}

static void
socks_read_cb(struct bufferevent *bev, void *ptr)
{
	obfsproxyssh_client_session_t *session = ptr;
	obfsproxyssh_t *state = session->client->state;
	struct evbuffer *buf;
	struct sockaddr_in addr;
	unsigned char *p, *userid;
	size_t len;
	int i;

	assert(bev == session->socks_ev);

	buf = bufferevent_get_input(bev);
	len = evbuffer_get_length(buf);
	if (len < SOCKS_4_CONNECT_REQUEST_LEN)
		return;

	p = evbuffer_pullup(buf, len);
	if (NULL == p) {
		log_f(state, "SOCKS: Error: %s Failed to pullup (OOM?)",
				bdata(session->socks_addr));
		goto out_free;
	}

	/*
	 * Parse the SOCKS 4 CONNECT
	 *
	 * uint8_4  VN  -> 4
	 * uint8_t  CN	-> 1
	 * uint16_t DSTPORT
	 * uint32_t DSTIP
	 * uint8_t  USERID[] (Tor PT arguments)
	 * uint8_t  NULL -> 0
	 */

	if (SOCKS_4_VER != p[0]) {
		log_f(state, "SOCKS: Error: %s Invalid SOCKS protocol version %d",
				bdata(session->socks_addr),
				p[0]);
		goto out_free;
	}

	if (SOCKS_4_CMD_CONNECT != p[1]) {
		log_f(state, "SOCKS: Error: %s Invalid SOCKS 4 command %d",
				bdata(session->socks_addr),
				p[1]);
		goto out_free;
	}

	userid = p + SOCKS_4_CONNECT_REQUEST_LEN;
	for (i = 0; i < len - SOCKS_4_CONNECT_REQUEST_LEN; i++) {
		if ('\0' == userid[i]) {
			if (len != SOCKS_4_CONNECT_REQUEST_LEN + i + 1) {
				log_f(state, "SOCKS: Error: %s Trailing garbage after CONNECT",
						bdata(session->socks_addr));
				goto out_free;
			}
			bufferevent_disable(bev, EV_READ);

			memset(&addr, 0, sizeof(addr));
			addr.sin_family = AF_INET;
			addr.sin_port = *(uint16_t *) (p + 2);
			addr.sin_addr.s_addr = *(uint32_t *) (p + 4);

			if (ssh_new_connection(session, &addr, (char *) userid))
				goto out_free;

			evbuffer_drain(buf, len);

			return;
		}
	}

	if (len > OBFSPROXYSSH_CLIENT_MAX_SOCKS_REQ) {
		log_f(state, "SOCKS: Error: %s SOCKS 4 Request too big",
				bdata(session->socks_addr));
		goto out_free;
	}
	return;

out_free:
	session_free(session);
	return;
}

static void
socks_event_cb(struct bufferevent *bev, short what, void *ptr)
{
	obfsproxyssh_client_session_t *session = ptr;
	obfsproxyssh_t *state = session->client->state;

	assert(session->socks_ev == bev);

	if (0 == (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)))
		return;

	log_f(state, "SOCKS: %s Disconnect", bdata(session->socks_addr));

	session->socks_is_valid = 0;
	if (0 == session->ssh_is_valid)
		session_free(session);
	else {
		session->libssh2_cb = ssh_relay_teardown_cb;
		session->libssh2_cb(session);
	}
}

static void
socks_relay_cb(struct bufferevent *bev, void *ptr)
{
	obfsproxyssh_client_session_t *session = ptr;
	obfsproxyssh_t *state = session->client->state;
	struct evbuffer *buf;
	unsigned char *p;
	size_t len;
	ssize_t rval;

	assert(session->socks_ev == bev);

	/*
	 * Note: This is not very efficient, but since libssh2 doesn't have
	 * scatter/gather I/O and libssh2 is most efficient when sending 1 SSH
	 * packet worth of data (32 KiB) at a time, I can't think of a better
	 * way to do this.
	 */

	buf = bufferevent_get_input(bev);
	len = evbuffer_get_length(buf);
	len = (len > OBFSPROXYSSH_CLIENT_WRITE_SZ) ?
		OBFSPROXYSSH_CLIENT_WRITE_SZ : len;
	p = evbuffer_pullup(buf, len);
	if (NULL == p) {
		log_f(state, "RELAY: Error: %s Failed to pullup (OOM?)",
				bdata(session->socks_addr));
		ssh_relay_event_cb(session->ssh_ev, BEV_EVENT_ERROR, session);
		return;
	}

	rval = libssh2_channel_write(session->ssh_channel, (char *) p, len);
	if (LIBSSH2_ERROR_EAGAIN == rval || 0 == rval)
		return;
	else if (rval < 0) {
		log_f(state, "RELAY: Error: %s Channel write failed (%d)",
				bdata(session->ssh_addr), rval);
		ssh_relay_event_cb(session->ssh_ev, BEV_EVENT_ERROR, session);
		return;
	} else
		evbuffer_drain(buf, rval);
}

static void
socks_relay_teardown_cb(struct bufferevent *bev, void *ptr)
{
	obfsproxyssh_client_session_t *session = ptr;

	session_free(session);
}

static int
ssh_new_connection(obfsproxyssh_client_session_t *session,
	struct sockaddr_in *addr, const char *args)
{
	obfsproxyssh_t *state = session->client->state;
	char addr_buf[INET_ADDRSTRLEN];
	char *cached_arg;
	uint32_t tmp;
	bstring tmp_addr;
	int rval;

	evutil_inet_ntop(AF_INET, &addr->sin_addr, addr_buf, INET_ADDRSTRLEN);
	tmp_addr = bformat("%s:%d", addr_buf, ntohs(addr->sin_port));

	if (0 == state->unsafe_logging) {
		tmp = ntohl(addr->sin_addr.s_addr);
		tmp &= 0x000000ff;
		session->ssh_addr = bformat("xxx.xxx.xxx.%d:%d", tmp,
			ntohs(addr->sin_port));
	} else {
		session->ssh_addr = bstrcpy(tmp_addr);
	}

	log_f(state, "SOCKS: %s SOCKS 4 CONNECT -> %s",
			bdata(session->socks_addr), bdata(session->ssh_addr));

	cached_arg = client_arg_cache(session->client, tmp_addr, args);
	bdestroy(tmp_addr);

	rval = ssh_parse_args(session, cached_arg);
	if (rval) {
		log_f(state, "SOCKS: Error: %s Invalid arguments in CONNECT",
				bdata(session->socks_addr));
		return -1;
	}

	/* Note: Yes, this needs defered callbacks */
	session->ssh_ev = bufferevent_socket_new(state->base, -1,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (NULL == session->ssh_ev) {
		log_f(state, "SOCKS: Error: %s Failed to allocate ssh event",
				bdata(session->socks_addr));
		return -1;
	}

	bufferevent_setcb(session->ssh_ev, NULL, NULL, ssh_event_cb, session);

	rval = bufferevent_socket_connect(session->ssh_ev,
			(struct sockaddr *) addr, sizeof (struct sockaddr_in));
	if (rval < 0) {
		log_f(state, "SOCKS: Error: %s Failed to connect ssh socket",
				bdata(session->socks_addr));
		return -1;
	}

	session->ssh_session = libssh2_session_init_ex(NULL, NULL, NULL, session);
	if (NULL == session->ssh_session) {
		log_f(state, "SOCKS: Error: %s Failed to initialize libssh2 session",
				bdata(session->socks_addr));
		return -1;
	}

	libssh2_session_callback_set(session->ssh_session,
				LIBSSH2_CALLBACK_RECV, libssh2_recv_cb);
	libssh2_session_callback_set(session->ssh_session,
				LIBSSH2_CALLBACK_SEND, libssh2_send_cb);
	libssh2_session_set_blocking(session->ssh_session, 0);
	rval = ssh_client_profile_set(session);
	if (rval < 0) {
		log_f(state, "SOCKS: Error: Failed to enable fingerprint resistance",
				bdata(session->socks_addr));
		return -1;
	}

	/*
	 * This only works with debug builds of libssh2 and creates an
	 * astronomical amount of log spam.
	 */
#ifdef TRACE_LIBSSH2
	if (1 == state->unsafe_logging) {
		libssh2_trace(session->ssh_session, LIBSSH2_TRACE_SOCKET |
				LIBSSH2_TRACE_TRANS | LIBSSH2_TRACE_KEX |
				LIBSSH2_TRACE_AUTH | LIBSSH2_TRACE_CONN |
				LIBSSH2_TRACE_ERROR);
		libssh2_trace_sethandler(session->ssh_session, state,
				libssh2_trace_cb);
	}
#endif

	return 0;
}

static int
ssh_parse_args(obfsproxyssh_client_session_t *session, const char * args)
{
	obfsproxyssh_t *state = session->client->state;
	struct tagbstring hkey_rsa_prefix = bsStatic("hostkey-rsa=");
	struct tagbstring hkey_dss_prefix = bsStatic("hostkey-dsa=");
	struct tagbstring user_prefix = bsStatic("user=");
	struct tagbstring privkey_prefix = bsStatic("privkey=");
	struct tagbstring orport_prefix = bsStatic("orport=");
	struct tagbstring arg_str;
	struct bstrList *arg_list;
	bstring tmp;
	int i;

	/*
	 * Arguments are passed in as a single NULL terminated string,
	 * separated by ";" (Eg: "rocks=20;height=5.6m").
	 *
	 * Supported args:
	 *  * "hostkey-rsa=XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX"
	 *  * "hostkey-dsa=YY:YY:YY:YY:YY:YY:YY:YY:YY:YY:YY:YY:YY:YY:YY:YY"
	 *  * "user=USERNAME"
	 *  * "privkey=PRIVATEKEY" "PEM" format RSA key, with the header/footer/
	 *  *                      newlines stripped.
	 *  * "orport=XXXXX" Port on the remote peer's loopback interface that
	 *                   Tor is listening on (Temporary argument since once
	 *                   there's an actual server implementation it should
	 *                   handle that automatically).
	 */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress"
	btfromcstr(arg_str, args);
	arg_list = bsplit(&arg_str, ';');
	for (i = 0; i < arg_list->qty; i++) {
		if (0 == bstrncmp(&hkey_rsa_prefix, arg_list->entry[i],
					blength(&hkey_rsa_prefix))) {
			session->hostkey_rsa = bmidstr(arg_list->entry[i],
					blength(&hkey_rsa_prefix),
					blength(arg_list->entry[i]) -
					blength(&hkey_rsa_prefix));
		} else if (0 == bstrncmp(&hkey_dss_prefix, arg_list->entry[i],
					blength(&hkey_dss_prefix))) {
			session->hostkey_dss = bmidstr(arg_list->entry[i],
					blength(&hkey_dss_prefix),
					blength(arg_list->entry[i]) -
					blength(&hkey_dss_prefix));
		} else if (0 == bstrncmp(&user_prefix, arg_list->entry[i],
					blength(&user_prefix))) {
			session->user = bmidstr(arg_list->entry[i],
					blength(&user_prefix),
					blength(arg_list->entry[i]) -
					blength(&user_prefix));
		} else if (0 == bstrncmp(&privkey_prefix, arg_list->entry[i],
					blength(&privkey_prefix))) {
			tmp = bmidstr(arg_list->entry[i],
					blength(&privkey_prefix),
					blength(arg_list->entry[i]) -
					blength(&user_prefix));
			session->privkey_pem = ssh_arg_to_privkey(tmp);
			bdestroy(tmp);
		} else if (0 == bstrncmp(&orport_prefix, arg_list->entry[i],
					blength(&orport_prefix))) {
			tmp = bmidstr(arg_list->entry[i],
					blength(&orport_prefix),
					blength(arg_list->entry[i]) -
					blength(&orport_prefix));
#pragma GCC diagnostic ignored "-Wnonnull"
			session->orport = atoi(bdata(tmp));
			bdestroy(tmp);
		}
	}
#pragma GCC diagnostic pop

	bstrListDestroy(arg_list);

	if (NULL == session->hostkey_rsa && NULL == session->hostkey_dss)
		return -1;

	if (NULL == session->user || NULL == session->privkey_pem ||
			0 == session->orport)
		return -1;

	/* Generate libssh compatible keys from the PEM */
	session->privkey = read_rsa_private_key_from_memory(
			bdata(session->privkey_pem),
			blength(session->privkey_pem));
	if (NULL == session->privkey) {
		log_f(state, "SOCKS: Error: %s Unable to decode private key",
					bdata(session->socks_addr));
		return -1;
	}

	return 0;
}

static bstring
ssh_arg_to_privkey(const bstring argkey)
{
	struct tagbstring tmp;
	bstring privkey;
	int i, len;

	/*
	 * A simple routine to convert from the private key format suitable for
	 * inclusion in a Torrc back to PEM.
	 */

	len = strlen(OBFSPROXYSSH_PEM_HDR) + blength(argkey) +
		blength(argkey) /64 + 1 + strlen(OBFSPROXYSSH_PEM_FTR);

	privkey = bfromcstralloc(len, OBFSPROXYSSH_PEM_HDR);

	for (i = 0; i < blength(argkey); i += 64) {
		bmid2tbstr(tmp, argkey, i, 64);
		bconcat(privkey, &tmp);
		bconchar(privkey, '\n');
	}

	bcatcstr(privkey, OBFSPROXYSSH_PEM_FTR);

	return privkey;
}

static int
ssh_validate_hostkey(obfsproxyssh_client_session_t *session)
{
	obfsproxyssh_t *state = session->client->state;
	const char *hkey_method;
	bstring trusted_fp;
	const char *fp;
	bstring fp_s;
	int i, len, dlen;

	hkey_method = libssh2_session_methods(session->ssh_session,
			LIBSSH2_METHOD_HOSTKEY);

	if (0 == strcmp(hkey_method, "ssh-rsa"))
		trusted_fp = session->hostkey_rsa;
	else if (0 == strcmp(hkey_method, "ssh-dss"))
		trusted_fp = session->hostkey_dss;
	else {
		log_f(state, "SSH: Error: Supplied hostkey method is invalid (%s)",
				bdata(session->ssh_addr),
				hkey_method);
		return -1;
	}

	len = blength(trusted_fp);
	switch (len) {
	case OBFSPROXYSSH_CLIENT_MD5_FP_LEN:
		fp = libssh2_hostkey_hash(session->ssh_session,
				LIBSSH2_HOSTKEY_HASH_MD5);
		dlen = 16;
		break;
	case OBFSPROXYSSH_CLIENT_SHA1_FP_LEN:
		fp = libssh2_hostkey_hash(session->ssh_session,
				LIBSSH2_HOSTKEY_HASH_SHA1);
		dlen = 20;
		break;
	default:
		log_f(state, "SSH: Error: Supplied hostkey length is invalid (%s)",
				bdata(session->ssh_addr),
				bdata(trusted_fp));
		return -1;
	}

	fp_s = bfromcstralloc(len, "");
	for (i = 0; i < dlen; i++) {
		bformata(fp_s, "%02X", (unsigned char) fp[i]);
		if (i != dlen - 1)
			bconchar(fp_s, ':');
	}

	i = bstricmp(trusted_fp, fp_s);

	if (0 != i)
		log_f(state, "SSH: Error: %s Hostkey mismatch (Got: %s, Expecting: %s)",
				bdata(session->ssh_addr),
				bdata(trusted_fp),
				bdata(fp_s));
	else
		log_f(state, "SSH: %s Hostkey matched (%s)",
				bdata(session->ssh_addr),
				bdata(trusted_fp));

	return (0 == i) ? 0 : -1;
}


static void
ssh_event_cb(struct bufferevent *bev, short what, void *ptr)
{
	obfsproxyssh_client_session_t *session = ptr;

	assert(bev == session->ssh_ev);

	if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		libssh2_session_free(session->ssh_session);
		session->ssh_session = NULL;
		session_free(session);
	} else if (what & BEV_EVENT_CONNECTED) {
		/* Setup the read/write callbacks for libssh2 and bev */
		bufferevent_setcb(bev, ssh_read_cb, ssh_write_cb, ssh_event_cb,
			      session);
		bufferevent_enable(bev, EV_READ | EV_WRITE);
		session->ssh_is_valid = 1;
		session->libssh2_cb = ssh_handshake_cb;
	}
}

static void
ssh_read_cb(struct bufferevent *bev, void *ptr)
{
	obfsproxyssh_client_session_t *session = ptr;

	if (NULL != session->libssh2_cb)
		session->libssh2_cb(session);
}

static void
ssh_write_cb(struct bufferevent *bev, void *ptr)
{
	obfsproxyssh_client_session_t *session = ptr;

	if (NULL != session->libssh2_cb)
		session->libssh2_cb(session);
}

static void
ssh_handshake_cb(obfsproxyssh_client_session_t *session)
{
	int rval;
	evutil_socket_t fd = bufferevent_getfd(session->ssh_ev);

	rval = libssh2_session_handshake(session->ssh_session, fd);
	if (LIBSSH2_ERROR_EAGAIN == rval)
		return;
	else if (0 != rval || 0 != ssh_validate_hostkey(session)) {
		libssh2_session_free(session->ssh_session);
		session->ssh_session = NULL;
		session_free(session);
		return;
	}

	session->libssh2_cb = ssh_auth_cb;
	session->libssh2_cb(session);
}

static void
ssh_auth_cb(obfsproxyssh_client_session_t *session)
{
	obfsproxyssh_t *state = session->client->state;
	int rval;

	rval = libssh2_userauth_publickey(session->ssh_session,
			bdata(session->user),
			get_rsa_public_key(session->privkey),
			get_rsa_public_key_len(session->privkey),
			sign_with_private_key,
			&session->privkey);
	if (LIBSSH2_ERROR_EAGAIN == rval)
		return;
	else if (0 != rval) {
		log_f(state, "SSH: Error: %s Failed to authenticate - %d",
				bdata(session->ssh_addr), rval);
		libssh2_session_free(session->ssh_session);
		session->ssh_session = NULL;
		session_free(session);
		return;
	}

	session->libssh2_cb = ssh_channel_cb;
	session->libssh2_cb(session);
}

static void
ssh_channel_cb(obfsproxyssh_client_session_t *session)
{
	static const char socks_4_resp[] = {
		0x00,				/* VN */
		SOCKS_4_REQUEST_GRANTED,	/* CD */
		0x00, 0x00,			/* DSTPORT */
		0x00 ,0x00, 0x00, 0x00		/* DSTIP */
	};
	obfsproxyssh_t *state = session->client->state;

	session->ssh_channel =
		libssh2_channel_direct_tcpip(session->ssh_session,
				"127.0.0.1", session->orport);
	if (NULL == session->ssh_channel) {
		if (LIBSSH2_ERROR_EAGAIN ==
				libssh2_session_last_errno(session->ssh_session))
			return;
		else {
			log_f(state, "SSH: Error: %s Failed to initialize direct-tcp channel",
					bdata(session->ssh_addr));
			libssh2_session_free(session->ssh_session);
			session->ssh_session = NULL;
			session_free(session);
			return;
		}
	}

	/* Send the SOCKS 4 response */
	bufferevent_write(session->socks_ev, socks_4_resp,
			SOCKS_4_CONNECT_RESPONSE_LEN);

	/* Renable reading/writing on the buffer event */
	bufferevent_enable(session->socks_ev, EV_READ);
	bufferevent_setcb(session->socks_ev, socks_relay_cb, NULL,
			socks_event_cb, session);
	session->socks_is_valid = 1;

	/* Change the event callback to something that does channel cleanup */
	bufferevent_setcb(session->ssh_ev, ssh_read_cb, ssh_write_cb,
			ssh_relay_event_cb, session);

	session->libssh2_cb = ssh_relay_cb;
}

static void
ssh_relay_event_cb(struct bufferevent *bev, short what, void *ptr)
{
	obfsproxyssh_client_session_t *session = ptr;
	struct evbuffer *buf;

	assert(bev == session->ssh_ev);

	if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		session->ssh_is_valid = 0;
		libssh2_channel_free(session->ssh_channel);
		session->ssh_channel = NULL;
		libssh2_session_free(session->ssh_session);
		session->ssh_session = NULL;
		buf = bufferevent_get_output(session->socks_ev);
		if (0 == session->socks_is_valid || 0 ==
				evbuffer_get_length(buf))
			session_free(session);
		else {
			bufferevent_disable(session->socks_ev, EV_READ);
			bufferevent_setcb(session->socks_ev, NULL,
					socks_relay_teardown_cb,
					socks_event_cb, session);
		}
	}
}

static void
ssh_relay_cb(obfsproxyssh_client_session_t *session)
{
	obfsproxyssh_t *state = session->client->state;
	char *p;
	ssize_t rval;

	p = session->ssh_rx_buf;
	for (;;) {
		rval = libssh2_channel_read(session->ssh_channel, p,
					OBFSPROXYSSH_CLIENT_READ_SZ);
		if (LIBSSH2_ERROR_EAGAIN == rval || 0 == rval)
			break;
		else if (rval < 0) {
			log_f(state, "RELAY: Error: %s Channel read failed (%d)",
					bdata(session->ssh_addr), rval);
			ssh_relay_event_cb(session->ssh_ev, BEV_EVENT_ERROR, session);
			return;
		}

		bufferevent_write(session->socks_ev, p, rval);
		memset(p, 0, OBFSPROXYSSH_CLIENT_READ_SZ);
	}
}

static void
ssh_relay_teardown_cb(obfsproxyssh_client_session_t *session)
{
	struct evbuffer *buf;
	int rval;

	buf = bufferevent_get_input(session->socks_ev);
	if (1 == session->ssh_is_valid && 0 < evbuffer_get_length(buf)) {
		socks_relay_cb(session->socks_ev, session);
		return;
	}

	buf = bufferevent_get_output(session->ssh_ev);
	if (1 == session->ssh_is_valid && 0 < evbuffer_get_length(buf))
		return;

	if (NULL != session->ssh_channel) {
		rval = libssh2_channel_close(session->ssh_channel);
		if (LIBSSH2_ERROR_EAGAIN == rval)
			return;
		libssh2_channel_free(session->ssh_channel);
		session->ssh_channel = NULL;
	}

	if (1 == session->ssh_is_valid && 0 < evbuffer_get_length(buf))
		return;

	if (NULL != session->ssh_session) {
		rval = libssh2_session_disconnect(session->ssh_session,
				ssh_client_profile_get_disconnect_msg());
		if (LIBSSH2_ERROR_EAGAIN == rval)
			return;
		libssh2_session_free(session->ssh_session);
		session->ssh_session = NULL;
	}

	if (1 == session->ssh_is_valid && 0 < evbuffer_get_length(buf))
		return;

	session_free(session);
}

/* ssize_t libssh2_recv_cb(libssh2_socket_t socket, void *buffer, size_t length,
 *		int flags, void **abstract)
 */
static
LIBSSH2_RECV_FUNC(libssh2_recv_cb)
{
	obfsproxyssh_client_session_t *session = *abstract;
	struct evbuffer *buf;

	if (0 == session->ssh_is_valid)
		return -EBADFD;

	buf = bufferevent_get_input(session->ssh_ev);
	if (0 == evbuffer_get_length(buf))
		return -EAGAIN;

	return evbuffer_remove(buf, buffer, length);
}

/* ssize_t libssh2_recv_cb(libssh2_socket_t socket, void *buffer, size_t length,
 *		int flags, void **abstract)
 */
static
LIBSSH2_SEND_FUNC(libssh2_send_cb)
{
	obfsproxyssh_client_session_t *session = *abstract;
	int rval;

	if (0 == session->ssh_is_valid)
		return -EBADFD;

	rval = bufferevent_write(session->ssh_ev, buffer, length);

	return (rval == 0) ? length : -1;
}

#ifdef TRACE_LIBSSH2
static void
libssh2_trace_cb(LIBSSH2_SESSION *session, void *context, const char
	*data, size_t length)
{
	obfsproxyssh_t *state = context;

	log_f(state, "libssh2: %s", data);
}
#endif

static void
session_free(obfsproxyssh_client_session_t *session)
{
	obfsproxyssh_client_t *client = session->client;

	assert(NULL == session->ssh_session);
	assert(NULL == session->ssh_channel);

	bdestroy(session->hostkey_rsa);
	bdestroy(session->hostkey_dss);
	bdestroy(session->user);
	bdestroy(session->privkey_pem);
	free_rsa_private_key(session->privkey);

	if (NULL !=session->ssh_ev)
		bufferevent_free(session->ssh_ev);
	bufferevent_free(session->socks_ev);

	bdestroy(session->ssh_addr);
	bdestroy(session->socks_addr);

	LIST_REMOVE(session, entries);
	free(session);

	/*
	 * Assuming that we are shutting down, ensure that we break out of the
	 * event loop if this is the last session.  (Not needed?)
	 */
	if (NULL == client->listener && LIST_EMPTY(&client->sessions))
		event_base_loopbreak(client->state->base);
}

static int
ssh_client_profile_init(obfsproxyssh_client_t *client)
{
	obfsproxyssh_t *state = client->state;
	LIBSSH2_SESSION *session;
	struct bstrList *pmethods;
	const char **methods;
	bstring s;
	int i, j, k, found, rval;

	/*
	 * Determine the OS and select a "likely" fingerprint.
	 *
	 * Note:
	 * Every single asshat out there that compiles OpenSSH seems to end up
	 * tacking on additional information as the banner comment (Eg:
	 * SSH-2.0-OpenSSH_6.1p1 Debian-4)
	 *
	 * Picking the "right" OpenSSH is tricky because of this, and opens up
	 * the potential for an active attacker to attempt to probe the client
	 * and see if the ssh version running matches what we claim to be.
	 *
	 * In theory we *COULD* just claim to be PuTTY since every single OS
	 * that we vaguely care about can run PuTTY, but no one that's in their
	 * right mind would use it for ssh on OSX or U*IX.
	 *
	 * That said, it's plausible that real OSes (and OSX) can be running NAT
	 * for a Windows box, so acting like Putty for now is probably fine.
	 */

	/* NOTYET */
/*	ssh_client_profile_current = &ssh_client_profile_putty; */
	ssh_client_profile_current = &ssh_client_profile_putty_insecure;
#if 0
	if (ssh_client_profile_current == &ssh_client_profile_putty)
		return 0;
#endif

	/*
	 * So, libssh2 doesn't like to actually return anything that resembles
	 * an error code when it is asked to use unsupported algorithms.
	 *
	 * Instead it tries to ignore unsupported algorithms and only returns
	 * an error from libssh2_session_method_pref when there are no
	 * algorithms at all that are supported.
	 *
	 * Since it's vital that our behavior matches the emulated real client
	 * exactly, ensure that all the algorithms in a given profile are
	 * actually supported by libssh2.
	 *
	 * There's no way to get the algorithms that will be sent in a KEX
	 * without reaching into libssh2 internals either, so this is the best
	 * that can be done).
	 *
	 * On failure should I fail hard, or continue as a "generic libssh2
	 * application"?
	 */

	session = libssh2_session_init();
	if (NULL == session) {
		log_f(state, "SSH: Error: Failed to make temporary libssh2 session");
		return -1;
	}

	libssh2_session_flag(session, LIBSSH2_FLAG_COMPRESS,
			ssh_client_profile_current->enable_compression);

	for (i = 0; i <= LIBSSH2_METHOD_LANG_SC; i++) {
		if (NULL == ssh_client_profile_current->kex_methods[i])
			continue;

		s = bfromcstr(ssh_client_profile_current->kex_methods[i]);
		pmethods = bsplit(s,',');
		bdestroy(s);
		if (NULL == pmethods) {
			log_f(state, "SSH: Error: Out of memory verifying libssh2 settings");
			libssh2_session_free(session);
			return -1;
		}

		methods = NULL;
		rval = libssh2_session_supported_algs(session, i, &methods);
		if (0 > rval) {
			log_f(state, "SSH: Error: Out of memory verifying libssh2 settings");
out_free:
			if (NULL != methods)
				libssh2_free(session, methods);
			bstrListDestroy(pmethods);
			libssh2_session_free(session);
			return -1;
		}

		/* This is slow, but at least it's only done once */
		for (j = 0; j < pmethods->qty; j++) {
			found = 0;
			for (k = 0; k < rval; k++) {
				if (1 == biseqcstr(pmethods->entry[j],
							methods[k])) {
					found = 1;
					break;
				}
			}

			if (0 == found) {
				log_f(state, "SSH: Error: Unsupported Algorithm: [%d]: %s",
						i, bdata(pmethods->entry[j]));
				goto out_free;
			}
		}

		bstrListDestroy(pmethods);
		if (NULL != methods)
			libssh2_free(session, methods);
	}

	libssh2_session_free(session);

	return 0;
}

static int
ssh_client_profile_set(obfsproxyssh_client_session_t *session)
{
	obfsproxyssh_t *state = session->client->state;
	const obfsproxyssh_client_profile_t *profile = ssh_client_profile_current;
	int i, rval;

	assert(NULL != profile);

	rval = libssh2_banner_set(session->ssh_session, profile->banner);
	if (0 != rval) {
		log_f(state, "SSH: Error: %s Failed to set banner %d",
				bdata(session->ssh_addr), rval);
	}

	libssh2_session_flag(session->ssh_session, LIBSSH2_FLAG_COMPRESS,
			profile->enable_compression);

	/*
	 * Failure to set things to exactly what I specify should be a
	 * immediate and fatal error as the lists in the profiles are chosen
	 * carefully to match existing client(s) in the wild, but see the
	 * comments in ssh_client_profile_init().
	 */

	for (i = 0; i <= LIBSSH2_METHOD_LANG_SC; i++) {
		/* Trying to force a value to NULL, causes libssh2 to SIGSEGV */
		if (NULL == profile->kex_methods[i])
			continue;

		rval = libssh2_session_method_pref(session->ssh_session, i,
				profile->kex_methods[i]);
		if (0 != rval) {
			log_f(state, "SSH: Error: %s Failed to set prefered methods %d (%d)",
					bdata(session->ssh_addr), i, rval);
			return -1;
		}
	}

	return 0;
}

static const char *
ssh_client_profile_get_disconnect_msg(void)
{
	assert(NULL != ssh_client_profile_current);

	return ssh_client_profile_current->disconnect_msg;
}

