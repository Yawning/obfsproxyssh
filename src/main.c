/*
 * main.c: The glue that ties everything together
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

#include <errno.h>
#include <signal.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>

#include "obfsproxyssh.h"
#include "obfsproxyssh_client.h"

static int	parse_args(obfsproxyssh_t *state, const int argc,
	char * const argv[]);

static int	log_init(obfsproxyssh_t *state);
static void	log_libevent_cb(int severity, const char *msg);
static void	log_shutdown(obfsproxyssh_t *state);

static void	sigint_cb(evutil_socket_t fd, short event, void *arg);
static void	mask_sigpipe(void);

/* Sadly libevent's logging callback doesn't take a context */
static obfsproxyssh_t *global_state;

int
main(const int argc, char * const argv[])
{
	struct tagbstring ssh_method = bsStatic(OBFSPROXYSSH_METHOD);
	obfsproxyssh_t *state;
	int rval = 1;

	state = calloc(1, sizeof(obfsproxyssh_t));
	if (NULL == state) {
		fprintf(stdout, "ENV-ERROR Failed to allocate initial state\n");
		goto out;
	}
	global_state = state;

	if (parse_args(state, argc, argv)) {
		fprintf(stdout, "ENV-ERROR Invalid command line arguments\n");
		goto cleanup_state;
	}

	/* Handle the Tor Pluggable Transport configuration */

	state->pt_config = tor_pt_get_config();
	if (tor_pt_check_config(state->pt_config, &ssh_method))
		goto cleanup_pt;

	/* Initialize the log */

	if (log_init(state))
		goto cleanup_pt;

	log_f(state, "obfsproxyssh: Initialized (PID: %d)", getpid());
	if (1 == state->wait_for_debugger) {
		log_f(state, "obfsproxyssh: Waiting for debugger....");
		while (1 == state->wait_for_debugger)
			sleep(0);
	}

	/* Initialize libevent and related things */

	event_set_log_callback(log_libevent_cb);
	state->base = event_base_new();
	state->sigint_ev = evsignal_new(state->base, SIGINT, sigint_cb, state);
	event_add(state->sigint_ev, NULL);
	mask_sigpipe();

	/* Initialize the client or server */

	if (state->pt_config->is_client) {
		rval = obfsproxyssh_client_init(state);
		tor_pt_on_client_done();
	} else {
		rval = 1; /* TODO: Initialize the server, when we have one */
		tor_pt_on_server_done();
	}
	if (0 != rval)
		goto cleanup_log;

	fflush(stdout);

	/* Run the event loop */

	event_base_dispatch(state->base);

	/*
	 * Clean shutdown
	 *
	 * Note:
	 * If Tor sends us more than 2 SIGINTs, we will end up here as well
	 * possibly with incomplete teardown.  It doesn't matter since our
	 * code is going to exit anyway.
	 */

	state->shutdown_fn(state, OBFSPROXYSSH_SHUTDOWN_FINAL);
	rval = 0;

	log_f(state, "obfsproxyssh: Shutting down");

cleanup_log:
	event_base_free(state->base);
	log_shutdown(state);
	global_state = NULL;
cleanup_pt:
	tor_pt_free_config(state->pt_config);
cleanup_state:
	free(state);
out:
	return rval; 
}

static int
parse_args(obfsproxyssh_t *state, const int argc,
	char * const argv[])
{
	int opt;

	while (-1 != (opt = getopt(argc, argv, "Udc:"))) {
		switch (opt) {
		case 'U':
			state->unsafe_logging = 1;
			break;
		case 'd':
			state->wait_for_debugger = 1;
			break;
		case 'c':
			state->default_client_args = optarg;
			break;
		default:
			/* TODO: Provide usage */
			return -1;
		}
	}

	return 0;
}

void
log_f(obfsproxyssh_t *state, const char *fmt, ...)
{
	int rval;

	/* XXX: This is rather heavyweight. */

	if (state->log >=0) {
		time_t t;
		struct tm *tm;
		char date_str[64];

		t = time(NULL);
		tm = localtime(&t);
		strftime(date_str, sizeof(date_str), "%F %T", tm);

		bassigncstr(state->log_buf, date_str);
		bconchar(state->log_buf, ' ');
		bvformata(rval, state->log_buf, fmt, fmt);
		if (BSTR_OK == rval && BSTR_OK == bconchar(state->log_buf, '\n'))
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnonnull"
			fputs(bdata(state->log_buf), state->log);
#pragma GCC diagnostic pop
		fflush(state->log);
	}
}

static int
log_init(obfsproxyssh_t *state)
{
	struct tagbstring log_file = bsStatic(OBFSPROXYSSH_LOG);
	bstring log_path;
	int rval = -1;

	if (NULL == state->pt_config->state_location) {
		state->log = NULL;
		return 0;
	}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnonnull"
	rval = mkdir(bdata(state->pt_config->state_location), 0700);
#pragma GCC diagnostic pop
	if (0 != rval && errno != EEXIST) {
		fprintf(stderr, "Failed to create log directory (%d)\n", errno);
		return -1;
	}

	/* XXX: Create the state_location path if required */

	state->log_buf = bfromcstralloc(OBFSPROXYSSH_LOG_LEN, "");
	log_path = bstrcpy(state->pt_config->state_location);
	if (NULL == state->log_buf || NULL == log_path || 
			BSTR_ERR == bconcat(log_path, &log_file)) {
		fprintf(stderr, "Out of memory when initializing logging\n");
		goto out;
	}

	state->log = fopen(bdata(log_path), "a+");
	if (NULL == state->log) {
		fprintf(stderr, "Failed to open log %s (%d)\n",
				bdata(log_path), errno);
		goto out;
	}

	rval = 0;

out:
	bdestroy(log_path);
	return rval;
}

static void
log_libevent_cb(int severity, const char *msg)
{
	if (NULL == global_state)
		return;
	log_f(global_state, "libevent: %d: %s", severity, msg);
}

static void
log_shutdown(obfsproxyssh_t *state)
{
	if (NULL != state->log) {
		fclose(state->log);
		bdestroy(state->log_buf);

		state->log = NULL;
		state->log_buf = NULL;
	}
}

static void
mask_sigpipe(void)
{
	struct sigaction sa;

	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;

	sigaction(SIGPIPE, &sa, 0);
}

static void
sigint_cb(evutil_socket_t fd, short event, void *arg)
{
	obfsproxyssh_t *state = arg;
	state->is_exiting++;

	switch (state->is_exiting) {
	case 1:
		/*
		 * Notify the client/server that they should stop accepting new
		 * connections and terminate once existing sessions have
		 * finished.
		 */
		state->shutdown_fn(state, OBFSPROXYSSH_SHUTDOWN_LISTENER);
		break;
	case 2:
		/*
		 * Notify the client/server that they should close all existing
		 * sessions.
		 */
		state->shutdown_fn(state, OBFSPROXYSSH_SHUTDOWN_SESSIONS);
		event_del(state->sigint_ev);
		break;
	default:
		/*
		 * This should *NEVER* happen because we deregister the signal
		 * handler on the second SIGINT, but handling the case doesn't
		 * hurt anything.
		 */
		event_base_loopbreak(state->base);
		break;
	}
}
