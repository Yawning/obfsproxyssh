/*
 * obfsproxyssh.h: Global state for obfsproxy-ssh
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

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/util.h>

#include "bstrlib.h"
#include "queue.h"
#include "tor_pt.h"

#ifndef _OBFSPROXYSSH_H_
#define _OBFSPROXYSSH_H_

#define OBFSPROXYSSH_METHOD		"ssh"
#define OBFSPROXYSSH_LOG		"obfsproxyssh.log"
#define OBFSPROXYSSH_LOG_LEN		128

#define OBFSPROXYSSH_SHUTDOWN_LISTENER	0
#define OBFSPROXYSSH_SHUTDOWN_SESSIONS	1
#define OBFSPROXYSSH_SHUTDOWN_FINAL	2

typedef struct obfsproxyssh obfsproxyssh_t;

struct obfsproxyssh {
	tor_pt_config_t *pt_config;
	int is_exiting;

	struct event_base *base;
	struct event *sigint_ev;

	FILE *log;
	bstring log_buf;

	/* Command line options */
	volatile int wait_for_debugger;
	int unsafe_logging;
	const char *default_client_args;

	void *ctxt;
	void (*shutdown_fn)(obfsproxyssh_t *, int);
};

void	log_f(obfsproxyssh_t *state, const char *fmt, ...);

#endif
