/*
 * libssh2_helpers.c: Things that libssh2 should contain
 * Yawning Angel <yawning at schwanenlied.me>
 */

/*
 * Most of the code here is cribbed from src/openssl.c since that's where
 * this functionality should belong in the first place.
 *
 * Additional inspiration was taken from:
 * [PATCH] userauth: Allow authentication keys to be passed in memory
 *   by Joe Turpin <joe.turpin at gmail.com>
 *
 * http://www.libssh2.org/mail/libssh2-devel-archive-2012-03/0135.shtml
 *
 * This effort would have been saved if the libssh2 maintainers actually merged
 * said patch, since it's cleaner than doing it like this (most of this is
 * re-implementing things already implemented in libssh2).
 *
 * Corresponding libssh2 (including the patch) routines are noted in comments
 * where appropriate.
 */

/*
 * Copyright (C) 2009, 2010 Simon Josefsson
 * Copyright (C) 2006, 2007 The Written Word, Inc.  All rights reserved.
 * Copyright (c) 2004-2006, Sara Golemon <sarag@libssh2.org>
 *
 * Author: Simon Josefsson
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libssh2_helpers.h"

/* This doesn't actually need to be exposed */
struct privkey_ctxt {
	RSA *rsa;
	unsigned char *pub_key;
	size_t pub_key_len;
};

/* Deal with Apple brain damage */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

/* Expose tasty libssh2 internals */
void _libssh2_htonu32(unsigned char *buf, uint32_t val);
int _libssh2_rsa_sha1_sign(LIBSSH2_SESSION * session,
		RSA * rsactx,
		const unsigned char *hash,
		size_t hash_len,
		unsigned char **signature,
		size_t *signature_len);

/* src/openssl.c: write_bn */
static unsigned char *
write_bn(unsigned char *buf, const BIGNUM *bn, int bn_bytes)
{
	unsigned char *p = buf;

	/* Left space for bn size which will be written below. */
	p += 4;

	*p = 0;
	BN_bn2bin(bn, p + 1);
	if (!(*(p + 1) & 0x80)) {
		memmove(p, p + 1, --bn_bytes);
	}
	_libssh2_htonu32(p - 4, bn_bytes);	/* Post write bn size. */

	return p + bn_bytes;
}

void *
read_rsa_private_key_from_memory(char *buf, size_t len)
{
	struct privkey_ctxt *ctxt;
	BIO *bp;
	unsigned char *p;
	int e_bytes, n_bytes;

	ctxt = malloc(sizeof(struct privkey_ctxt));
	if (NULL == ctxt)
		return NULL;

	/* src/openssl.c: _libssh2_pub_priv_keyfilefrommemory */

	bp = BIO_new_mem_buf(buf, len);
	if (NULL == bp) {
out_free:
		free(ctxt);
		return NULL;
	}

	if (!EVP_get_cipherbyname("des")) {
		/* If this cipher isn't loaded it's a pretty good indication
		 * that none are.  I have *NO DOUBT* that there's a better way
		 * to deal with this ($#&%#$(%$#( Someone buy me an OpenSSL
		 * manual and I'll read up on it.
		 */
		OpenSSL_add_all_ciphers();
	}

	(void) BIO_reset(bp);
	ctxt->rsa = PEM_read_bio_RSAPrivateKey(bp, NULL, NULL, NULL);
	BIO_free(bp);

	if (NULL == ctxt->rsa)
		goto out_free;

	/*
	 * Ok, private key obtained, generate the public key so that libssh2
	 * can transmit it to the remote peer.  It's not actually used for
	 * anything else so just stash it in a buffer somewhere.
	 *
	 * src/openssl.c: gen_publickey_from_rsa
	 */

	e_bytes = BN_num_bytes(ctxt->rsa->e) + 1;
	n_bytes = BN_num_bytes(ctxt->rsa->n) + 1;

	/* Key form is "ssh-rsa" + e + n. */
	ctxt->pub_key_len = 4 + 7 + 4 + e_bytes + 4 + n_bytes;

	ctxt->pub_key = malloc(ctxt->pub_key_len);
	if (NULL == ctxt->pub_key) {
		RSA_free(ctxt->rsa);
		goto out_free;
	}

	p = ctxt->pub_key;

	_libssh2_htonu32(p, 7);  /* Key type. */
	p += 4;
	memcpy(p, "ssh-rsa", 7);
	p += 7;

	p = write_bn(p, ctxt->rsa->e, e_bytes);
	p = write_bn(p, ctxt->rsa->n, n_bytes);

	ctxt->pub_key_len = p - ctxt->pub_key;

	return ctxt;
}

void
free_rsa_private_key(void *handle)
{
	struct privkey_ctxt *ctxt = handle;

	if (NULL != handle) {
		RSA_free(ctxt->rsa);
		free(ctxt);
	}
}

unsigned char *
get_rsa_public_key(void *handle)
{
	return ((struct privkey_ctxt *) handle)->pub_key;
}

size_t
get_rsa_public_key_len(void *handle)
{
	return ((struct privkey_ctxt *) handle)->pub_key_len;
}

/* int (LIBSSH2_SESSION *session, unsigned char **sig, size_t *sig_len,
 *		const unsigned char *data, size_t data_len, void **abstract)
 */
LIBSSH2_USERAUTH_PUBLICKEY_SIGN_FUNC(sign_with_private_key)
{
	struct privkey_ctxt *ctxt = *abstract;
	unsigned char hash[SHA_DIGEST_LENGTH];

	SHA1(data, data_len, hash);

	return _libssh2_rsa_sha1_sign(session, ctxt->rsa, hash,
			SHA_DIGEST_LENGTH, sig, sig_len);
}

