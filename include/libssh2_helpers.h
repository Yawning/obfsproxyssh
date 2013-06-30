/*
 * libssh2_helpers.h: Implement missing libssh2 functionality
 * Yawning Angel <yawning at schwanenlied dot me>
 */

#include "libssh2.h"

#ifndef _LIBSSH2_HELPERS_H_
#define _LIBSSH2_HELPERS_H_

void		*read_rsa_private_key_from_memory(char *buf, size_t len);
void	 	 free_rsa_private_key(void *handle);
unsigned char	*get_rsa_public_key(void *handle);
size_t		 get_rsa_public_key_len(void *handle);

LIBSSH2_USERAUTH_PUBLICKEY_SIGN_FUNC(sign_with_private_key);

#endif
