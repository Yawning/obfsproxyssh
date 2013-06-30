/*
 * socks4.h: SOCKS 4 related defintions
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

#ifndef _SOCKS4_H_
#define _SOCKS4_H_

#define SOCKS_4_VER				0x04

#define SOCKS_4_CMD_CONNECT			0x01
#define SOCKS_4_CMD_BIND			0x02

#define SOCKS_4_REQUEST_GRANTED			0x5a
#define SOCKS_4_REQUEST_FAILED			0x5b
#define SOCKS_4_REQUEST_FAILED_NO_IDENTD	0x5c
#define SOCKS_4_REQUEST_FAILED_BAD_IDENTD	0x5d

#define SOCKS_4_CONNECT_REQUEST_LEN		8
#define SOCKS_4_CONNECT_RESPONSE_LEN		8

#endif
