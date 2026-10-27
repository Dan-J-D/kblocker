/*
 * Pure parsing and formatting helpers with no kernel state, built both
 * into the module and into a userspace library for property tests
 * (tests/proptest).
 */
#ifndef _KBLOCKER_PARSE_H
#define _KBLOCKER_PARSE_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef uint8_t u8;
typedef uint64_t u64;
#endif

#define MAX_DOMAIN_LEN 256
#define HOSTS_MARKER "# kblocker managed entries - do not edit manually"

/* Copy the ClientHello's server_name into @out (NUL-terminated). @data
 * holds @len bytes starting at a TLS record. Returns the name length,
 * or 0 if there is no well-formed server_name. */
int kb_sni_extract(const u8 *data, int len, char *out, int outlen);

/* @host (first @hlen bytes) equals @blocked or is a subdomain of it */
bool kb_domain_matches(const char *host, size_t hlen, const char *blocked);

/* Normalize a domain in place; returns its start or NULL if invalid */
char *kb_normalize_domain(char *d);

int kb_hex_decode(const char *s, u8 *out, int count);

/* Value of the last complete "remaining:N\n" line in @s, or 0 */
u64 kb_last_remaining(const char *s);

/* Length of the hosts file in @buf without the kblocker block and
 * trailing newlines; bytes before it are the user's own */
size_t kb_hosts_base_len(const char *buf, size_t len);

/* Exact size of the kblocker hosts block for @nd domains stored every
 * @stride bytes in @doms, and the formatter that writes it (no NUL).
 * kb_hosts_format() writes at most @size bytes and returns the length. */
size_t kb_hosts_block_size(const char *doms, int nd, size_t stride);
size_t kb_hosts_format(const char *doms, int nd, size_t stride,
		       char *out, size_t size);

#endif
