// SPDX-License-Identifier: GPL-2.0
/*
 * Pure helpers shared by the module and the userspace property tests.
 * Only functions available both in the kernel and in libc are used here.
 * Character classes are spelled out because the kernel's <linux/ctype.h>
 * treats Latin-1 bytes as letters and libc's does not.
 */
#ifdef __KERNEL__
#include <linux/kernel.h>
#include <linux/string.h>
#else
#include <string.h>
#endif
#include "parse.h"

#define TLS_EXT_SERVER_NAME 0x0000

static bool kb_isspace(char c)
{
	return c == ' ' || (c >= '\t' && c <= '\r');
}

static bool kb_isdigit(char c)
{
	return c >= '0' && c <= '9';
}

static char kb_tolower(char c)
{
	return c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c;
}

static bool kb_domain_char(char c)
{
	c = kb_tolower(c);
	return (c >= 'a' && c <= 'z') || kb_isdigit(c) ||
	       c == '-' || c == '.' || c == '_';
}

static int get_u16(const u8 *p)
{
	return (p[0] << 8) | p[1];
}

/*
 * Encrypted Client Hello (0xfe0d) is not treated specially: its outer
 * server_name (the provider's public name) is what gets extracted, since
 * browsers also send GREASE ECH extensions on ordinary connections.
 */
int kb_sni_extract(const u8 *data, int len, char *out, int outlen)
{
	int off, end, ext_end;

	if (len < 9 || data[0] != 0x16 || data[5] != 0x01)
		return 0;

	/* record(5) + handshake type(1) + length(3) + version(2) + random(32) */
	off = 5 + 4 + 2 + 32;
	if (off + 1 > len)
		return 0;
	off += 1 + data[off];			/* session id */
	if (off + 2 > len)
		return 0;
	off += 2 + get_u16(data + off);		/* cipher suites */
	if (off + 1 > len)
		return 0;
	off += 1 + data[off];			/* compression methods */
	if (off + 2 > len)
		return 0;
	ext_end = off + 2 + get_u16(data + off);
	off += 2;
	end = len < ext_end ? len : ext_end;

	while (off + 4 <= end) {
		int type = get_u16(data + off);
		int ext_len = get_u16(data + off + 2);

		off += 4;
		if (off + ext_len > end)
			return 0;

		if (type == TLS_EXT_SERVER_NAME) {
			/* list length(2), name type(1), name length(2) */
			int name_len;

			if (ext_len < 5 || data[off + 2] != 0x00)
				return 0;
			name_len = get_u16(data + off + 3);
			if (name_len <= 0 || name_len >= outlen ||
			    5 + name_len > ext_len)
				return 0;
			memcpy(out, data + off + 5, name_len);
			out[name_len] = '\0';
			return name_len;
		}
		off += ext_len;
	}
	return 0;
}

bool kb_domain_matches(const char *host, size_t hlen, const char *blocked)
{
	size_t blen = strlen(blocked), i;

	if (!blen || hlen < blen)
		return false;
	for (i = 0; i < blen; i++)
		if (kb_tolower(host[hlen - blen + i]) != kb_tolower(blocked[i]))
			return false;
	return hlen == blen || host[hlen - blen - 1] == '.';
}

char *kb_normalize_domain(char *d)
{
	size_t len;
	char *p;

	while (kb_isspace(*d))
		d++;
	len = strlen(d);
	while (len && kb_isspace(d[len - 1]))
		d[--len] = '\0';
	if (!strncmp(d, "*.", 2)) {
		d += 2;
		len -= 2;
	}
	while (*d == '.') {
		d++;
		len--;
	}
	while (len && d[len - 1] == '.')
		d[--len] = '\0';
	if (!len || len >= MAX_DOMAIN_LEN)
		return NULL;
	/* No separators used by the state file or hosts file */
	for (p = d; *p; p++) {
		if (!kb_domain_char(*p))
			return NULL;
		*p = kb_tolower(*p);
	}
	return d;
}

static int hex_val(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	return -1;
}

int kb_hex_decode(const char *s, u8 *out, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		int hi = hex_val(s[i * 2]);
		int lo = hi < 0 ? -1 : hex_val(s[i * 2 + 1]);

		if (hi < 0 || lo < 0)
			return -1;
		out[i] = (hi << 4) | lo;
	}
	return 0;
}

/* Parse a decimal terminated by '\n'; digits only, no overflow */
static bool parse_line_u64(const char *p, u64 *val)
{
	u64 v = 0;

	if (!kb_isdigit(*p))
		return false;
	for (; kb_isdigit(*p); p++) {
		unsigned int d = *p - '0';

		if (v > (~0ULL - d) / 10)
			return false;
		v = v * 10 + d;
	}
	if (*p != '\n')
		return false;
	*val = v;
	return true;
}

u64 kb_last_remaining(const char *s)
{
	const char *p = s, *hit;
	u64 val = 0, v;

	while ((hit = strstr(p, "remaining:"))) {
		p = hit + 10;
		if (hit != s && hit[-1] != '\n')
			continue;
		if (parse_line_u64(p, &v))
			val = v;
	}
	return val;
}

size_t kb_hosts_base_len(const char *buf, size_t len)
{
	const char *p = strstr(buf, HOSTS_MARKER);

	if (p && (size_t)(p - buf) < len)
		len = p - buf;
	while (len > 0 && buf[len - 1] == '\n')
		len--;
	return len;
}

/* Per domain: "0.0.0.0 d\n" ":: d\n" "0.0.0.0 www.d\n" ":: www.d\n" */
#define HOSTS_LINES_FIXED (8 + 1 + 3 + 1 + 12 + 1 + 7 + 1)

size_t kb_hosts_block_size(const char *doms, int nd, size_t stride)
{
	size_t size = 2 + strlen(HOSTS_MARKER) + 1 + 1;
	int i;

	for (i = 0; i < nd; i++)
		size += 4 * strnlen(doms + i * stride, stride) + HOSTS_LINES_FIXED;
	return size;
}

struct out_buf {
	char *p;
	size_t len, size;
};

static void put(struct out_buf *o, const char *s, size_t n)
{
	if (n > o->size - o->len)
		n = o->size - o->len;
	memcpy(o->p + o->len, s, n);
	o->len += n;
}

size_t kb_hosts_format(const char *doms, int nd, size_t stride,
		       char *out, size_t size)
{
	struct out_buf o = { out, 0, size };
	int i;

	put(&o, "\n\n", 2);
	put(&o, HOSTS_MARKER, strlen(HOSTS_MARKER));
	put(&o, "\n", 1);
	for (i = 0; i < nd; i++) {
		const char *d = doms + i * stride;
		size_t n = strnlen(d, stride);

		put(&o, "0.0.0.0 ", 8);
		put(&o, d, n);
		put(&o, "\n:: ", 4);
		put(&o, d, n);
		put(&o, "\n0.0.0.0 www.", 13);
		put(&o, d, n);
		put(&o, "\n:: www.", 8);
		put(&o, d, n);
		put(&o, "\n", 1);
	}
	put(&o, "\n", 1);
	return o.len;
}
