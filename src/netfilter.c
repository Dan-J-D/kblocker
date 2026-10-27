#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <net/ip.h>
#include <net/net_namespace.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include "kblocker.h"

/* TLS record header (5) + maximum plaintext record (16 KiB) */
#define TLS_MAX_RECORD (5 + 16384)

/* [0] LOCAL_OUT, [1] FORWARD; filled in by kblocker_register_netfilter().
 * Must be static: netfilter keeps pointers to the registered ops. */
static struct nf_hook_ops kb_ops[2];
static bool out_registered;
static bool forward_registered;

/*
 * By default only the initial network namespace is filtered; traffic from
 * other namespaces reaches the host through FORWARD. Fuzzers such as
 * syzkaller run every test process in a fresh namespace, so they set this
 * to reach the packet parsers. It then filters every namespace except the
 * initial one: syz-executor talks to the fuzzer over loopback there, and a
 * fuzzed blocked_ips entry such as 127.0.0.1 would cut that connection.
 */
static bool hook_all_netns;
module_param(hook_all_netns, bool, 0444);
MODULE_PARM_DESC(hook_all_netns,
		 "Filter traffic in every network namespace but the initial one (for fuzzing)");
static bool pernet_registered;

static bool is_ip_blocked(__be32 addr)
{
	int i;
	bool found = false;

	spin_lock_bh(&ip_list_lock);
	for (i = 0; i < blocked_count_v4; i++) {
		if (blocked_ips_v4[i] == addr) {
			found = true;
			break;
		}
	}
	spin_unlock_bh(&ip_list_lock);

	return found;
}

#if IS_ENABLED(CONFIG_IPV6)
static bool is_ipv6_blocked(const struct in6_addr *addr)
{
	int i;
	bool found = false;

	spin_lock_bh(&ip_list_lock);
	for (i = 0; i < blocked_count_v6; i++) {
		if (ipv6_addr_equal(&blocked_ips_v6[i], addr)) {
			found = true;
			break;
		}
	}
	spin_unlock_bh(&ip_list_lock);

	return found;
}
#endif

/* kb_domain_matches(): x.com blocks www.x.com but not netflix.com */
static bool domain_list_contains(const char *hostname)
{
	size_t hlen = strlen(hostname);
	bool found = false;
	int i;

	while (hlen && hostname[hlen - 1] == '.')
		hlen--;

	spin_lock_bh(&ip_list_lock);
	for (i = 0; i < blocked_domain_count && !found; i++)
		found = kb_domain_matches(hostname, hlen, blocked_domains[i]);
	spin_unlock_bh(&ip_list_lock);
	return found;
}

/* @data holds @len bytes starting at a TLS handshake record */
static bool sni_matches_blocked(const u8 *data, int len)
{
	char sni[MAX_DOMAIN_LEN];

	return kb_sni_extract(data, len, sni, sizeof(sni)) &&
	       domain_list_contains(sni);
}

/* @thoff is the offset of the TCP header within @skb */
static unsigned int inspect_tcp(struct sk_buff *skb, unsigned int thoff)
{
	struct tcphdr _th;
	const struct tcphdr *th;
	u8 _hdr[6];
	const u8 *hdr;
	unsigned int doff, copy;
	u8 *buf;
	bool match;

	th = skb_header_pointer(skb, thoff, sizeof(_th), &_th);
	if (!th || th->rst || th->doff < 5)
		return NF_ACCEPT;

	/* Includes SYN packets: TCP Fast Open carries data in the SYN */
	doff = thoff + th->doff * 4;
	if (doff >= skb->len)
		return NF_ACCEPT;

	hdr = skb_header_pointer(skb, doff, sizeof(_hdr), _hdr);
	if (!hdr || hdr[0] != 0x16 || hdr[5] != 0x01)
		return NF_ACCEPT;

	/* Copy the ClientHello out of the (possibly paged) skb, bounded by
	 * what is actually present. */
	copy = min_t(unsigned int, skb->len - doff, 5 + ((hdr[3] << 8) | hdr[4]));
	copy = min_t(unsigned int, copy, TLS_MAX_RECORD);
	buf = kmalloc(copy, GFP_ATOMIC);
	if (!buf)
		return NF_ACCEPT;
	if (skb_copy_bits(skb, doff, buf, copy)) {
		kfree(buf);
		return NF_ACCEPT;
	}
	match = sni_matches_blocked(buf, copy);
	kfree(buf);
	return match ? NF_DROP : NF_ACCEPT;
}

/* QUIC carries its ClientHello encrypted, so while domains are blocked all
 * UDP/443 is dropped and browsers fall back to TCP, where SNI is visible. */
static unsigned int inspect_udp(struct sk_buff *skb, unsigned int thoff)
{
	struct udphdr _uh;
	const struct udphdr *uh;

	uh = skb_header_pointer(skb, thoff, sizeof(_uh), &_uh);
	if (uh && uh->dest == htons(443))
		return NF_DROP;
	return NF_ACCEPT;
}

static unsigned int kblocker_hook_v4(struct sk_buff *skb)
{
	struct iphdr _iph;
	const struct iphdr *iph;
	unsigned int noff = skb_network_offset(skb), thoff;

	iph = skb_header_pointer(skb, noff, sizeof(_iph), &_iph);
	if (!iph || iph->ihl < 5)
		return NF_ACCEPT;

	if (READ_ONCE(blocked_count_v4) && is_ip_blocked(iph->daddr))
		return NF_DROP;

	if (!READ_ONCE(blocked_domain_count))
		return NF_ACCEPT;
	/* Non-first fragments carry no transport header */
	if (iph->frag_off & htons(IP_OFFSET))
		return NF_ACCEPT;

	thoff = noff + iph->ihl * 4;
	if (iph->protocol == IPPROTO_TCP)
		return inspect_tcp(skb, thoff);
	if (iph->protocol == IPPROTO_UDP)
		return inspect_udp(skb, thoff);
	return NF_ACCEPT;
}

#if IS_ENABLED(CONFIG_IPV6)
static unsigned int kblocker_hook_v6(struct sk_buff *skb)
{
	struct ipv6hdr _ip6h;
	const struct ipv6hdr *ip6h;
	unsigned int noff = skb_network_offset(skb);
	__be16 frag_off;
	u8 nexthdr;
	int thoff;

	ip6h = skb_header_pointer(skb, noff, sizeof(_ip6h), &_ip6h);
	if (!ip6h)
		return NF_ACCEPT;

	if (READ_ONCE(blocked_count_v6) && is_ipv6_blocked(&ip6h->daddr))
		return NF_DROP;

	if (!READ_ONCE(blocked_domain_count))
		return NF_ACCEPT;

	/* Walk extension headers to the transport header */
	nexthdr = ip6h->nexthdr;
	thoff = ipv6_skip_exthdr(skb, noff + sizeof(*ip6h), &nexthdr, &frag_off);
	if (thoff < 0 || (frag_off & htons(~0x7)))
		return NF_ACCEPT;

	if (nexthdr == IPPROTO_TCP)
		return inspect_tcp(skb, thoff);
	if (nexthdr == IPPROTO_UDP)
		return inspect_udp(skb, thoff);
	return NF_ACCEPT;
}
#endif

static unsigned int kblocker_hook(void *priv, struct sk_buff *skb,
				  const struct nf_hook_state *state)
{
	if (!READ_ONCE(enabled) || !skb)
		return NF_ACCEPT;

	if (state->pf == NFPROTO_IPV4)
		return kblocker_hook_v4(skb);
#if IS_ENABLED(CONFIG_IPV6)
	if (state->pf == NFPROTO_IPV6)
		return kblocker_hook_v6(skb);
#endif
	return NF_ACCEPT;
}

void log_blocklist_on_disable(void)
{
	int i;

	spin_lock_bh(&ip_list_lock);
	if (blocked_count_v4) {
		printk(KERN_DEBUG "kblocker: blocked IPv4 on disable:");
		for (i = 0; i < blocked_count_v4; i++)
			printk(KERN_DEBUG "kblocker:   %pI4", &blocked_ips_v4[i]);
	}
	if (blocked_count_v6) {
		printk(KERN_DEBUG "kblocker: blocked IPv6 on disable:");
		for (i = 0; i < blocked_count_v6; i++)
			printk(KERN_DEBUG "kblocker:   %pI6", &blocked_ips_v6[i]);
	}
	if (blocked_domain_count) {
		printk(KERN_DEBUG "kblocker: blocked domains on disable:");
		for (i = 0; i < blocked_domain_count; i++)
			printk(KERN_DEBUG "kblocker:   %s", blocked_domains[i]);
	}
	spin_unlock_bh(&ip_list_lock);
}

static int __net_init kb_net_init(struct net *net)
{
	if (net_eq(net, &init_net))
		return 0;
	return nf_register_net_hooks(net, kb_ops, ARRAY_SIZE(kb_ops));
}

static void __net_exit kb_net_exit(struct net *net)
{
	if (net_eq(net, &init_net))
		return;
	nf_unregister_net_hooks(net, kb_ops, ARRAY_SIZE(kb_ops));
}

static struct pernet_operations kb_net_ops = {
	.init = kb_net_init,
	.exit = kb_net_exit,
};

int kblocker_register_netfilter(void)
{
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(kb_ops); i++) {
		kb_ops[i].hook = kblocker_hook;
		kb_ops[i].pf = NFPROTO_INET;
		kb_ops[i].priority = NF_IP_PRI_FILTER;
	}
	kb_ops[0].hooknum = NF_INET_LOCAL_OUT;
	kb_ops[1].hooknum = NF_INET_FORWARD;

	if (hook_all_netns) {
		/* Every namespace except init_net, see hook_all_netns */
		ret = register_pernet_subsys(&kb_net_ops);
		if (ret)
			return ret;
		pernet_registered = true;
		return 0;
	}

	ret = nf_register_net_hook(&init_net, &kb_ops[0]);
	if (ret) {
		printk(KERN_ERR "kblocker: failed to register LOCAL_OUT hook\n");
		return ret;
	}
	out_registered = true;

	if (nf_register_net_hook(&init_net, &kb_ops[1]))
		printk(KERN_WARNING "kblocker: FORWARD hook failed (non-fatal)\n");
	else
		forward_registered = true;
	return 0;
}

void kblocker_cleanup_netfilter(void)
{
	if (pernet_registered) {
		unregister_pernet_subsys(&kb_net_ops);
		pernet_registered = false;
	}
	if (forward_registered) {
		nf_unregister_net_hook(&init_net, &kb_ops[1]);
		forward_registered = false;
	}
	if (out_registered) {
		nf_unregister_net_hook(&init_net, &kb_ops[0]);
		out_registered = false;
	}
}
