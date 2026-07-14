#include <linux/kernel.h>
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
#include <linux/version.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include "kblocker.h"

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
static bool is_ipv6_blocked(struct in6_addr *addr)
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

static bool domain_list_contains(const char *hostname)
{
	int i;
	bool found = false;

	spin_lock_bh(&ip_list_lock);
	if (!blocked_domain_count)
		goto out;
	for (i = 0; i < blocked_domain_count; i++) {
		const char *blocked = blocked_domains[i];
		int blen = strlen(blocked);
		const char *p = hostname;
		while (*p) {
			if (strncasecmp(p, blocked, blen) == 0) {
				found = true;
				goto out;
			}
			p++;
		}
	}
out:
	spin_unlock_bh(&ip_list_lock);
	return found;
}

static bool sni_matches_blocked(const struct sk_buff *skb, struct tcphdr *tcph)
{
	int thlen = tcph->doff * 4;
	const u8 *data;
	int data_len, offset;

	data = (u8 *)tcph + thlen;
	data_len = skb->len - (int)((u8 *)tcph - skb->data) - thlen;

	if (data_len < 6)
		return false;
	if (data[0] != 0x16) {
		return false;
	}
	if (data[5] != 0x01) {
		return false;
	}

	offset = 5 + 4;
	if (offset + 34 > data_len)
		return false;
	offset += 2;
	offset += 32;

	if (offset + 1 > data_len)
		return false;
	offset += 1 + data[offset];

	if (offset + 2 > data_len)
		return false;
	offset += 2 + (data[offset] << 8 | data[offset + 1]);

	if (offset + 1 > data_len)
		return false;
	offset += 1 + data[offset];

	if (offset + 2 > data_len)
		return false;
	{
		int ext_total = (data[offset] << 8) | data[offset + 1];
		offset += 2;

		while (offset + 4 <= data_len && ext_total > 0) {
			int ext_type = (data[offset] << 8) | data[offset + 1];
			int ext_len = (data[offset + 2] << 8) | data[offset + 3];
			offset += 4;
			ext_total -= 4;

			if (ext_type == 0xFE0A) {
				return true;
			}
			if (ext_type == 0x0000) {
				if (offset + 3 > data_len)
					return false;
				offset += 2;
				if (data[offset] != 0x00)
					return false;
				offset += 1;
				if (offset + 2 > data_len)
					return false;
				int name_len = (data[offset] << 8) | data[offset + 1];
				offset += 2;

				if (name_len > 0 && offset + name_len <= data_len) {
					char sni_buf[MAX_DOMAIN_LEN];
					int copy_len = min(name_len, (int)sizeof(sni_buf) - 1);
					memcpy(sni_buf, data + offset, copy_len);
					sni_buf[copy_len] = '\0';
					return domain_list_contains(sni_buf);
				}
				return false;
			}
			offset += ext_len;
			ext_total -= ext_len;
		}
	}
	return false;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
unsigned int kblocker_hook(void *priv, struct sk_buff *skb,
				     const struct nf_hook_state *state)
#else
unsigned int kblocker_hook(unsigned int hooknum, struct sk_buff *skb,
				     const struct net_device *in, const struct net_device *out,
				     int (*okfn)(struct sk_buff *))
#endif
{
	if (!READ_ONCE(enabled)) return NF_ACCEPT;
	if (!skb) return NF_ACCEPT;

	if (state->pf == NFPROTO_IPV4)
		return kblocker_hook_v4(priv, skb, state);
#if IS_ENABLED(CONFIG_IPV6)
	if (state->pf == NFPROTO_IPV6)
		return kblocker_hook_v6(priv, skb, state);
#endif
	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
unsigned int kblocker_hook_v4(void *priv, struct sk_buff *skb,
				    const struct nf_hook_state *state)
#else
unsigned int kblocker_hook_v4(unsigned int hooknum, struct sk_buff *skb,
				    const struct net_device *in, const struct net_device *out,
				    int (*okfn)(struct sk_buff *))
#endif
{
	struct iphdr *iph;
	struct tcphdr *tcph;

	if (READ_ONCE(blocked_count_v4)) {
		if (!pskb_may_pull(skb, sizeof(struct iphdr)))
			return NF_ACCEPT;
		iph = ip_hdr(skb);
		if (!iph) return NF_ACCEPT;
		if (is_ip_blocked(iph->daddr))
			return NF_DROP;
	}

	if (READ_ONCE(blocked_domain_count)) {
		if (!pskb_may_pull(skb, sizeof(struct iphdr)))
			return NF_ACCEPT;
		iph = ip_hdr(skb);
		if (!iph) return NF_ACCEPT;
		if (iph->protocol == IPPROTO_UDP) {
			int ip_hdr_len = iph->ihl * 4;
			if (pskb_may_pull(skb, ip_hdr_len + sizeof(struct udphdr))) {
				iph = ip_hdr(skb);
				struct udphdr *udph = (void *)iph + ip_hdr_len;
				if (udph->dest == htons(443))
					return NF_DROP;
			}
			return NF_ACCEPT;
		}
		if (iph->protocol != IPPROTO_TCP)
			return NF_ACCEPT;
		int ip_hdr_len = iph->ihl * 4;
		if (!pskb_may_pull(skb, ip_hdr_len + sizeof(struct tcphdr)))
			return NF_ACCEPT;
		iph = ip_hdr(skb);
		tcph = (void *)iph + ip_hdr_len;
		if (tcph->syn || !tcph->ack || tcph->rst)
			return NF_ACCEPT;
		int tcp_data_off = ip_hdr_len + (tcph->doff * 4);
		int sni_pull = tcp_data_off + 512;
		if (sni_pull > skb->len)
			sni_pull = skb->len;
		if (!pskb_may_pull(skb, sni_pull))
			return NF_ACCEPT;
		iph = ip_hdr(skb);
		tcph = (void *)iph + ip_hdr_len;
		if (sni_matches_blocked(skb, tcph))
			return NF_DROP;
	}

	return NF_ACCEPT;
}

#if IS_ENABLED(CONFIG_IPV6)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
unsigned int kblocker_hook_v6(void *priv, struct sk_buff *skb,
				    const struct nf_hook_state *state)
#else
unsigned int kblocker_hook_v6(unsigned int hooknum, struct sk_buff *skb,
				    const struct net_device *in, const struct net_device *out,
				    int (*okfn)(struct sk_buff *))
#endif
{
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;

	if (!READ_ONCE(enabled)) return NF_ACCEPT;

	if (READ_ONCE(blocked_count_v6)) {
		if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
			return NF_ACCEPT;
		ip6h = ipv6_hdr(skb);
		if (!ip6h) return NF_ACCEPT;
		if (is_ipv6_blocked(&ip6h->daddr))
			return NF_DROP;
	}

	if (READ_ONCE(blocked_domain_count)) {
		if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
			return NF_ACCEPT;
		ip6h = ipv6_hdr(skb);
		if (!ip6h) return NF_ACCEPT;

		u8 nexthdr = ip6h->nexthdr;
		int hdr_offset = sizeof(struct ipv6hdr);

		if (nexthdr == IPPROTO_UDP) {
			if (pskb_may_pull(skb, hdr_offset + sizeof(struct udphdr))) {
				struct udphdr *udph = (struct udphdr *)((u8 *)ipv6_hdr(skb) + hdr_offset);
				if (udph->dest == htons(443))
					return NF_DROP;
			}
			return NF_ACCEPT;
		}
		if (nexthdr != IPPROTO_TCP)
			return NF_ACCEPT;
		if (!pskb_may_pull(skb, hdr_offset + sizeof(struct tcphdr)))
			return NF_ACCEPT;
		ip6h = ipv6_hdr(skb);
		tcph = (struct tcphdr *)((u8 *)ip6h + hdr_offset);
		if (tcph->syn || !tcph->ack || tcph->rst)
			return NF_ACCEPT;
		int tcp_data_off = hdr_offset + (tcph->doff * 4);
		int sni_pull = tcp_data_off + 512;
		if (sni_pull > skb->len)
			sni_pull = skb->len;
		if (!pskb_may_pull(skb, sni_pull))
			return NF_ACCEPT;
		ip6h = ipv6_hdr(skb);
		tcph = (struct tcphdr *)((u8 *)ip6h + hdr_offset);
		if (sni_matches_blocked(skb, tcph))
			return NF_DROP;
	}

	return NF_ACCEPT;
}
#endif

void log_blocklist_on_disable(void)
{
	int i;

	if (READ_ONCE(blocked_count_v4)) {
		spin_lock_bh(&ip_list_lock);
		printk(KERN_DEBUG "kblocker: blocked IPv4 on disable:");
		for (i = 0; i < blocked_count_v4; i++)
			printk(KERN_DEBUG "kblocker:   %pI4", &blocked_ips_v4[i]);
		spin_unlock_bh(&ip_list_lock);
	}

	if (READ_ONCE(blocked_count_v6)) {
		spin_lock_bh(&ip_list_lock);
		printk(KERN_DEBUG "kblocker: blocked IPv6 on disable:");
		for (i = 0; i < blocked_count_v6; i++)
			printk(KERN_DEBUG "kblocker:   %pI6", &blocked_ips_v6[i]);
		spin_unlock_bh(&ip_list_lock);
	}

	if (READ_ONCE(blocked_domain_count)) {
		spin_lock_bh(&ip_list_lock);
		printk(KERN_DEBUG "kblocker: blocked domains on disable:");
		for (i = 0; i < blocked_domain_count; i++)
			printk(KERN_DEBUG "kblocker:   %s", blocked_domains[i]);
		spin_unlock_bh(&ip_list_lock);
	}
}

void kblocker_cleanup_netfilter(void)
{
	if (forward_registered) {
		nf_unregister_net_hook(&init_net, &nfho_forward);
		forward_registered = false;
	}
	if (ipv4_registered) {
		nf_unregister_net_hook(&init_net, &nfho_out);
		ipv4_registered = false;
	}
}