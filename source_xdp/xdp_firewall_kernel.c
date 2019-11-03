/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "common_kern_user.h" /* defines: struct datarec; */
#include "../common/parsing_helpers.h"


struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};

struct bpf_map_def SEC("maps") xdp_filter_ipv4 = {
	.type 		 = BPF_MAP_TYPE_HASH,
	.key_size 	 = sizeof(__be32),
	.value_size  = sizeof(IP4_FILTER_MASK),
	.max_entries = MAX_IP4_FILTER_SIZE,
};

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

static __always_inline
__u32 xdp_stats_record_action(__u64 bytes, __u32 action)
{
	if (action >= XDP_ACTION_MAX)
		return XDP_ABORTED;

	__be32 k = 213;
	bpf_map_update_elem(&xdp_filter_ipv4, &k, &action, BPF_ANY);


	/* Lookup in kernel BPF-side return pointer to actual data record */
	struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
	if (!rec)
		return XDP_ABORTED;

	/* BPF_MAP_TYPE_PERCPU_ARRAY returns a data record specific to current
	 * CPU and XDP hooks runs under Softirq, which makes it safe to update
	 * without atomic operations.
	 */
	rec->rx_packets++;
	rec->rx_bytes += bytes;

	return action;
}

SEC("firewall-action")
int firewall_action(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;

	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		// pas avery ipv6 packet for now
		action = XDP_PASS;
		// struct ipv6hdr *ip6h;
		// struct icmp6hdr *icmp6h;

		// nh_type = parse_ip6hdr(&nh, data_end, &ip6h);
		// if (nh_type != IPPROTO_ICMPV6)
		// 	goto out;

		// nh_type = parse_icmp6hdr(&nh, data_end, &icmp6h);
		// if (nh_type != ICMPV6_ECHO_REQUEST)
		// 	goto out;

		// if (bpf_ntohs(icmp6h->icmp6_sequence) % 2 == 0)
		// 	action = XDP_DROP;

	} else if (nh_type == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph;
		//struct icmphdr *icmph;

		nh_type = parse_iphdr(&nh, data_end, &iph);
		
		if (nh_type == -1) {
			action = XDP_ABORTED;
			goto out;
		}

		if (iph + 1 > data_end) {
			action = XDP_DROP;
			goto out;
		}

		// check if we have a rule for this source or destination
		__be32 s_key = iph->saddr, d_key = iph->daddr;
		IP4_FILTER_MASK *s_verdict = bpf_map_lookup_elem(&xdp_filter_ipv4, &s_key);
		IP4_FILTER_MASK *d_verdict = bpf_map_lookup_elem(&xdp_filter_ipv4, &d_key);

		IP4_FILTER_MASK verdict = 0;

		// if one of our verdicts is drop, set action acordingly
		if (NULL != s_verdict && (*s_verdict == IP4_ABORT || *s_verdict == IP4_DROP)) {
			action = XDP_DROP;
			__be32 k = 32;
			bpf_map_update_elem(&xdp_filter_ipv4, &k, &verdict, BPF_ANY);
			goto out;
		}

		if (NULL != d_verdict && (*d_verdict == IP4_ABORT || *d_verdict == IP4_DROP)) {
			action = XDP_DROP;
			__be32 k = 32;
			bpf_map_update_elem(&xdp_filter_ipv4, &k, &verdict, BPF_ANY);
			goto out;
		}

		// if (nh_type != IPPROTO_ICMP)
		// 	goto out;

		// nh_type = parse_icmphdr(&nh, data_end, &icmph);
		// if (nh_type != ICMP_ECHO)
		// 	goto out;

		// if (bpf_ntohs(icmph->un.echo.sequence) % 2 == 0)
		// 	action = XDP_DROP;
	}
 out:
	return xdp_stats_record_action(data_end - data, action);
}


char _license[] SEC("license") = "GPL";
