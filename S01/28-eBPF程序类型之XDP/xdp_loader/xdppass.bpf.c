#ifdef BCC_SEC
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#else
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#endif

// clang -O2 -Wall -target bpf -c xdppass.bpf.c -o xdppass.o
// export DEV=enp0s5
// sudo ip link set dev $DEV xdp off
// sudo ip link show dev $DEV
// sudo ip link set dev $DEV xdp obj xdppass.o sec xdp
// sudo bpftool net list dev $DEV

#ifdef BCC_SEC
#else
char __license[] SEC("license") = "GPL";

SEC("xdp")
#endif
int xdp_pass(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int pkt_sz = data_end - data;

	bpf_trace_printk("packet size: %d", sizeof("packet size: %d"), pkt_sz);
	return XDP_PASS;
}

