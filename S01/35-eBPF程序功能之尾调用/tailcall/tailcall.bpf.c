// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023 fei_cong(https://github.com/feicong/ebpf-course) */
#include "vmlinux.h"
#include <linux/unistd.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, u32);
} progs SEC(".maps");


SEC("kprobe/do_unlinkat")
int BPF_KPROBE(hello_func, int dfd, struct filename *name) {
	pid_t pid;
	const char *filename;

	pid = bpf_get_current_pid_tgid() >> 32;
	filename = BPF_CORE_READ(name, name);
	bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);

  	bpf_printk("hello\n");
  	bpf_tail_call(ctx, &progs, 3);
  	bpf_printk("never called.\n");

  	return 0;
}

SEC("kprobe/world")
int world_func(void *ctx) {
  	bpf_printk("world\n");

  	return 0;
}
