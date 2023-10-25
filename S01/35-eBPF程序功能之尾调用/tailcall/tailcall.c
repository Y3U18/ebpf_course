// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023 fei_cong(https://github.com/feicong/ebpf-course) */
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <sys/resource.h>
#include <linux/if_link.h>
#include <linux/limits.h>
#include <linux/unistd.h>

#include <bpf/libbpf.h>
#include "tailcall.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool stop = false;

static void sig_handler(int sig)
{
	stop = true;
}

int main(int argc, char **argv)
{
	struct tailcall_bpf *skel;
	int err;

	libbpf_set_print(libbpf_print_fn);

	// Load and verify BPF application
	skel = tailcall_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	// Load and verify BPF programs
	err = tailcall_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	struct bpf_program *prog = bpf_object__find_program_by_name(skel->obj, "world_func");
	if (!prog) {
		fprintf(stderr, "Error: bpf_object__find_program_by_name failed\n");
		return 1;
	}
	bpf_program__set_type(prog, BPF_PROG_TYPE_KPROBE);
    int prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "Error: Couldn't get file descriptor for program.\n");
		return 1;
	}

	// update tailcall maps fd
	unsigned int map_prog_idx = 3;
	err = bpf_map__update_elem(skel->maps.progs, &map_prog_idx, sizeof(map_prog_idx), &prog_fd, sizeof(prog_fd), BPF_ANY);
	if (err) {
		fprintf(stderr, "Error: bpf_map__update_elem failed for prog array map\n");
		return 1;
	}

	// attach do_unlinkat prog only
	struct bpf_link* link = bpf_program__attach(skel->progs.hello_func);
	if (link == NULL) {
		fprintf(stderr, "Error: bpf_program__attach failed\n");
		return 1;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	fprintf(stderr, "Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	while (!stop) {
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	bpf_link__destroy(link);
	tailcall_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
