// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#include <test_progs.h>
#include <unistd.h>
#include "syscall.skel.h"

struct args {
	__u64 log_buf;
	__u32 log_size;
	int max_entries;
	int map_fd;
	int prog_fd;
	int btf_fd;
};

void test_syscall(void)
{
	static char verifier_log[8192];
	struct args ctx = {
		.max_entries = 1024,
		.log_buf = (uintptr_t) verifier_log,
		.log_size = sizeof(verifier_log),
	};
	struct bpf_prog_test_run_attr tattr = {
		.ctx_in = &ctx,
		.ctx_size_in = sizeof(ctx),
	};
	struct syscall *skel = syscall__open_and_load();
	if (!skel) {
        printf("skel_load error\n");
		goto cleanup;
    }
	tattr.prog_fd = bpf_program__fd(skel->progs.bpf_prog);
	int err = bpf_prog_test_run_xattr(&tattr);

    /* use libbpf v1.0 API bpf_prog_test_run_opts insteadof bpf_prog_test_run_xattr
	struct bpf_test_run_opts opts = {
		.ctx_in = &ctx,
		.ctx_size_in = sizeof(ctx),
	};
	int prog_fd = bpf_program__fd(skel->progs.bpf_prog);
    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    */

    if (err != 0) {
        printf("err error\n");
    }
    if (tattr.retval != 1) {
        printf("retval error\n");
    }
    if (ctx.map_fd < 0) {
        printf("ctx.map_fd error\n");
    }
    if (ctx.prog_fd < 0) {
        printf("ctx.prog_fd error\n");
    }
    printf("map_fd:%d, prog_fd:%d\n", ctx.map_fd, ctx.prog_fd);

	__u64 key = 12, value = 0;
	err = bpf_map_lookup_elem(ctx.map_fd, &key, &value);
    if (err != 0) {
        printf("map_lookup error\n");
    }
    if (value != 34) {
        printf("map lookup value error\n");
    }
cleanup:
	syscall__destroy(skel);
	if (ctx.prog_fd > 0)
		close(ctx.prog_fd);
	if (ctx.map_fd > 0)
		close(ctx.map_fd);
	if (ctx.btf_fd > 0)
		close(ctx.btf_fd);

    printf("ebpf syscall test done\n");
}

int main() {
	test_syscall();
    // sleep(6);
    return 0;
}