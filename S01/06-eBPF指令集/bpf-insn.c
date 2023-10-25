// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023 fei_cong(https://github.com/feicong/ebpf-course) */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <linux/version.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
// #include <bpf/bpf.h>
#include <bcc/libbpf.h>

// clang bpf-insn.c -o bpf-insn -lbcc -lbpf
#define BPF_LOG_BUF_SIZE (UINT32_MAX >> 8) /* verifier maximum in kernels <= 5.1 */
char bpf_log_buf[BPF_LOG_BUF_SIZE];

int wait_for_sig_int()
{
    sigset_t set;
    sigemptyset(&set);
    int rc = sigaddset(&set, SIGINT);
    if (rc < 0)
    {
        perror("Error calling sigaddset()");
        return 1;
    }

    rc = sigprocmask(SIG_BLOCK, &set, NULL);
    if (rc < 0)
    {
        perror("Error calling sigprocmask()");
        return 1;
    }

    int sig;
    rc = sigwait(&set, &sig);
    if (rc < 0)
    {
        perror("Error calling sigwait()");
        return 1;
    }
    else if (sig == SIGINT)
    {
        fprintf(stderr, "SIGINT received!\n");
        return 0;
    }
    else
    {
        fprintf(stderr, "Unexpected signal received: %d\n", sig);
        return 0;
    }
}

int main(int argc, char **argv) {
    unsigned char prog[] = {
        0xb7, 0x01, 0x00, 0x00, 0x21, 0x0a, 0x00, 0x00, 0x6b, 0x1a, 0xfc, 0xff, 0x00, 0x00, 0x00, 0x00, 0xb7, 0x01, 0x00, 0x00, 0x6f, 0x72, 0x6c, 0x64, 0x63, 0x1a, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00, 0xb7, 0x01, 0x00, 0x00, 0x6f, 0x2c, 0x20, 0x57, 0x63, 0x1a, 0xf4, 0xff, 0x00, 0x00, 0x00, 0x00, 0xb7, 0x01, 0x00, 0x00, 0x48, 0x65, 0x6c, 0x6c, 0x63, 0x1a, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x73, 0x1a, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0xbf, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x01, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0xb7, 0x02, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x85, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    int insn_cnt = sizeof(prog) / sizeof(struct bpf_insn);
    printf("insn_cnt: %d\n", insn_cnt);

    // 经测试，最新版本bcc的bpf_load_program接口无法使用，改用bcc_prog_load加载
    int prog_fd = bcc_prog_load(BPF_PROG_TYPE_KPROBE, NULL, (const struct bpf_insn *)&prog, sizeof(prog), "GPL", LINUX_VERSION_CODE, 1, bpf_log_buf, BPF_LOG_BUF_SIZE);
    if (prog_fd < 0)
    {
        printf("ERROR: failed to load prog '%s'\n", strerror(errno));
        return 1;
    }

    int perf_event_fd = bpf_attach_kprobe(prog_fd, BPF_PROBE_ENTRY, "kprobe__hello", "do_unlinkat", 0, 0);
    if (perf_event_fd < 0)
    {
        perror("Error calling attach_kprobe()");
        close(prog_fd);
        return 1;
    }

    system("cat /sys/kernel/debug/tracing/trace_pipe");
    int exit_code = wait_for_sig_int();
    close(perf_event_fd);
    close(prog_fd);
    bpf_detach_kprobe("kprobe__hello");

    return exit_code;
}
