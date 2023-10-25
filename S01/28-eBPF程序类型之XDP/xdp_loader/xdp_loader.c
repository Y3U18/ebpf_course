/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP prog loader\n";

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/types.h>
#include <stdbool.h>

#include <net/if.h>
#include <linux/if_link.h> /* XDP_FLAGS_* depend on kernel-headers installed */
#include <linux/if_xdp.h>

// clang xdp_loader.c -o xdp_loader -lbpf -lelf -lz -static

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

struct config {
	__u32 xdp_flags;
	int ifindex;
	char *ifname;
	char ifname_buf[IF_NAMESIZE];
	int redirect_ifindex;
	char *redirect_ifname;
	char redirect_ifname_buf[IF_NAMESIZE];
	bool do_unload;
	bool reuse_maps;
	char pin_dir[512];
	char filename[512];
	char progsec[32];
	char src_mac[18];
	char dest_mac[18];
	__u16 xsk_bind_flags;
	int xsk_if_queue;
	bool xsk_poll_mode;
};


/* Exit return codes */
#define EXIT_OK 		 0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL		 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION	 2
#define EXIT_FAIL_XDP		30
#define EXIT_FAIL_BPF		40

int load_bpf_object_file__simple(const char *filename) {
    struct bpf_object *obj = bpf_object__open_file(filename, NULL);
    int err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "ERR: open BPF-OBJ file(%s) (%d): %s\n",
			filename, err, strerror(-err));
		return -1;
	}
    err = bpf_object__load(obj);
    if (err) {
		fprintf(stderr, "ERR: load BPF-OBJ file(%s) (%d): %s\n",
			filename, err, strerror(-err));
		return -1;
	}
	int prog_fd = bpf_program__fd(bpf_object__next_program(obj, NULL));

	return prog_fd;
}

int main(int argc, char **argv) {
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	char filename[256] = "xdppass.o";
	int prog_fd, err;

    const char *ifname = "lo";
	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
		.ifindex   = if_nametoindex(ifname),
		.do_unload = false,
	};

    // skb mode
    cfg.xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
    cfg.xdp_flags |= XDP_FLAGS_SKB_MODE;  /* Set   flag */
    cfg.xsk_bind_flags &= XDP_ZEROCOPY;
    cfg.xsk_bind_flags |= XDP_COPY;

	/* Load the BPF-ELF object file and get back first BPF_prog FD */
	prog_fd = load_bpf_object_file__simple(filename);
	if (prog_fd <= 0) {
		fprintf(stderr, "ERR: loading file: %s\n", filename);
		return EXIT_FAIL_BPF;
	}

	err = bpf_xdp_attach(cfg.ifindex, prog_fd, cfg.xdp_flags, NULL);
	if (err)
		return err;

    /* This step is not really needed , BPF-info via bpf-syscall */
	err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: can't get prog info - %s\n",
			strerror(errno));
		return err;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Success: Loading "
	       "XDP prog name:%s(id:%d) on device:%s(ifindex:%d)\n",
	       info.name, info.id, cfg.ifname, cfg.ifindex);
    
    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	while (!exiting) {
		fprintf(stderr, ".");
		sleep(1);
	}

	err = bpf_xdp_detach(cfg.ifindex, cfg.xdp_flags, NULL);
    if (err) {
		fprintf(stderr, "Failed to detach XDP: %d\n", err);
		goto cleanup;
	}

cleanup:
    fprintf(stderr, "XDP loader exit.\n");

	return EXIT_OK;
}