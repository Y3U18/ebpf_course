#!/usr/bin/env python

# // SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# /* Copyright (c) 2023 fei_cong(https://github.com/feicong/ebpf-course) */
from bcc import BPF
from ctypes import *

prog="""
BPF_PROG_ARRAY(prog_array, 10);
int world_func(void *ctx) {
  bpf_trace_printk("world\\n");
  return 0;
}

int hello_func(void *ctx) {
  bpf_trace_printk("hello\\n");
  prog_array.call(ctx, 3);
  bpf_trace_printk("never called.\\n");
  return 0;
}
"""
b = BPF(text=prog)
tail_func = b.load_func("world_func", BPF.KPROBE)
prog_array = b.get_table("prog_array")
prog_array[c_int(3)] = c_int(tail_func.fd)
b.attach_kprobe(event="__arm64_sys_clone", fn_name="hello_func")
b.trace_print()
