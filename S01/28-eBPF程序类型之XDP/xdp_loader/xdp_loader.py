#!/usr/bin/python3

from bcc import BPF
import time

device = "lo"
b = BPF(src_file="xdppass.bpf.c")
fn = b.load_func("xdp_pass", BPF.XDP)
b.attach_xdp(device, fn, 0)

prev = [0] * 256
print("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");
while 1:
    try:
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break

b.remove_xdp(device, 0)