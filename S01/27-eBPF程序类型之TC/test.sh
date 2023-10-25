# // SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# /* Copyright (c) 2023 fei_cong(https://github.com/feicong/ebpf-course) */
# compile ebpf
clang -O2 -Wall -target bpf -c drop-icmp.c -o drop-icmp.o

export IFACE=enp7s0
# add a tc classifier
sudo tc qdisc add dev $IFACE clsact
# load and attach program
sudo tc filter add dev $IFACE ingress bpf da obj drop-icmp.o sec ingress
# check the filter we've added just now
sudo tc filter show dev $IFACE ingress

# do test
timeout 5s ping  -n 1 cn.bing.com

# clean up
sudo tc qdisc del dev $IFACE clsact
sudo tc filter show dev $IFACE ingress

echo done.
