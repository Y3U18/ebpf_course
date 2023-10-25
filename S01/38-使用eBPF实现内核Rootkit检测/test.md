
sudo bpftrace -e 'kprobe:__x64_sys_getdents64 {printf("%s",kstack)}' -c /bin/ls
