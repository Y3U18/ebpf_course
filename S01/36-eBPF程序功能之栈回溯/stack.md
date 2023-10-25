sudo ./trace.py  'c:open "%s %d", arg1, arg2' -U --address -v

sudo bpftrace -e 'uprobe:/lib/x86_64-linux-gnu/libc.so.6:close {printf("%s",ustack)}' -c /bin/ls
sudo bpftrace -e 'kprobe:__x64_sys_openat {printf("%s",kstack)}' -c /bin/ls
sudo bpftrace -e 'profile:hz:99 {@[kstack]=count();}'