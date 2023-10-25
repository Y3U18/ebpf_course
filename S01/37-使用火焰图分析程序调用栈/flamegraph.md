git clone https://github.com/brendangregg/FlameGraph
sudo perf record -F 99 -a -g -- sleep 20
perf script > out.perf
sudo perf record -F 99 -p 2959 -g -- sleep 20
perf script > out.perf
sudo perf script > out.perf
FlameGraph/stackcollapse-perf.pl out.perf
FlameGraph/stackcollapse-perf.pl out.perf > out.folded
FlameGraph/flamegraph.pl out.folded
FlameGraph/flamegraph.pl out.folded > out.svg

sudo bpftrace -e 'profile:hz:99 {@[kstack]=count();}' > stack.data
FlameGraph/stackcollapse-bpftrace.pl stack.data > stack.data.folded
FlameGraph/flamegraph.pl < stack.data.folded > stack.svg

sudo python3 bcc/tools/stackcount.py -K t:sched:sched_switch
sudo python3 bcc/tools/offcputime.py -f 30 > out.offcpustacks01
sudo python3 bcc/tools/offcputime.py -uf > out.offcpustacks02
FlameGraph/flamegraph.pl --color=io --countname=us --width=900 \
    --title="Off-CPU Time Flame Graph: idle system" < out.offcpustacks02 > offcpu2.svg
