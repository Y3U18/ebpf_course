# eBPF开发环境准备

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023 fei_cong(https://github.com/feicong/ebpf-course) */

## 系统准备

```
# Upgrade all packages to newest.
sudo apt update -y && sudo apt upgrade -y

# Change apt mirror，这一步根据自己的网络情况，可以不改
sudo cp /etc/apt/sources.list /etc/apt/sources.list.bak
sudo apt update && sudo apt install apt-utils gnupg ca-certificates apt-transport-https software-properties-common wget -y
# https://mirrors.tuna.tsinghua.edu.cn/help/ubuntu/
x86_64:
sudo sed -i "s@http://.*archive.ubuntu.com@https://mirrors.tuna.tsinghua.edu.cn@g" /etc/apt/sources.list
sudo sed -i "s@http://.*security.ubuntu.com@https://mirrors.tuna.tsinghua.edu.cn@g" /etc/apt/sources.list
or arm64:
sudo sed -i "s@http://.*ports.ubuntu.com@https://mirrors.tuna.tsinghua.edu.cn@g" /etc/apt/sources.list
sudo apt update -y && sudo apt upgrade -y

# Install apt-utils to make apt run more smoothly
DEBIAN_FRONTEND="noninteractive" sudo apt-get install -y apt-utils python3 python3-pip python2

# Setup pip mirror
```
mkdir ~/.pip
touch ~/.pip/pip.conf
echo -e '\n[install]\ntrusted-host=pypi.douban.com\n[global]\nindex-url=http://pypi.douban.com/simple' > ~/.pip/pip.conf
cat ~/.pip/pip.conf
pip install -U pip
```
或者使用下面的方法更简单：
```
pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
pip install -U pip
pip install pytest
```

# Install docker
sudo apt-get install docker.io -y
sudo gpasswd -a ${USER} docker
newgrp - docker
sudo service docker restart

# 安装最新版本的Golang

```
export GOV=1.20.4
wget https://go.dev/dl/go${GOV}.linux-amd64.tar.gz
# wget https://go.dev/dl/go${GOV}.linux-arm64.tar.gz
rm -rf /usr/local/go && sudo mkdir -p /usr/local/go && sudo chmod 777 /usr/local/go
sudo tar -C /usr/local -xzf go${GOV}.linux-amd64.tar.gz
export PATH=/usr/local/go/bin:$PATH
echo 'PATH="/usr/local/go/bin:$PATH"' >> ~/.profile && source ~/.profile
go version
go env -w GO111MODULE=on
go env -w GOPROXY=https://goproxy.cn,direct
```

或者下面更简单:

```
sudo apt install golang -y
go version
echo "export GO111MODULE=on" >> ~/.profile
echo "export GOPROXY=https://goproxy.cn" >> ~/.profile
source ~/.profile
```

或者更简单：

```
go env -w GO111MODULE=on
go env -w GOPROXY=https://goproxy.cn,direct
```

## 编码工具

```
# Install vscode
sudo rm -f /etc/apt/keyrings/packages.microsoft.gpg
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
sudo install -D -o root -g root -m 644 packages.microsoft.gpg /etc/apt/keyrings/packages.microsoft.gpg
sudo sh -c 'echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list'
sudo apt update -y && sudo apt install code -y
```

## AOSP与内核

**这里对于rock5b或者其它arm64环境不需要安装**

```
# Install the packages needed for AOSP build
DEBIAN_FRONTEND="noninteractive" sudo apt-get install -y git-core gnupg flex bison build-essential \
    zip curl zlib1g-dev gcc-multilib g++-multilib libc6-dev-i386 lib32ncurses5-dev \
    x11proto-core-dev libx11-dev lib32z1-dev libgl1-mesa-dev libxml2-utils xsltproc unzip \
    fontconfig libncurses5 procps rsync libsqlite3-0

# Install the packages needed for AOSP kernel build
sudo apt install p7zip-full wget curl git tree pkg-config vim -y
sudo apt-get install dialog file python3 python3-pip python2 libelf-dev gpg gpg-agent tree flex bison libssl-dev zip unzip curl wget tree build-essential bc software-properties-common libstdc++6 libpulse0 libglu1-mesa locales lcov --no-install-recommends -y
```

## Linux kernel内核编译依赖

```
$ sudo apt-get install -y fakeroot build-essential devscripts libncurses5 libncurses5-dev
```

## BCC

开箱使用：

https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---binary

```
# Install kernel headers and BCC
sudo apt-get install -y linux-headers-$(uname -r)
```

源码编译：

https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---source

# depends for bcc

```
sudo apt install -y bison build-essential cmake flex git libedit-dev \
    libllvm14 llvm-14-dev libclang-14-dev python3 zlib1g-dev libelf-dev libfl-dev python3-distutils iperf netperf arping net-tools python-is-python3 libbfd-dev libcap-dev clang llvm dwarves
```

# make all packages under ebpf dir

```
mkdir ebpf && cd ebpf
```

## bcc python

```
rm -rf bcc
git clone --recursive https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake .. -DENABLE_LLVM_SHARED=1
make -j8
sudo make install
cmake -DPYTHON_CMD=python3 -DENABLE_LLVM_SHARED=1 ..
pushd src/python/
make -j8
sudo make install
popd
cd ..
```

## bcc libbpf-tools

直接编译会报如下错误：

```
/usr/include/linux/errno.h:1:10: fatal error: 'asm/errno.h' file not found
#include <asm/errno.h>
         ^~~~~~~~~~~~~
1 error generated.
```

执行如下命令编译即可：

```
cd libbpf-tools/
make -j8 BPFCFLAGS="-g -O2 -Wall -I/usr/include/aarch64-linux-gnu"
cd ../../
```


## bpftrace

源码编译：

https://github.com/iovisor/bpftrace/blob/master/INSTALL.md#ubuntu

先安装依赖：

```
sudo apt-get install -y \
  bison \
  cmake \
  flex \
  g++ \
  git \
  libelf-dev \
  zlib1g-dev \
  libfl-dev \
  systemtap-sdt-dev \
  binutils-dev \
  libcereal-dev \
  llvm-12-dev \
  llvm-12-runtime \
  libclang-12-dev \
  clang-12 \
  libpcap-dev \
  libgtest-dev \
  libgmock-dev \
  asciidoctor
```

build bpftrace:

```
rm -rf bpftrace
# export https_proxy=http://192.168.0.120:7890 http_proxy=http://192.168.0.120:7890 all_proxy=socks5://192.168.0.120:7890
git clone https://github.com/iovisor/bpftrace --recurse-submodules
mkdir bpftrace/build; cd bpftrace/build;
../build-libs.sh
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j8
sudo make install
cd ../../
```


## libbpf

```
# For libbpf c compile
# sudo apt-get install -y clang llvm libelf1 libelf-dev zlib1g-dev

git clone https://github.com/libbpf/libbpf
pushd libbpf/src
make -j8
sudo make install
popd
```

## libbpf-bootstrap

```
git clone --recursive https://github.com/libbpf/libbpf-bootstrap
pushd libbpf-bootstrap/examples/c
make -j8
popd
```

## bpftool

```
git clone --recursive https://github.com/libbpf/bpftool
pushd bpftool/src
make -j8
sudo make install
popd
```



## 其他

perf

```
$ sudo apt-get install openssh-server linux-tools-$(uname -r) -y
```

## cuttlefish

https://source.android.com/docs/setup/create/cuttlefish-use?hl=zh-cn

https://android.googlesource.com/device/google/cuttlefish/

在rock5b上执行：

编译模拟器：

```
sudo apt install -y git devscripts config-package-dev debhelper-compat golang curl
git clone https://github.com/google/android-cuttlefish
cd android-cuttlefish
for dir in base frontend; do
  cd $dir
  debuild -i -us -uc -b -d
  cd ..
done
sudo dpkg -i ./cuttlefish-base_*_*64.deb || sudo apt-get install -f
sudo dpkg -i ./cuttlefish-user_*_*64.deb || sudo apt-get install -f
sudo usermod -aG kvm,cvdnetwork,render $USER
sudo reboot
```

启动模拟器：

```
HOME=$PWD ./bin/launch_cvd
```

在自己的机器上连接cuttlefish:

先安装scrcpy，在Ubuntu上执行`sudo apt install -y scrcpy`，macOS上执行`brew install scrcpy`。然后连接：

```
adb connect $ip_of_cf:6520
scrcpy
```
