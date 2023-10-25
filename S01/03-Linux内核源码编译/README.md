Linux内核源码编译：

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023 fei_cong(https://github.com/feicong/ebpf-course) */

依赖：

```
sudo apt-get install git fakeroot build-essential ncurses-dev xz-utils libssl-dev bc flex libelf-dev bison binutils-dev libcap-dev libreadline-dev pahole -y
```

安装：

```
sudo cp /boot/config-$(uname -r) /usr/src/linux-source-5.15.0/linux-source-5.15.0/.config
cd linux-source-5.15.0/
sudo cp -R ../debian .
sudo cp -R ../debian.master .

sudo make -j 8 modules
sudo make -C samples/bpf
sudo make modules_install
sudo make -j 8
sudo make install

安装启动项
sudo update-initramfs -c -k 5.15.60
sudo update-grub

卸载启动项：
sudo update-initramfs -d -k 5.15.60
sudo rm -rf /boot/*5.15.60*
sudo update-grub

dpkg --get-selections|grep linux
sudo apt-get remove linux-headers-5.15.0-43-generic linux-image-5.15.0-43-generic
sudo apt autoremove
```

下面的方法，编译生成deb安装包，见第一季31集LSM的源码目录。

https://wiki.ubuntu.com/Kernel/BuildYourOwnKernel

```
LANG=C fakeroot debian/rules clean
# quicker build:
LANG=C fakeroot debian/rules binary-headers binary-generic binary-perarch
# if you need linux-tools or lowlatency kernel, run instead:
LANG=C fakeroot debian/rules binary
```
