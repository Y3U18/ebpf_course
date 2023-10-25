LSM支持需要开启内核支持。方式两种，安装自己编译的内核，位于kernel_enabled_lsm目录下。

或者执行下面操作：

管理员权限打开/etc/default/grub文件，为GRUB_CMDLINE_LINUX变量添加以下内容：
```
"lsm=lockdown,capability,yama,apparmor,bpf"
```
