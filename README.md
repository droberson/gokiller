# Golang Killing Rootkit

This rootkit was based off of https://github.com/rootfoo/rootkit

This LKM detects golang binary executions and kills them. The desired result
will be denying attackers the ability to use golang-based tools such as
[gscript](https://github.com/gen0cide/gscript) on your systems in a CTF
setting. This is not meant for production use.


## Description

After fingerprinting several dozen golang binaries on Linux, I discovered that
they make a call to mmap() with fingerprintable arguments early on in their
execution. This is an anomaly compared to system utilities written in C
(/bin/ls, /bin/bash, ...)

If this specific mmap() call is made, the kernel will kill the offending process:
```
$ strace ../1571514139_gscript.bin 
execve("../1571514139_gscript.bin", ["../1571514139_gscript.bin"], [/* 21 vars */]) = 0
arch_prctl(ARCH_SET_FS, 0x83b4f0)       = 0
sched_getaffinity(0, 8192, [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ...]) = 64


mmap(0xc000000000, 65536, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 <unfinished ...>
^^^^ this is the mmap() call that we are looking for.


+++ killed by SIGKILL +++
Killed
```
It will also execute _/root/cp.sh pid_. This script can contain anything or be
a compiled binary.

The provided script simply makes a copy of the executable running before it is
killed. This is useful for collecting malware.


## Compiling, Loading

Use `dmesg -w` to see the diagnostic output. After loading, experiment running various
shell commands to see execve being hijacked in real time.

```
make
sudo insmod gokiller.ko
lsmod
sudo cp cp.sh /root/cp.sh
sudo chmod +x /root/cp.sh
```

## Status

This project was last developed and tested on Ubuntu 18.04 (Linux kernel 4.15.0-48-generic). It worked on several older systems as well with 3.x kernels. 2.6 kernels did not work.


## Installing binary modules

Generally you should always compile kernel modules on the same host they will be installed
on. However, it is possible to compile it offline and install it on a target system. Note 
that it must be compiled with the same kernel version and Linux distribution for this to 
work. The script below outlines the process.

```
#!/bin/bash
NAME="gokiller"
DIR="/lib/modules/`uname -r`/kernel/drivers/$NAME/"
sudo mkdir -p $DIR
sudo cp $NAME.ko $DIR
sudo depmod
sudo bash -c 'cat << EOF > /etc/modules-load.d/gokiller.conf
gokiller
EOF'
```

