# 踩坑
在搭建集群环境的过程中尝试过不少方式，或是没搭成功，或是效果不佳： 

+ metarget云原生攻防靶场 
+ 在线学习平台katacoda 
+ minikube 

本地环境是苹果M1，只支持ARM架构的虚拟机，出现了各种问题，最后还是购买多节点的腾讯云服务器，使用kubeadm搭建K8s集群环境。

# 购买服务器
在腾讯云控制台搜索“私有网络”

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665369971938-e8b6c66c-d15f-4eda-b989-b382f522c779.png)

点击进入，新建私有网络信息，记住自己的地区，添加云服务时需要与之对应

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665370084535-befb6723-b5de-4735-a900-963217569fad.png)

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665370195766-702223f6-1b40-496d-9bc1-dfe71b622eeb.png)

添加云服务器

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665370310952-e767de71-27ae-446d-bbed-349df3dab812.png)

系统选择Centos8.0，用于测试可先按量计费购买

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665370293002-a7fe3517-0d23-4c59-b242-72c264fe040d.png)

此时拥有了两台在内网联通的Centos8.0服务器，可以开始搭建K8s集群环境。

# 节点初始化
<font style="color:rgb(51, 51, 51);">操作系统：CentOS 8.0（适用Centos7.x~8.x）  
</font><font style="color:rgb(51, 51, 51);">网络信息：k8s-master: </font>10.206.0.2<font style="color:rgb(51, 51, 51);">；k8s-worker: </font>10.206.0.3<font style="color:rgb(51, 51, 51);">  
</font><font style="color:rgb(51, 51, 51);">软件版本：Kubernetes v1.22</font>

> 参考[https://blog.k4nz.com/689628a1fd99be17b0ae82cea460b327/](https://blog.k4nz.com/689628a1fd99be17b0ae82cea460b327/)
>
> 在Master节点（10.206.0.2）与普通Node节点（10.206.0.3）上都需要进行以下操作
>

## 环境初始化
```plain
# 关闭防火墙
systemctl stop firewalld
systemctl disable firewalld

# 设置 SELINUX 关闭
# setenforce 0
yes | cp /etc/selinux/config /etc/selinux/config.backup
sed -i 's%SELINUX=enforcing%SELINUX=disabled%g' /etc/selinux/config

# 关闭Swap分区
# swapoff -a && sysctl -w vm.swappiness=0
yes | cp /etc/fstab /etc/fstab.backup
sed -i -E 's/(.+swap\s+swap.+)/# \1/g' /etc/fstab
swapoff -a

# 加载内核模块
cat > /etc/modules-load.d/kubernetes.conf <<EOF
br_netfilter
EOF

cat > /etc/sysctl.d/kubernets.conf <<EOF
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-arptables = 1
EOF
sysctl --system
```



## 安装docker服务
```plain
# 第一步、删除旧版本，并安装依赖
yum remove -y docker docker-client docker-client-latest docker-common \
    docker-latest docker-latest-logrotate docker-logrotate docker-engine

yum install -y yum-utils device-mapper-persistent-data lvm2

# 第二步、添加仓库并安装 Docker 服务
yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
yum install -y docker-ce                                                        # yum install -y docker-ce-18.09.0

# 第三步、启动 Docker 服务
systemctl start docker
systemctl enable docker

# 第四步、验证 Docker 服务正确安装
docker run --rm hello-world
docker -v

# docker服务配置
mkdir /etc/docker
cat <<EOF | sudo tee /etc/docker/daemon.json
{
  "exec-opts": ["native.cgroupdriver=systemd"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m"
  },
  "storage-driver": "overlay2"
}
EOF

systemctl enable docker
systemctl daemon-reload
systemctl restart docker
```

## 安装kubadm服务
```plain
配置源仓库，以安装必要的包：
# 下面是官方源（网络通常不通，除非使用网络加速，YUM 支持）
cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=0
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg
        https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
EOF

# 使用阿里镜像站
cat <<EOF > /etc/yum.repos.d/kubernetes-ali.repo
[kubernetes-ali]
name=Kubernetes ALi
baseurl=https://mirrors.aliyun.com/kubernetes/yum/repos/kubernetes-el7-x86_64/
enabled=1
gpgcheck=0
EOF

# 最后，更新YUM缓存
yum makecache

安装 kubadm 工具（但是不需要启动服务）：
yum install -y kubeadm-1.22.6 kubelet-1.22.6

# 如果没有 enable 服务，则在 kubeadm init 时会有警告。
# 但是不要 start 服务，这时候还没有初始化完成，缺少启动服务的某些配置文件（比如/var/lib/kubelet/config.yaml文件）。
# 这得感谢群里朋友的反馈 :-)
systemctl enable kubelet
```

## 重置kubeadm
在测试的过程中不小心把集群搞崩过，如果需要使用kubeadm reset 重置，有这些注意点：

+ Master节点重置之后，node节点也需要kubeadm reset 重置才可以加入
+ Master中的凭证也需要覆盖，cp /etc/kubernetes/admin.conf ~/.kube/config，否则使用kubectl命令会报 错误:

```plain
Unable to connect to the server: x509: certificate signed by unknown authority (possibly because of "crypto/rsa: verification error" while trying to verify candidate authority certificate "kubernetes")
```

+ <font style="color:rgb(51, 51, 51);">reset之后 node节点cni0网卡会冲突，需要删除，</font>flannel网络会重新分配

```plain
ifconfig cni0 down    
ip link delete cni0
```



# 在Master上执行
在10.206.0.2上执行

## kubeadm初始化
<font style="color:rgb(51, 51, 51);">执行如下命令进行节点初始化：</font>

```plain
# 在初始化之间
# 如果必要，则执行 kubeadm config images list 命令，并将相关镜像保存到私有仓库中。
kubeadm config images list 

# 开始初始化（依旧使用阿里云的镜像，没有私用私有镜像仓库）
# 如果直接使用官方镜像，则初始化可能失败。因为它会去k8s.gcr.io拉取镜像，而国内网络无法访问。
# 所以，我们使用 kubeadm init --image-repository 选项指定阿里云的镜像来初始化
kubeadm init                             \
    --pod-network-cidr=10.244.0.0/16     \
    --image-repository registry.aliyuncs.com/google_containers

# 等待初始化结束
# 在执行 kubeadm init 结束后，留意下面的输出：
...
Your Kubernetes control-plane has initialized successfully!

To start using your cluster, you need to run the following as a regular user:

  mkdir -p $HOME/.kube
  sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
  sudo chown $(id -u):$(id -g) $HOME/.kube/config

Alternatively, if you are the root user, you can run:

  export KUBECONFIG=/etc/kubernetes/admin.conf

You should now deploy a pod network to the cluster.
Run "kubectl apply -f [podnetwork].yaml" with one of the options listed at:
  https://kubernetes.io/docs/concepts/cluster-administration/addons/

Then you can join any number of worker nodes by running the following on each as root:

kubeadm join 10.206.0.2:6443 --token gfryox.ytmse7e3r0scurcy \
        --discovery-token-ca-cert-hash sha256:d2fcd2bc71c258f5af9cc444094c4add43705e52adad17c78b6f35bf54689ea3

# 上述内容：
# 1. 提示你初始化成功
# 2. 然后，执行下面的三条命令
# 3. 告诉你应该向集群中部署一个Pod网络，这一点参考官方中列出的网络选择
# 4. 在工作节点上执行命令可以加入集群中。
```

## <font style="color:rgb(51, 51, 51);">部署</font>flannel<font style="color:rgb(51, 51, 51);">网络插件</font>
```plain
# 创建网络
kubectl apply -f https://raw.githubusercontent.com/flannel-io/flannel/master/Documentation/kube-flannel.yml

# 然后，执行如下命令查看状态
kubectl get nodes
kubectl get pods --all-namespaces

# nodes 要处于 Ready 状态，pod 要处于 running 状态
# 当显示 ContainerCreating 时，表示正在创建，稍等即可
```



安装后可能会出现报错，需要手动创建/run/flannel/subnet.env文件

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665371598152-5f8f81d0-8b5d-4114-b71b-11797ea00785.png)

# 在Node上执行
在10.206.0.3上执行

## 添加节点到集群
```plain
kubeadm join 10.206.0.2:6443 --token gfryox.ytmse7e3r0scurcy \
        --discovery-token-ca-cert-hash sha256:d2fcd2bc71c258f5af9cc444094c4add43705e52adad17c78b6f35bf54689ea3

# ！！！ error execution phase preflight: unable to fetch the kubeadm-config ConfigMap: failed to get config map: Unauthorized
# ！！！ 遇到这错误是因为--token选项的TOKEN时效了（部署MASTER和NODE我间隔了很久），口令是有生存时间（TTL）的。
# ！！！ 使用kubeadm token create命令重新创建token口令（在Master上执行）。
# ！！！ https://github.com/kubernetes/kubeadm/issues/1310
# ！！！ 或者执行kubeadm token create --print-join-command命令，重新生成JOIN命令

# 重新生成token值
kubeadm token create

# 如果 token 过期，创建永不过期的 token 值（不建议）
kubeadm token create --ttl 0
```

## 从集群中删除节点
```plain
kubectl get nodes
kubectl drain "<node-name>" --ignore-daemonsets --delete-local-data
kubectl delete node "<node-name>"
```



# 验证集群状态
在Master节点上，执行

```plain
kubectl get nodes
```

发现成功创建K8s集群，存在一个Master主节点和Node工作节点

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665373903844-dc36305f-3342-484c-ac41-321b4394a585.png)

