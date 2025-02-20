# 云原生安全——K8s基础知识

# 概述
<font style="color:rgb(34, 34, 34);">一言以蔽之，</font><font style="color:rgb(51, 51, 51);">云原生架构和技术，解决了企业上云时，如何设计、构建和操作，并充分利用云计算模型工作负载的问题。</font>

<font style="color:rgb(51, 51, 51);">以下是云原生计算基金会（CNCF）对云原生的定义：  
</font>![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664637594685-fd390f16-adca-4d99-979e-7fb0868403c9.png)

<font style="color:rgb(51, 51, 51);">作为云原生管理与编排系统的代表</font><font style="color:rgb(51, 51, 51);">，</font><font style="color:rgb(34, 34, 34);">Kubernetes 是一个可移植、可扩展的开源平台，用于管理容器化的工作负载和服务，可促进声明式配置和自动化。 Kubernetes 拥有一个庞大且快速增长的生态，其服务、支持和工具的使用范围相当广泛。</font>

<font style="color:rgb(34, 34, 34);">应用程序运行环境在Kubernetes崛起的过程中，也经历了从传统系统部署->硬件虚拟化系统部署->容器部署的过程。</font>

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664684841638-e730746d-61aa-4189-bad3-2b8dab2a584f.png)

<font style="color:rgb(34, 34, 34);">当我们在讨论云原生安全时，大部分时候是在讨论 Kubernetes（后边都简称K8s）安全。这也是本文即后续文章讨论云原生安全的主要方向，由于本文为基础知识篇，我们主要关注在红蓝对抗场景下会涉及到的K8s相关对象、组件、用户认证知识，以便后续更好的理解K8s在实战攻防中的攻击思路。</font>

# <font style="color:rgb(34, 34, 34);">K8s组件</font>
<font style="color:rgb(34, 34, 34);">Node</font>，Pod，API server 是我们经常听到的K8s相关名词，那他们之间是什么关系呢？

参考官方文档，<font style="color:rgb(34, 34, 34);">一个 K8s 集群，包括一群工作机器，这些机器称为 Node，可以部署在虚拟机或者物理机上，一个集群至少存在一个 Node。工作节点托管着 Pod ，运行着一个或者多个容器，即容器跑在 Pod 上。API server 作为集群中控制平面的一员大将，协同集群控制平面中其他组件管理着 Node 和 Pod。 一个集群通常运行多个 Node，所以控制平面也管理着多台机器，提供了容错性和高可用性。Node我们常称为工作节点，多个 Node，Pod 称为 Nodes 和 Pods，这都很好理解。</font>

<font style="color:rgb(34, 34, 34);">上边提到的 Node 跟控制平面，包含着 K8s 集群中的各种组件，一个正常运行的 K8s 集群所需的各种组件如下：</font>

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664641430038-4a4f2134-8551-46d8-888b-6cb928f07ea2.png)

<font style="color:rgb(34, 34, 34);">可见，API server 属于控制平面组件；</font>kubelet，kube- proxy 属于 Node 组件等等，这些组件在集群工作中都是什么关系呢？可以参考 neargle 在[从零开始的Kubernetes攻防](https://github.com/neargle/my-re0-k8s-security/blob/main/README.md#7-%E5%AE%B9%E5%99%A8%E5%AE%B9%E5%99%A8%E7%BC%96%E6%8E%92%E7%BB%84%E4%BB%B6-api-%E9%85%8D%E7%BD%AE%E4%B8%8D%E5%BD%93%E6%88%96%E6%9C%AA%E9%89%B4%E6%9D%83)中提供的组件分工图

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664643705369-48b08733-8f10-4666-bd08-87b43e73e815.png)

为了方法理解，作者还简述了各组件的工作关系，这里一并贴出来：

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664643760639-fe624346-8aba-436e-9c93-d38b76cc4409.png)

对K8s各组件功能及工作关系有了大致的了解后，接下来强化一些重要的名词的概念。

## API server
<font style="color:rgb(34, 34, 34);">API server 是K8s集群控制平面的组件，通过 Kubernetes API，负责接受和处理请求。API server 是 Kubernetes 控制平面的前端。作为K8s集群管理的入口，获取 API server 的管理权限，经常作为攻击链中的重要一环。</font>

## kubectl
<font style="color:rgb(34, 34, 34);"> kubectl 是K8s 提供的命令行工具，与 API server 组件通过 Kubernetes API 进行通信，达到部署应用、监测和管理集群资源以及查看日志的作用。其本质上都是通过HTTP/HTTPS请求实现，kubectl通信前在 $HOME/.kube 目录中查找一个名为 config 的配置文件，也可以通过设置 KUBECONFIG 环境变量或设置 </font>[<font style="color:rgb(34, 34, 34);">--kubeconfig</font>](https://kubernetes.io/zh-cn/docs/concepts/configuration/organize-cluster-access-kubeconfig/)<font style="color:rgb(34, 34, 34);"> 参数指定。</font>

## Node
<font style="color:rgb(34, 34, 34);">K8s在Node上托管着 Pod ，运行着一个或者多个容器，即容器跑在 Pod 上。Node 可以部署在虚拟机或者物理机上，包含着运行 Pod 所需的服务，这些节点由控制平面负责管理，通常K8s集群中会有若干个节点。</font>

<font style="color:rgb(51, 51, 51);">有必要了解一下 Master 节点，该节点是 K8s 集群的控制节点，每个 K8s 集群里至少有一个 Master 节点，它负责整个集群的决策（如调度），发现和响应集群的事件。Master 节点可以运行在集群中的任意一个节点上，但是最好将 Master 节点作为一个独立节点，不在该节点上创建容器，因为如果该节点出现问题导致宕机或不可用，整个集群的管理就会失效。之前提到的控制平面组件，包括 API server、ETCD等，正是运行在 Master 节点上。</font>

<font style="color:rgb(51, 51, 51);">通常情况下，我们使用 kubectl 工具在 Master 节点上对 K8s 集群进行管理。</font>

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664649266830-73bc0ac6-eae6-4e1d-9bd7-8a3ab6fe12f7.png)

图为腾讯云私有网络中部署的具有两个节点的 K8s 集群环境，对应主机名，发现 Master 节点正是运行 kubectl 工具的主机，Master 节点的 INTERNAL-IP 字段为腾讯云内网IP，与 kubectl 配置文件中 server 字段表示的 APIserver 服务IP一致，说明控制平面运行在 Master 节点上。

## kubelet
前边提到，Node 中的组件包含 的kubelet，<font style="color:rgb(34, 34, 34);">是在每个 Node 节点上运行 的agent，可以向 API server 注册 Node 信息。kubelet 是基于 PodSpec来工作的。每个 PodSpec是一个描述 Pod 的 YAML 或 JSON 对象。 kubelet 接受通过各种机制（主要是通过 apiserver）提供的一组 PodSpec，并确保这些 PodSpec 中描述的容器处于运行状态且运行状况良好。</font>

在 K8s 集群中，大部分组件都是运行在容器中的应用，包括API server

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664651699923-5f8d6b2d-f642-4b21-bb59-4c0e68f9d1f7.png)

但kubelet与docker一样，以本地服务的形式存在

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664651810971-a149cdc4-6631-47b5-9a75-ea055131229f.png)

## <font style="color:rgb(34, 34, 34);">Pod</font>
<font style="color:rgb(34, 34, 34);">Pod是可以在 Kubernetes 中创建和管理的、最小的可部署的计算单元。</font>

<font style="color:rgb(34, 34, 34);">一个Pod包含一个或多个容器，这些容器共享存储、网络、以及怎样运行这些容器的声明。 Pod 中的内容在共享的上下文中运行。 一个Pod可以理解为一个拥有IP的虚拟主机 ，其中包含一个或多个容器应用，暴露在不同的端口。如果把Pod理解为一个物理主机，那一个或多个容器应用就可以大致理解为物理主机上运行多个服务。</font>

<font style="color:rgb(34, 34, 34);">在同一个Node上创建多个Pod，则容器网络会为每个Pod分配一个虚拟IP</font>

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664652909721-e2110e83-f98d-4f07-b68d-3630326221c5.png)

如图在 vm-0-3-centos 节点上（10.206.0.3），存在3个Pod（10.244.1.18-20），每个Pod所分配的虚拟IP不同，这种网络是通过Flannel网络插件实现的，作为容器应用运行在节点上。

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664653808088-78f4716d-fbf3-4107-8054-34cca191721b.png)

## 容器网络
通过K8s网络插件（如Flannel）实现的容器网络，无论是在Node主机上，还是在Pod上运行的容器中，都能对这些Pod虚拟IP进行访问；在Pod<font style="color:rgb(36, 41, 47);">容器里也可以直接访问内网：</font>

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664654924317-533dcf36-996f-4867-9735-6d8777a03038.png)

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664654945647-7e5dff23-abb6-4186-b247-b501f6e9adbe.png)

如果在真实的K8s集群环境中碰到这种网络环境，会加速集群内网的沦陷。<font style="color:rgb(36, 41, 47);">合理的网络隔离是必要的，可以利用常规的 iptables 进行设置和规划。更多容器网络相关知识可参考</font>[这里](https://github.com/neargle/my-re0-k8s-security/blob/main/README.md#4-%E5%AE%B9%E5%99%A8%E7%BD%91%E7%BB%9C)。

# <font style="color:rgb(34, 34, 34);">K8s对象</font>
<font style="color:rgb(34, 34, 34);">在 Kubernetes 系统中，Kubernetes 对象是持久化的实体。 Kubernetes 使用这些实体去表示整个集群的状态。 </font>常见的K8s对象有Node、Pod、Service、ServiceAccount、ClusterRole等，稍后将介绍这些对象常见的创建与管理方法。

<font style="color:rgb(34, 34, 34);">当使用 Kubernetes API 创建对象时，API 请求必须在请求本体中包含 JSON 格式的信息。大多数情况下，我们会使用 .yaml 文件为 kubectl 提供这些信息。 kubectl 在发起 API 请求时，将这些信息转换成 JSON格式。</font>

```plain
#simple-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - name: nginx
    image: nginx:1.14.2
    ports:
    - containerPort: 80
```

<font style="color:rgb(34, 34, 34);">上边是一个简单的yaml配置文件，描述了如果如何创建一个对象</font>

```plain
#使用kubectl，根据simple-pod.yaml创建对象
kubectl apply -f simple-pod.yaml
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664682529942-afc3318f-c0d3-47b2-87ef-4af0eef135ff.png)

```plain
#设置-v=8，发现kubectl 在发起 API 请求创建对象时，将yaml配置信息转换成JSON格式,作为请求体发送。
kubectl create -f simple-pod.yaml -v=8
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664682908557-5f52509d-93f7-469c-be33-bcb64f478946.png)

<font style="color:rgb(34, 34, 34);">对应上边的例子，在想要创建的 Kubernetes 对象所对应的 .yaml 文件中，需要配置的字段如下：</font>

+ <font style="color:rgb(34, 34, 34);">apiVersion</font><font style="color:rgb(34, 34, 34);"> </font><font style="color:rgb(34, 34, 34);">- 创建该对象所使用的 Kubernetes API 的版本</font>
+ <font style="color:rgb(34, 34, 34);">kind - 想要创建的对象的类别</font>
+ metadata<font style="color:rgb(34, 34, 34);"> </font><font style="color:rgb(34, 34, 34);">- 帮助唯一标识对象的一些数据，包括一个</font><font style="color:rgb(34, 34, 34);"> </font>name<font style="color:rgb(34, 34, 34);"> </font><font style="color:rgb(34, 34, 34);">字符串、</font>UID<font style="color:rgb(34, 34, 34);"> </font><font style="color:rgb(34, 34, 34);">和可选的</font><font style="color:rgb(34, 34, 34);"> </font>namespace
+ spec<font style="color:rgb(34, 34, 34);"> - 你所期望的该对象的状态</font>

<font style="color:rgb(34, 34, 34);"> 关于这些字段的详细格式，可以查阅 </font>[Kubernetes API 参考](https://kubernetes.io/zh-cn/docs/reference/kubernetes-api/)<font style="color:rgb(34, 34, 34);">。</font>

## Namespace
<font style="color:rgb(34, 34, 34);">在了解如何管理对象之前，我们还需要知道在K8s中，什么是namespace？名字空间（Namespace） 将同一集群中的资源划分为相互隔离的组。我们常见的对象如Deployment、Pod、ServiceAccount、Service都存在namespace；但也有不存在namespace的，比如Node。</font>

```plain
#查看所有的namespace
kubectl get namespaces
#查看各个namespace下的Pod
kubectl get pods --all-namespaces
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664685281146-7b1dbabc-5eb8-436b-aeeb-02a899dae4cd.png)

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664685316364-a31bd402-0521-4d2f-97cf-5a2fa548b4f2.png)

## Deployment
<font style="color:rgb(34, 34, 34);">简单的理解，Deployment声明了如何更新一组Pods（通过相同的Pod模版构建）。我们可以在创建 Deployment 的.yaml 中的描述一组Pods的期望状态，然后 Deployment 控制器 会以受控速率更改实际状态，使其变为期望状态。你可以定义 Deployment 以创建新的 Pods，或删除现有 Deployment，并通过新的 Deployment 回收其资源，简单的说，就是Deployment根据期望状态，可以动态创建和销毁 Pod。</font>

```plain
#run-my-nginx.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-nginx
spec:
  selector:
    matchLabels:
      run: my-nginx
  replicas: 2
  template:
    metadata:
      labels:
        run: my-nginx
    spec:
      containers:
      - name: my-nginx
        image: nginx
        ports:
        - containerPort: 80
```

```plain
#上述描述了一个Deployment,创建Deployment类似创建Pod等其他对象
kubectl create -f run-my-nginx.yaml

#查看所有namespace下的deployment
kubectl get deployment --all-namespaces
#通过-n指定default名称空间，寻找该名称空间下名为my-nginx的deployment的description
kubectl describe deployment -n default my-nginx
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664689557213-cfa51d4d-0a60-4aa4-b0ca-4d3b866f2931.png)

run-my-nginx.yaml中replicas为2，即容器会时刻监控并确保该Deployment中的Pod数量为2，至于如何实现的我们不用太关心。除了上述的create、describe、get，kubectl常用的命令还有apply、delete命令，用于更新和删除K8s对象

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664689980702-890c136b-7a4a-4638-87ba-8ae6be2c64aa.png)

由于没修改simple.pod.yaml，apply后显示unchanged

## Service
<font style="color:rgb(34, 34, 34);">K8s 的 Deployment对象，可以动态的创建和销毁Pod，每一次Pod的创建，都会在容器网络中被新分配一个IP，这样十分不便其他Pod与之进行通信，因为IP在不断变化。K8s提供service对象解决了这个问题，将一组Pods抽象为一个网络服务，并分配一个独立的IP，其他Pod只需要关心如何跟这个IP通信，K8s会自动在一组相同功能的Pod间实现负载均衡，这个service就是我们常说的微服务。</font>

<font style="color:rgb(34, 34, 34);">配合创建好的deployment对象，创建service对象：</font>

```plain
#nginx-svc.yaml
apiVersion: v1
kind: Service
metadata:
  name: my-nginx
  labels:
    run: my-nginx
spec:
  ports:
  - port: 80
    protocol: TCP
  selector:
    run: my-nginx
```

labels标签"run：my-nginx"与之前创建的deployment的 labels 标签对应

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664692406152-769fec90-6a7d-408d-aba6-79223cb44274.png)

```plain
kubectl create -f nginx-svc.yaml

#查看所有namespace下的service
kubectl get service --all-namespaces
#查看default名称空间下my-nginx service的description
kubectl describe service -n default my-nginx
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664692585537-52f1e7a1-d7bf-478d-a28a-eb793ff8de13.png)

可见新建的my-nginx service服务对应IP 10.97.29.251，对应的后端Pod为10.244.1.18-19，访问10.97.29.251会负载到后端任意Pod上

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664693052464-45625971-9c4a-485e-aa51-ac13459f4f01.png)

## Node
Node相信大家都比较熟悉了，但与上边提到的对象不同，他是没有名称空间的

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664693379020-5ccc3ae5-ae31-433f-8a62-6337908d9c56.png)



除了上述对象，Role、Rolebinding、ClusterRole、ClusterRoleBinding、ServiceAccount等也是在攻防技战法中会接触到的对象，等后边提及时我们再展开。

# <font style="color:rgb(34, 34, 34);">K8s用户认证</font>
## 用户
<font style="color:rgb(34, 34, 34);">所有 Kubernetes 集群都有两类用户：由 Kubernetes 管理的服务账号和普通用户。</font>

<font style="color:rgb(34, 34, 34);">Kubernetes 并不包含用来代表普通用户账号的对象，即普通用户的信息无法通过 API 调用添加到集群中。</font>

<font style="color:rgb(34, 34, 34);">与此不同，服务账号是 Kubernetes API 所管理的用户，为K8s中的ServiceAccount对象，它们被绑定到特定的名字空间，或者由 API 服务器自动创建，或者通过 API 调用创建。</font>

<font style="color:rgb(34, 34, 34);">ServiceAccount 对象对应着一组认证凭据，保存在Secret 对象中，这些凭据会被挂载到 Pod 中，从而允许集群内的进程访问 Kubernetes API。在红蓝对抗的过程中，我们会经常与ServiceAccount和Secret对象接触。</font>

```plain
#查找kube-system名称空间下的serviceaccount对象
kubectl get serviceaccount -n kube-system
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664704994068-16533716-f399-4263-9e41-57269c296597.png)

```plain
#获取hx-sa-list-secrets用户对应的Secret对象
kubectl get secret -n kube-system |grep hx-sa-list-secrets
kubectl get secret hx-sa-list-secrets-token-w2tsl -n kube-system -o yaml
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664705262112-7bc99f96-660d-42df-a6b7-36e16e9496d5.png)

<font style="color:rgb(34, 34, 34);">成功读取到了ServiceAccount凭据，可用于K8s中与API server的身份认证。</font>

## 身份认证策略
在K8s中与API server通信，需要通过身份认证，一般有以下两种方式：

+ 请求中携带token
+ 使用kubectl

### 请求中携带token
通过添加头部进行认证，Bearer后的值为用户认证凭据中的token，如Secert对象中的token字段

```plain
Authorization: Bearer 31ada4fd-adec-460c-809a-9e56ceb75269
```

如图，在header中添加高权限的ServiceAccount token值，通过API server的身份认证后，读取敏感信息：

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664725464679-53b0ff61-703b-4ad1-89b3-01c9e1875ed5.png)

### 使用kubectl
当我们使用kubectl访问API server时候，默认情况下，kubectl 会在 $HOME/.kube 目录下查找名为 config 的文件。 你可以通过设置 KUBECONFIG 环境变量或者设置 --kubeconfig 参数来指定其他 kubeconfig 文件。

```plain
#因为kubeconfig文件的位置不固定，使用kubectl命令读取kubeconfig文件
kubectl config view --raw
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664721271883-15f1e2a2-fb1f-4857-94b2-460b15f69358.png)

无论是kubeconfig还是ServiceAccount的Secret，都存在着与API server通信所需要的身份认证凭证，在红蓝对抗中，当我们拿到这些凭证，要如何与API server进行通信呢？

理想的情况下，当我们拿下了Master节点，可以直接使用kubectl命令，它会自动寻找本地存储的kubeconfig文件与API server进行通信：

```plain
#在Master节点上执行如下语句，无需额外参数，kubectl会自动寻找kubeconfig文件
kubectl get node
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664721935852-37dafcd2-b32f-465a-b640-82047bb29af1.png)

但是当我们还没获取Master节点权限，只是在容器内网中通过漏洞利用或者信息收集获取到身份凭证和API server的地址呢？

<font style="color:rgb(34, 34, 34);">此时可以参考kubeconfig配置中描述的与API server的通信的常用的两种认证方式，并对应到kubectl命令：</font>

+ <font style="color:rgb(34, 34, 34);">Certificates</font>

```plain
#kubeconfig配置
users:
  - name: admin
    user:
      client-certificate-data: <base64 encoded client cert data>
      client-key-data: <base64 encoded client key>

#kubectl通过证书进行身份认证
kubectl --server=https://10.206.0.2:6443 --insecure-skip-tls-verify=true --client-key=kublet.key --client-certificate=kublet.crt get pods --all-namespaces
```

这里获取kubeconfig的client-certificate-data和client-key-data后，base64解码保存到kubelet.crt和kubele.key中，--insecure-skip-tls-verify=true表示不验证服务端证书的有效性。

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664723344381-4a023354-2b34-4b80-adaa-57cd7ded68b9.png)

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664723016869-55854dbc-9cfc-4337-9c91-b90ef6bc43da.png)

+ <font style="color:rgb(34, 34, 34);">Authentication tokens</font>

```plain
#kubeconfig配置
users:
  - name: admin
    user:
      token: >_
        dGhpcyBpcyBhIHJhbmRvbSBzZW50ZW5jZSB0aGF0IGlzIGJhc2UgZW5jb2R

#通过token进行身份认证
kubectl --insecure-skip-tls-verify=true --server="https://10.206.0.2:6443" --token="eyJhbGciOiJSU..." get ns
```

比如获取ServiceAccount的Secret凭据后，通过token进行认证

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664724296180-5e2df83f-a465-4996-811b-f4ef7a769a4e.png)

由于该ServiceAccount权限不够，无法执行列举namespace

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664724408063-7db42dad-efb0-47f4-ad18-3014a1ce9eb3.png)

通过身份认证后，基于角色访问控制（RBAC，K8s高版本默认鉴权方式）子系统会确定用户是否有权针对某资源执行特定的操作。此鉴权方式在配置不当的情况下，也会出现一些安全问题，将再后续的文章提及。关于K8s中用户其他的身份认证策略，可以参考[这里](https://kubernetes.io/zh-cn/docs/reference/access-authn-authz/authentication/#authentication-strategies)。

# K8s安全
了解完K8s相关组件、对象、用户认证等基础知识后，可以开始谈K8s相关的安全问题了，<font style="color:rgb(36, 41, 47);">CIS2020上总结过的K8s集群攻击模型：</font>

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1664727240194-70ccc10c-fab9-438a-9ae4-f9bcfc6f7c39.png)

<font style="color:rgb(36, 41, 47);">我们攻击的起点可能并不一定总是权限受限的容器，在内网信息收集时，也可能直接探测到K8s API server的非安全端口开放的情况，此时攻击起点变成了API server。在这里我们不纠结攻击的起点，而是考虑当我们碰到一个K8s内网，我们的关键目的是什么？</font>

针对K8s安全，我从红队视角和漏洞视角两个维度出发，列出了一些可能用到的知识点。在后续的研究过程中，不当不足之处，会进行更新补充，如下为V1.1版本：

![](https://cdn.nlark.com/yuque/0/2023/png/12767265/1673583867106-873fdc4e-1957-4da4-829f-be511214ff00.png)

在针对K8s的攻防场景下，集群权限的获取和隔离突破，常常作为技战术中的关键目的，当然达成目的前期，离不开容器内网的信息收集的。同时，K8s相关漏洞也贯穿在重要的攻击节点中，如K8s组件配置不当、容器逃逸/提权。后续将以K8s容器内网信息收集、组件配置不当、容器逃逸/提权等为主题分享技术文章。



## 参考
> 学习过程主要参考文章如下：
>
> [https://github.com/neargle/my-re0-k8s-security](https://github.com/neargle/my-re0-k8s-security)  
[https://kubernetes.io/zh-cn/docs/home/](https://kubernetes.io/zh-cn/docs/home/)
>

