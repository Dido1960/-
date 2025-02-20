之前提到的<font style="color:rgb(36, 41, 47);">K8s集群攻击模型，发现在该K8s内网中，所处位置大致可能是Pod容器上、Node节点上、Master节点上，可以按这个来分类信息收集的方式。</font>

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665374523817-90122076-653e-49c1-8f1f-8772fb29c88c.png)

<font style="color:rgb(36, 41, 47);">当然信息收集还包括常规的端口扫描方式，K8s集群内网的端口探测方式与常规内网并无太大区别，只需要关注K8s集群内的常见端口即可，前六个服务在实战中出现的概率较高：</font>

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

# Pod容器
## 判断是否在容器中
```plain
#查看CGroup信息
cat /proc/1/cgroup
```

在K8s容器上执行

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665382707969-ddbcdb39-abf6-4057-8cd4-874eda434ea6.png)

在docker容器上执行 

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665382731194-5125adce-00f4-4442-8e5c-f4bf19361959.png)

在Node上执行

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665385164877-72e2a786-7a28-48bd-b8ac-43dc0f8a14a0.png)

这个方式不止能判断是否在容器中，还能判断是否在K8s集群中，同时，这里的 CGroup 信息也是宿主机内当前容器所对应的 CGroup 路径，在后续的多个逃逸场景中获取 CGroup 的路径是非常重要的。 

```plain
# 该方式无法区分容器是否在K8s环境中
ls -l .dockerenv
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665382258028-4fd67026-30a3-4436-a581-43a453a2659e.png)

```plain
#查看挂载信息
cat /proc/mounts | grep kub
cat /proc/self/mounts | grep kub
cat  /etc/mtab | grep kub
```

在K8s容器上执行

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665384863671-09e1f73c-ecf6-4ccb-b9d8-96eef82fd67e.png)

在docker容器上执行

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665384976830-1ed20472-62a9-444a-b369-be5dee20425e.png)

在Node节点上执行

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665384954780-7622ab85-832d-40b8-bf7f-622c33383666.png)

```plain
env | grep KUBE -i
ls /run/secrets/kubernetes.io/
df -h
cat /etc/resolv.conf
```

在K8s容器上执行

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665392721580-91d30fbe-3f34-4bd6-aa0d-22038fb51cda.png)

```plain
cat /proc/self/mountinfo | grep kub
```

在K8s容器上

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665386709912-a39d0d0f-d794-416a-b058-3ed18e67c3f8.png)

在docker容器上

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665386725894-f1f1f0e0-ed3d-4396-aa42-bb7fe6e82dfa.png)

在Node节点上

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665386691752-8f37dca1-de55-4037-afda-a5b8ad7fd6e2.png)

## 
## 获取Service account身份认证凭据
```plain
ls /var/run/secrets/kubernetes.io/serviceaccount
```

# ![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665391065905-3bf044d3-da09-4a68-bd0b-9fb85edfa1fd.png)
```plain
#根据token获取当前ServiceAccount账号具有哪些权限
kubectl --insecure-skip-tls-verify=true --server="https://10.206.0.2:6443" --token="eyJhbG..." auth can-i --list
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665391424574-44793c92-9929-4aa3-8499-375b281a6c88.png)

在容器中中执行

```plain
env | grep kube -i
```

可能存在KUBLET_CERT，KUBLET_KEY和CA_CERT环境变量，使用这些身份认证凭据与API server通信

![](https://cdn.nlark.com/yuque/0/2022/jpeg/12767265/1665393695487-ea7d686c-faf4-4f3b-8144-2ae01895324f.jpeg)

```plain
#根据ca.crt、kublet.key、kublet.crt进行认证
kubectl --server=https://10.206.0.2:6443 --insecure-skip-tls-verify=true --client-key=kublet.key --client-certificate=kublet.crt get pods --all-namespaces
```



## 获取Capabilities信息
```plain
#获取Capabilities信息，判断是否存在容器逃逸的可能
capsh --print
不存在capsh命令时：
cat /proc/1/status | grep Cap
在本地主机上执行
capsh --decode=xxx
解码出 Capabilities 的可读字符串即可。
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665384424861-4931b3f4-de24-4854-bfad-7da82a57fba8.png)

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665384432475-2c6f3f1d-b263-449f-933e-6ca4993b4ffd.png)

> 不安全的权限配置，相关利用在讲到容器逃逸时会提及
>

## 使用CDK
在命令受限的容器环境中，如不存在ps和ifconfig命令，还可以使用[cdk](https://github.com/cdk-team/CDK/)工具代替

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665387454613-a0222fd9-b99b-4458-a8f9-7e19d84dbdab.png)

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665387460634-79c0bff6-7266-4354-ae43-6c781c2f2a3b.png)

cdk还存在容器内部信息收集的功能，<font style="color:rgb(36, 41, 47);">以发现潜在的弱点便于后续利用</font>

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665387839763-0b98ffbc-8a5d-4091-b0d2-841b7afbc095.png)

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665389269277-e8d7c73e-9a2e-4033-9b51-c6f264624dc3.png)

寻找云厂商的 metadata API 信息

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665422683064-0e60ba29-5e08-4c85-9659-5d8d07bf8fc5.png)

使用cdk工具有被检测的风险

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665387490572-da79e2ea-6255-471b-a48f-b688d6dd273d.png)

# Master节点
```plain
#查看授权模式
cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep "authorization-mode"
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665389954863-10b06d9c-6dab-4dfd-ae46-6936e4539142.png)



```plain
#查看API server非安全端口是否暴露
cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep insecure-port
但是这种情况很少了，条件必须是低版本（1.20版本后该选项已无效化）加配置中(/etc/kubernets/manifests/kube-apiserver.yaml )写了insecure-port选项,默认不开启
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665390050622-e64c1c2b-8bd0-4b87-9d4f-2bc011745f31.png)

```plain
寻找ca.crt、key.pem、server.key等认证相关文件，存在多台Master节点时，可能寻找新的Master节点
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665390195136-34e90935-01e0-497b-8e06-d28359f804dc.png)

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665390202451-11b400fb-40e7-4e55-b482-628508d8f086.png)

```plain
#查看集群kubeconfig配置文件
kubectl config view --raw
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665390289883-74b04976-6082-446a-8012-1a4398dff763.png)

寻找Master节点上etcd证书相关配置

```plain
env | grep ETCDCTL -i
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665422490132-3c849ee1-c998-4f9b-ad01-a9b7b10aa493.png)

# Node节点
```plain
#查看是否存在kubelet配置不当导致的匿名访问
cat /var/lib/kubelet/config.yaml
```

![](https://cdn.nlark.com/yuque/0/2022/png/12767265/1665390638132-d58367ae-f26b-482c-8be0-c5afe767182b.png)



