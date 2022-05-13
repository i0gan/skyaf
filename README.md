# avoid-ctf-py

仓库地址：https://github.com/i0gan/ctf-avoid-py

CTF大赛中很实用的防止PY工具，国内的PY现象一个日渐泛滥，在这种趋势下，想要赛选出真正有实力的选手还得看举办方的一个比赛规则的规定，也是举办方与参赛选手的一种对抗。再此呢，我开发了`skyaf`工具，在CTF PWN中十抓九准！曾经实践于2021安洵杯所有pwn题中，由于防止引起大家的煽动，当时没有公布筛选结果出来，大家有兴趣的话，可以看一下当时的流量抓取情况，在traffic目录下。

我也是本来想把这款软件技术写份专利的，但没有时间去搞这玩意儿，知识是拿来分享的，藏着也不行。我呢，目前也逐渐从CTF离开了，就把他公布出来吧，拯救一下国内严重泛滥的PY现象吧。自己之前写过选手博弈举办方的工具，比如[pwn_waf](https://github.com/i0gan/pwn_waf)，当然也配套有AWD批量攻击脚本 [awd_script](https://github.com/i0gan/awd_script)，这两个工具在打ctf awd模式的时候就爽歪歪了，除了安恒举办的awd plus。

## 原理

`skyaf`工具的思想是源自于我之前写了[pwn_waf](https://github.com/i0gan/pwn_waf)流量抓取工具中的转发模式。在docker内部网络中采用tcp非阻塞select进行转发了一下，并且对数据进行了日志写入。采用动态输入token，能够有一定程度防止PY。

选手连接过程：

```
选手 -> docker -> xinitd -> skyaf -> xinitd -> pwn
```

看着有点长，其实真正缩短起来，可以忽略docker和xinitd。

```
选手->skyaf->pwn
```

skyaf是作为选手和pwn服务的中介，传输的数据都要经过skyaf，这样skyaf只需吧数据记录下来就可以了。

skyaf不止是进行流量日志记录，且skyaf要求输入参数选手的账号以及选手的名字，若打通了之后，也加入了动态token验证，通过输入正确的token，才能获取正确的flag。



## 编译skyaf

进入到skyaf目录下，输入以下命令

```
make
```

这样就会在当前目录下编译出了skyaf。



## 如何使用skyaf？

### 基于所给的例子来改

我也给了个例子，在`examples/configure/pwnsky/docker/`下，着重看一下ctf.xinetd文件和skyaf.xinetd。这两个文件是xinetd服务的配置文件，相当于一个nginx的CGI一样。将二进制程序的标准IO映射成一个网络端口。ctf.xinetd文件基本就不用改，如下：

ctf.xinetd

```
service ctf
{
    disable = no
    socket_type = stream
    protocol    = tcp
    wait        = no
    user        = root
    type        = UNLISTED
    port        = 8080
    bind        = 0.0.0.0
    server      = /usr/sbin/chroot   
    server_args = --userspec=1000:1000 /home/ctf /pwn
    # safety options
    per_source  = 5 # the maximum instances of this service per source IP address
    rlimit_cpu  = 20 # the maximum number of CPU seconds that the service may use
    rlimit_as  = 100M # the Address Space resource limit for the service
    #access_times = 8:50-17:10
}

```

skyaf.xinetd文件呢，主要包含了个flag信息，其他的也可以不用改，更换flag的话就改这个配置文件。

```
service skyaf
{
    disable = no
    socket_type = stream
    protocol    = tcp
    wait        = no
    user        = root
    type        = UNLISTED
    port        = 80
    bind        = 0.0.0.0
    server      = /skyaf
    server_args = 127.0.0.1 8080 /home/ctf/sky_token d0g3{f2f82dc8faa12b715d90ff8f205a4cf6}
    # safety options
    per_source  = 5 # the maximum instances of this service per source IP address
    rlimit_cpu  = 20 # the maximum number of CPU seconds that the service may use
    rlimit_as  = 100M # the Address Space resource limit for the service
    #access_times = 8:50-17:10
}

```

然后替换一下/home/ctf/pwn为你的附件就ok啦。



### 基于自己的docker文件来增加skyaf

添加

```
service skyaf
{
    disable = no
    socket_type = stream
    protocol    = tcp
    wait        = no
    user        = root
    type        = UNLISTED
    port        = 80
    bind        = 0.0.0.0
    server      = /skyaf
    server_args = 127.0.0.1 8080 /home/ctf/sky_token d0g3{f2f82dc8faa12b715d90ff8f205a4cf6}
    # safety options
    per_source  = 5 # the maximum instances of this service per source IP address
    rlimit_cpu  = 20 # the maximum number of CPU seconds that the service may use
    rlimit_as  = 100M # the Address Space resource limit for the service
    #access_times = 8:50-17:10
}
```

skyaf.xinetd文件呢，把`d0g3{f2f82dc8faa12b715d90ff8f205a4cf6}` 改成你的flag，主要包含了个flag信息，其他的也可以不用改，更换flag的话就改这个配置文件。将编译好skyaf文件复制到docker文件目录下，且赋予可执行权限。

修改你自己的ctf.xinetd配置文件中的端口为8080，然后在docker启动容器的时候，将其内部的80映射为外部其他端口即可。比如说，我写了个docker-compose.yml

```
version: '3'
services:
  axb_awd_pwn_runner:
    image: axb_pwn_pwnsky
    build: .
    container_name: con_axb_pwn_pwnsky
    ports:
      - 20135:80
```

穿透出去的也就是20135端口了，外部通过访问 20135就可以访问该题了。





## 如何对skyaf已抓取到日志流量进行审计？

这里给的例子是，2021安洵杯比赛中所抓取到的日志流量，在examples/traffic/axb2021/unziped/下，该目录下是解压过以及处理过的，向获取未处理过的文件，请查看examples/traffic/axb2021/zip_download/ 目录下的文件。



抓取到的日志流量都比较多，采用一定手段将其无用的日志文件筛选掉。

1. 筛选提交正确flag的日志文件
2. 根据大小排序，依次人工审计流量 【当然这里也有别人采用文件对比的方式进行筛选，但我感觉人工审计比较准确一些】

### 筛选出提交正确的日志文件

一下命令是需要进入到出现一大批日志文件的目录。

赛选出统计提交对日志文件的总数

```
find . | xargs grep -i "right" | wc -l
```

赛选出提交对的日志文件，并移动到 data目录下

```
mkdir -p data && find . | xargs grep  -l "right" 2>0 | xargs -i cp -L {} ./data
```

进入到筛选出来提交正确的日志目录，在电脑上采用文件大小进行排序，然后两两依次向后对比，主要对比就是所交互的逻辑以及所交互的数据。



### 判断依据

堆栈题型：一般堆栈题型都逻辑，交互逻辑都比较单一，主要对比的是 数据内容，ip地址，提交时间，来进行综合判断。

堆类型：堆类型一般exp交互过程比较多，主要是先对比交互逻辑，依次是数据内容，ip地址，提交时间。

其他类型：其他类型的题也都差不多，从4个点进行对比：交互逻辑、数据内容、ip地址、提交时间。





