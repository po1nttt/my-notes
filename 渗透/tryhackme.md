
# 被动侦察

|Purpose  目的|Commandline Example  命令行示例|
|---|---|
|Lookup WHOIS record  查找 WHOIS 记录|`whois tryhackme.com`|
|Lookup DNS A records  <br>查找 DNS A 记录|`nslookup -type=A tryhackme.com`|
|Lookup DNS MX records at DNS server  <br>在 DNS 服务器上查找 DNS MX 记录|`nslookup -type=MX tryhackme.com 1.1.1.1`|
|Lookup DNS TXT records  <br>查找 DNS TXT 记录|`nslookup -type=TXT tryhackme.com`|
|Lookup DNS A records  <br>查找 DNS A 记录|`dig tryhackme.com A`|
|Lookup DNS MX records at DNS server  <br>在 DNS 服务器上查找 DNS MX 记录|`dig @1.1.1.1 tryhackme.com MX`|
|Lookup DNS TXT records  <br>查找 DNS TXT 记录|`dig tryhackme.com TXT`|
两种公开可用的服务 [DNSDumpster](https://dnsdumpster.com/) 和 [Shodan.io](https://www.shodan.io/)。


# 主动侦察

## Telnet

假设我们想发现有关 Web 服务器的更多信息，在端口 80 上侦听。我们通过端口 80 连接到服务器，然后使用 HTTP 协议进行通信。您无需深入研究 HTTP 协议;您只需发出 `GET / HTTP/1.1` 即可。要指定默认索引页以外的内容，可以发出 `GET /page.html HTTP/1.1`，这将请求 `page.html`。我们还向远程 Web 服务器指定了我们要使用 HTTP 1.1 版进行通信。要获得有效的响应，而不是错误，您需要为主机主机输入一些值 `：示例并`按两次 Enter 键。执行这些步骤将提供请求的索引页。

![[Pasted image 20251109003632.png]]


有意思的是，我们试了一下fa1lsnow的服务器呀~
![[Pasted image 20251109003704.png]]
有意思，感觉可以打一下~

## netcat


![[Pasted image 20251109004659.png]]
![[Pasted image 20251109004706.png]]



# nmap


This room covered the following types of scans.  
这个房间涵盖了以下类型的扫描。

|Port Scan Type  端口扫描类型|Example Command  示例命令|
|---|---|
|TCP Null Scan  TCP 的空扫描|`sudo nmap -sN MACHINE_IP`|
|TCP FIN Scan  TCP 的鳍扫描|`sudo nmap -sF MACHINE_IP`|
|TCP Xmas Scan  TCP 的圣诞扫描|`sudo nmap -sX MACHINE_IP`|
|TCP Maimon Scan  TCP 的迈蒙扫描 Maimon 扫描|`sudo nmap -sM MACHINE_IP`|
|TCP ACK Scan  TCP 的 ACK 扫描|`sudo nmap -sA MACHINE_IP`|
|TCP Window Scan  TCP 的窗口扫描|`sudo nmap -sW MACHINE_IP`|
|Custom TCP Scan  自定义 TCP 扫描|`sudo nmap --scanflags URGACKPSHRSTSYNFIN MACHINE_IP`|
|Spoofed Source IP  欺骗源 IP|`sudo nmap -S SPOOFED_IP MACHINE_IP`|
|Spoofed MAC Address  欺骗性 MAC 地址|`--spoof-mac SPOOFED_MAC`|
|Decoy Scan  诱饵扫描|`nmap -D DECOY_IP,ME MACHINE_IP`|
|Idle (Zombie) Scan  <br>空闲（ 僵尸 ）扫描|`sudo nmap -sI ZOMBIE_IP MACHINE_IP`|
|Fragment IP data into 8 bytes  <br>将 IP 数据分片为 8 个字节|`-f`|
|Fragment IP data into 16 bytes  <br>将 IP 数据分片为 16 个字节|`-ff`|

|Option  选择|Purpose  目的|
|---|---|
|`--source-port PORT_NUM`|specify source port number  <br>指定源端口号|
|`--data-length NUM`|append random data to reach given length  <br>附加随机数据以达到给定长度|

These scan types rely on setting TCP flags in unexpected ways to prompt ports for a reply. Null, FIN, and Xmas scan provoke a response from closed ports, while Maimon, ACK, and Window scans provoke a response from open and closed ports.  
这些扫描类型依赖于以意外方式设置 TCP 标志来提示端口进行回复。空、FIN 和 Xmas 扫描会引发来自关闭端口的响应，而 Maimon、ACK 和 Window 扫描会引发来自打开和关闭端口的响应。

|Option  选择|Purpose  目的|
|---|---|
|`--reason`|explains how Nmap made its conclusion  <br>解释了 Nmap 是如何得出结论的|
|`-v`|verbose  详细|
|`-vv`|very verbose  非常冗长|
|`-d`|debugging  调试|
|`-dd`|more details for debugging  <br>调试的更多详细信息|

# 提权
### hostname  主机名

The `hostname` command will return the hostname of the target machine. Although this value can easily be changed or have a relatively meaningless string (e.g. Ubuntu-3487340239), in some cases, it can provide information about the target system’s role within the corporate network (e.g. SQL-PROD-01 for a production SQL server).  
`hostname` 命令将返回目标计算机的主机名。尽管此值可以轻松更改或具有相对无意义的字符串（例如 Ubuntu-3487340239），但在某些情况下，它可以提供有关目标系统在公司网络中的角色的信息（生产 SQL 服务器的 e.g. SQL-PROD-01）。

  

### uname -a

Will print system information giving us additional detail about the kernel used by the system. This will be useful when searching for any potential kernel vulnerabilities that could lead to privilege escalation.  
将打印系统信息，为我们提供有关系统使用的内核的更多详细信息。这在搜索可能导致权限升级的任何潜在内核漏洞时非常有用。

  

### /proc/version  /proc/版本

The proc filesystem (procfs) provides information about the target system processes. You will find proc on many different Linux flavours, making it an essential tool to have in your arsenal.  
proc 文件系统 （procfs） 提供有关目标系统进程的信息。您会在许多不同的 Linux 风格上找到 proc，使其成为您武器库中必不可少的工具。

Looking at `/proc/version` may give you information on the kernel version and additional data such as whether a compiler (e.g. GCC) is installed.  
查看 `/proc/version` 可能会为您提供有关内核版本和其他数据的信息，例如是否安装了编译器（例如 GCC）。

  

### /etc/issue  /etc/问题

Systems can also be identified by looking at the `/etc/issue` file. This file usually contains some information about the operating system but can easily be customized or changed. While on the subject, any file containing system information can be customized or changed. For a clearer understanding of the system, it is always good to look at all of these.  
也可以通过查看 `/etc/issue` 文件来识别系统 。该文件通常包含有关作系统的一些信息，但可以轻松自定义或更改。在主题上，任何包含系统信息的文件都可以自定义或更改。为了更清楚地了解系统，查看所有这些总是好的。

### ps Command  ps 命令

The `ps` command is an effective way to see the running processes on a Linux system. Typing `ps` on your terminal will show processes for the current shell.  
`ps` 命令是查看 Linux 系统上正在运行的进程的有效方法。在终端上键入 `ps` 将显示当前 shell 的进程。

The output of the `ps` (Process Status) will show the following;  
`ps` （进程状态）的输出将显示以下内容;

- PID: The process ID (unique to the process)  
    PID：进程 ID（对进程唯一）
- TTY: Terminal type used by the user  
    TTY：用户使用的终端类型
- Time: Amount of CPU time used by the process (this is NOT the time this process has been running for)  
    时间：进程使用的 CPU 时间量（这不是此进程运行的时间）
- CMD: The command or executable running (will NOT display any command line parameter)  
    CMD：正在运行的命令或可执行文件（不会显示任何命令行参数）

The “ps” command provides a few useful options.  
“ps”命令提供了一些有用的选项。

- `ps -A`: View all running processes  
    `ps -A`：查看所有正在运行的进程
- `ps axjf`: View process tree (see the tree formation until `ps axjf` is run below)  
    `ps axjf`：查看进程树（请参阅下面的树形成，直到`运行 ps axjf`）

![](https://assets.tryhackme.com/additional/imgur/xsbohSd.png)  

- `ps aux`: The `aux` option will show processes for all users (a), display the user that launched the process (u), and show processes that are not attached to a terminal (x). Looking at the ps aux command output, we can have a better understanding of the system and potential vulnerabilities.  
    `ps aux`：`aux` 选项将显示所有用户的进程 （a），显示启动该进程的用户 （u），并显示未附加到终端的进程 （x）。查看 ps aux 命令输出，我们可以更好地了解系统和潜在漏洞。  
    

### env  环境

The `env` command will show environmental variables.  
`env` 命令将显示环境变量。

  

![](https://assets.tryhackme.com/additional/imgur/LWdJ8Fw.png)

  

The PATH variable may have a compiler or a scripting language (e.g. Python) that could be used to run code on the target system or leveraged for privilege escalation.  
PATH 变量可能具有编译器或脚本语言（例如 Python），可用于在目标系统上运行代码或用于权限提升。

  

### sudo -l

The target system may be configured to allow users to run some (or all) commands with root privileges. The `sudo -l` command can be used to list all commands your user can run using `sudo`  
目标系统可以配置为允许用户以 root 权限运行部分（或全部）命令。`sudo -l` 命令可用于列出用户可以使用 `sudo` 运行的所有命令.

  

ls

One of the common commands used in Linux is probably `ls`  
Linux 中使用的常用命令之一可能是 `ls`.

  

While looking for potential privilege escalation vectors, please remember to always use the `ls` command with the `-la` parameter. The example below shows how the “secret.txt” file can easily be missed using the `ls` or `ls -l` commands.  
在寻找潜在的权限提升向量时，请记住始终将 `ls` 命令与 `-la` 参数一起使用。下面的示例显示了如何使用 `ls` 或 `ls -l` 命令轻松遗漏“secret.txt”文件。

![](https://assets.tryhackme.com/additional/imgur/2jOtOat.png)  

  

  

### Id  同上

The `id` command will provide a general overview of the user’s privilege level and group memberships.  
`id` 命令将提供用户权限级别和组成员身份的总体概述。

  

It is worth remembering that the `id` command can also be used to obtain the same information for another user as seen below.  
值得记住的是，`id` 命令也可用于为其他用户获取相同的信息，如下所示。

  

![](https://assets.tryhackme.com/additional/imgur/YzfJliG.png)

  

  

### /etc/passwd

Reading the `/etc/passwd` file can be an easy way to discover users on the system.  
读取 `/etc/passwd` 文件是发现系统上用户的简单方法。

  

![](https://assets.tryhackme.com/additional/imgur/r6oYOEi.png)

  

While the output can be long and a bit intimidating, it can easily be cut and converted to a useful list for brute-force attacks.  
虽然输出可能很长并且有点吓人，但它很容易被剪切并转换为暴力攻击的有用列表。

![](https://assets.tryhackme.com/additional/imgur/cpS2U93.png)

  

Remember that this will return all users, some of which are system or service users that would not be very useful. Another approach could be to grep for “home” as real users will most likely have their folders under the “home” directory.  
请记住，这将返回所有用户，其中一些是系统或服务用户，不会很有用。另一种方法是对“home”进行 grep，因为真实用户很可能将他们的文件夹放在“home”目录下。

  

![](https://assets.tryhackme.com/additional/imgur/psxE6V4.png)

  

### history  历史

Looking at earlier commands with the `history` command can give us some idea about the target system and, albeit rarely, have stored information such as passwords or usernames.  
使用 `history` 命令查看早期命令可以让我们对目标系统有所了解，并且尽管很少存储密码或用户名等信息。

  

### ifconfig

The target system may be a pivoting point to another network. The `ifconfig` command will give us information about the network interfaces of the system. The example below shows the target system has three interfaces (eth0, tun0, and tun1). Our attacking machine can reach the eth0 interface but can not directly access the two other networks.  
目标系统可能是另一个网络的枢轴点。`ifconfig` 命令将为我们提供有关系统网络接口的信息。下面的示例显示目标系统有三个接口（eth0、tun0 和 tun1）。我们的攻击机器可以到达 eth0 接口，但不能直接访问另外两个网络。

  

![](https://assets.tryhackme.com/additional/imgur/hcdZnwK.png)

  

  

This can be confirmed using the `ip route` command to see which network routes exist.  
这可以使用 `ip route` 命令来确认，以查看存在哪些网络路由。

  

![](https://assets.tryhackme.com/additional/imgur/PSrmz5O.png)

  

  

### netstat  网络统计

Following an initial check for existing interfaces and network routes, it is worth looking into existing communications. The `netstat` command can be used with several different options to gather information on existing connections.  
在对现有接口和网络路由进行初步检查之后，值得研究现有通信。`netstat` 命令可以与多个不同的选项一起使用，以收集有关现有连接的信息。

  

- `netstat -a`: shows all listening ports and established connections.  
    `netstat -a`：显示所有侦听端口和已建立的连接。
- `netstat -at` or `netstat -au` can also be used to list TCP or UDP protocols respectively.  
    `netstat -at` 或 `netstat -au` 也可用于分别列出 TCP 或 UDP 协议。
- `netstat -l`: list ports in “listening” mode. These ports are open and ready to accept incoming connections. This can be used with the “t” option to list only ports that are listening using the TCP protocol (below)  
    `netstat -l`：列出处于“侦听”模式的端口。这些端口是打开的，可以接受传入的连接。这可以与“t”选项一起使用，以仅列出使用 TCP 协议侦听的端口（如下）

  

![](https://assets.tryhackme.com/additional/imgur/BbLdyrr.png)

  

- `netstat -s`: list network usage statistics by protocol (below) This can also be used with the `-t` or `-u` options to limit the output to a specific protocol.  
    `netstat -s`：按协议列出网络使用统计信息（如下）这也可以与 `-t` 或 `-u` 选项一起使用，以将输出限制为特定协议。

  

![](https://assets.tryhackme.com/additional/imgur/mc8OWP0.png)

  

- `netstat -tp`: list connections with the service name and PID information.  
    `netstat -tp`：列出带有服务名称和 PID 的连接 信息。

  

![](https://assets.tryhackme.com/additional/imgur/fDYQwbW.png)

  

This can also be used with the `-l` option to list listening ports (below)  
这也可以与 `-l` 选项一起使用以列出侦听端口（如下）

  

![](https://assets.tryhackme.com/additional/imgur/JK7DNv0.png)

  

We can see the “PID/Program name” column is empty as this process is owned by another user.  
我们可以看到“PID/程序名称”列为空，因为此进程由另一个用户拥有。

Below is the same command run with root privileges and reveals this information as 2641/nc (netcat)  
下面是以 root 权限运行的相同命令，并将此信息显示为 2641/nc （netcat）

![](https://assets.tryhackme.com/additional/imgur/FjZHqlY.png)`   `

- `netstat -i`: Shows interface statistics. We see below that “eth0” and “tun0” are more active than “tun1”.  
    `netstat -i`：显示接口统计信息。我们在下面看到“eth0”和“tun0”比“tun1”更活跃。

![](https://assets.tryhackme.com/additional/imgur/r6IjpmZ.png)

  

  

The `netstat` usage you will probably see most often in blog posts, write-ups, and courses is `netstat -ano` which could be broken down as follows;  
您可能在博客文章、文章和课程中最常看到的 `netstat` 用法是 `netstat -ano` ，可以细分如下;

- `-a`: Display all sockets  
    `-a`：显示所有套接字
- `-n`: Do not resolve names  
    `-n`：不解析名称
- `-o`: Display timers  
    `-o`：显示定时器

  

![](https://assets.tryhackme.com/additional/imgur/UxzLBRw.png)

  

  

### find Command  find 命令

Searching the target system for important information and potential privilege escalation vectors can be fruitful. The built-in “find” command is useful and worth keeping in your arsenal.  
在目标系统中搜索重要信息和潜在的权限提升向量可能会很有成效。内置的“查找”命令非常有用，值得保留在您的武器库中。

Below are some useful examples for the “find” command.  
以下是“find”命令的一些有用示例。

**Find files:   查找文件：**

- `find . -name flag1.txt`: find the file named “flag1.txt” in the current directory  
    `find .-name flag1.txt`：在当前目录中找到名为“flag1.txt”的文件
- `find /home -name flag1.txt`: find the file names “flag1.txt” in the /home directory  
    `find /home -name flag1.txt`：在 /home 目录下找到文件名“flag1.txt”
- `find / -type d -name config`: find the directory named config under “/”  
    `find / -type d -name config`：在“/”下找到名为 config 的目录
- `find / -type f -perm 0777`: find files with the 777 permissions (files readable, writable, and executable by all users)  
    `find / -type f -perm 0777`：查找具有 777 权限的文件（所有用户都可读、可写和可执行的文件）
- `find / -perm a=x`: find executable files  
    `find / -perm a=x`：查找可执行文件
- `find /home -user frank`: find all files for user “frank” under “/home”  
    `find /home -user frank`：在“/home”下查找用户“Frank”的所有文件
- `find / -mtime 10`: find files that were modified in the last 10 days  
    `find / -mtime 10`：查找最近 10 天内修改过的文件
- `find / -atime 10`: find files that were accessed in the last 10 day  
    `find / -atime 10`：查找过去 10 天内访问过的文件
- `find / -cmin -60`: find files changed within the last hour (60 minutes)  
    `find / -cmin -60`：查找过去一小时（60 分钟）内更改的文件
- `find / -amin -60`: find files accesses within the last hour (60 minutes)  
    `find / -amin -60`：查找过去一小时（60 分钟）内访问的文件
- `find / -size 50M`: find files with a 50 MB size  
    `find / -size 50M`：查找大小为 50 MB 的文件

This command can also be used with (+) and (-) signs to specify a file that is larger or smaller than the given size.  
此命令还可以与 （+） 和 （-） 符号一起使用，以指定大于或小于给定大小的文件。

![](https://assets.tryhackme.com/additional/imgur/pSMfoz4.png)

The example above returns files that are larger than 100 MB. It is important to note that the “find” command tends to generate errors which sometimes makes the output hard to read. This is why it would be wise to use the “find” command with “-type f 2>/dev/null” to redirect errors to “/dev/null” and have a cleaner output (below).  
上面的示例返回大于 100 MB 的文件。重要的是要注意，“find”命令往往会产生错误，有时会使输出难以阅读。这就是为什么将“find”命令与“-type f 2>/dev/null”一起使用以将错误重定向到“/dev/null”并获得更干净的输出（如下）是明智的。

![](https://assets.tryhackme.com/additional/imgur/UKYSdE3.png)

  

Folders and files that can be written to or executed from:  
可以写入或执行的文件夹和文件：

- `find / -writable -type d 2>/dev/null` : Find world-writeable folders  
    `find / -writable -type d 2>/dev/null` ：查找世界可写文件夹
- `find / -perm -222 -type d 2>/dev/null`: Find world-writeable folders  
    `find / -perm -222 -type d 2>/dev/null` ：查找世界可写文件夹
- `find / -perm -o w -type d 2>/dev/null`: Find world-writeable folders  
    `find / -perm -o w -type d 2>/dev/null` ：查找世界可写文件夹

The reason we see three different “find” commands that could potentially lead to the same result can be seen in the manual document. As you can see below, the perm parameter affects the way “find” works.  
我们看到三个不同的“查找”命令可能导致相同结果的原因可以在手册文档中看到。如下所示，perm 参数会影响“查找”的工作方式。

![](https://assets.tryhackme.com/additional/imgur/qb0klHH.png)  

- `find / -perm -o x -type d 2>/dev/null` : Find world-executable folders  
    `find / -perm -o x -type d 2>/dev/null` ：查找世界可执行文件夹

Find development tools and supported languages:  
查找开发工具和支持的语言：

- `find / -name perl*`
- `find / -name python*`
- `find / -name gcc*`

Find specific file permissions:  
查找特定文件权限：

Below is a short example used to find files that have the SUID bit set. The SUID bit allows the file to run with the privilege level of the account that owns it, rather than the account which runs it. This allows for an interesting privilege escalation path,we will see in more details on task 6. The example below is given to complete the subject on the “find” command.  
下面是一个用于查找设置了 SUID 位的文件的简短示例。SUID 位允许文件以拥有它的帐户的权限级别运行，而不是运行它的帐户。这允许一个有趣的权限升级路径，我们将在任务 6 中看到更多详细信息。下面的示例用于完成“find”命令的主题。

- `find / -perm -u=s -type f 2>/dev/null`: Find files with the SUID bit, which allows us to run the file with a higher privilege level than the current user.  
    `find / -perm -u=s -type f 2>/dev/null` ：查找带有 SUID 位的文件，这允许我们以比当前用户更高的权限级别运行文件。

### General Linux Commands  
常规 Linux 的 命令

As we are in the Linux realm, familiarity with Linux commands, in general, will be very useful. Please spend some time getting comfortable with commands such as `find`, `locate`, `grep`, `cut`, `sort`, etc.  
正如我们在 Linux 领域，熟悉 Linux 命令，一般来说，会非常有用。请花一些时间熟悉诸如`查找` 、 `定位` 、`grep`、 `剪切` 、 `排序`等命令。



## 自动枚举工具
目标系统的环境将影响您将能够使用的工具。例如，如果目标系统上未安装用 Python 编写的工具，您将无法运行该工具。这就是为什么最好熟悉一些工具而不是拥有单一的首选工具。

- **LinPeas**: [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)  
    **豌豆** ：[https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
- **LinEnum:** [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)  
    LinEnum：https://github.com/rebootuser/LinEnum[](https://github.com/rebootuser/LinEnum)
- **LES (Linux Exploit Suggester):** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)  
    **LES（Linux 漏洞利用建议器）：**[https://github.com/mzet-/ linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
- **Linux Smart Enumeration:** [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)  
    **Linux 智能枚举：**[https://github.com/diego-treitos/ linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
- **Linux Priv Checker:** [https://github.com/linted/linuxprivchecker](https://github.com/linted/linuxprivchecker)  
    **Linux Priv Checker：**[https://github.com/linted/linuxprivchecker](https://github.com/linted/linuxprivchecker)

