
# Packets & Frames 数据包和帧



数据包和帧是小块数据，当它们形成在一起时，会形成更大的信息或消息。然而，在 OSI 模型中，它们是两个不同的东西。



**数据包**是来自 OSI 模型第 3 层（网络层）的一段数据，包含 ==IP 标头==和有效负载等信息。然而，OSI 模型的第 2 层（数据链路）使用帧，该**帧**封装数据包并添加 MAC 地址等附加信息（无IP）。


#  TCP/IP


**TCP** （或  **简称 T**ransmission **C**ontrol **P**rotocol）
TCP/IP 协议由四层组成

- Application  应用
- Transport  运输
- Internet  互联网
- Network Interface  网络接口


与 OSI 模型的工作方式非常相似，当数据（或数据包）遍历 TCP 模型时，信息会添加到 TCP 模型的每一层。您可能还记得，这个过程被称为封装——这个过程的反面是解封装。


TCP 的一个定义特征是它是  **基于连接**（Connection-based）。即为在传输数据之前，TCP 必须先在客户端和服务器之间建立一条**虚拟的通信通道**（连接）。
这就像打电话一样：

1. 你先拨号
    
2. 对方接听
    
3. 电话接通之后才能说话
    

在 TCP 里，这个过程叫 **三次握手（Three-way Handshake）**。


## 三次握手过程

1. **客户端 → 服务器**：发 SYN 请求，表示“我想和你通信”
    
2. **服务器 → 客户端**：发 SYN-ACK，表示“好的，我同意通信”
    
3. **客户端 → 服务器**：发 ACK，表示“确认收到，可以开始通信”









|                                                                                                                                            |                                                                                                                                                                                                                         |
| ------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Advantages of TCP  <br>TCP 的优势**                                                                                                         | **Disadvantages of TCP  <br>TCP 的缺点**                                                                                                                                                                                   |
| Guarantees the integrity of data.  <br>保证数据的完整性。                                                                                           | Requires a reliable connection between the two devices. If one small chunk of data is not received, then the entire chunk of data cannot be used and must be re-sent.  <br>需要两个设备之间可靠的连接。如果没有收到一小块数据，则无法使用整个数据块，必须重新发送。 |
| Capable of synchronising two devices to prevent each other from being flooded with data in the wrong order.  <br>能够同步两个设备，以防止彼此以错误的顺序充斥数据。 | A slow connection can bottleneck another device as the connection will be reserved on the other device the whole time.  <br>连接速度慢可能会使另一台设备成为瓶颈，因为连接将始终保留在另一台设备上。                                                        |
| Performs a lot more processes for reliability  <br>执行更多流程以提高可靠性                                                                            | TCP is significantly slower than UDP because more work (computing) has to be done by the devices using this protocol.  <br>TCP 比 UDP 慢得多，因为使用此协议的设备必须完成更多的工作（计算）。                                                       |




TCP 数据包包含从封装添加的称为标头的各个信息部分。让我们解释一下下表中的一些关键标题：

  

|   |   |
|---|---|
|Header  页眉|Description  描述|
|Source Port  源端口|This value is the port opened by the sender to send the TCP packet from. This value is chosen randomly (out of the ports from 0-65535 that aren't already in use at the time).  <br>此值是发送方打开的端口，用于从中发送 TCP 数据包。此值是随机选择的（从 0-65535 中当时尚未使用的端口中选择）。|
|Destination Port  目的港|This value is the port number that an application or service is running on the remote host (the one receiving data); for example, a webserver running on port 80. Unlike the source port, this value is not chosen at random.  <br>此值是应用程序或服务在远程主机（接收数据的主机）上运行的端口号;例如，在端口 80 上运行的 Web 服务器。与源端口不同，此值不是随机选择的。|
|Source IP  源 IP|This is the IP address of the device that is sending the packet.  <br>这是发送数据包的设备的 IP 地址。|
|Destination IP  目标 IP|This is the IP address of the device that the packet is destined for.  <br>这是数据包的目的地设备的 IP 地址。|
|Sequence Number  序列号|When a connection occurs, the first piece of data transmitted is given a random number. We'll explain this more in-depth further on.  <br>当连接发生时，传输的第一条数据会被赋予一个随机数。我们将进一步更深入地解释这一点。|
|Acknowledgement Number  确认编号|After a piece of data has been given a sequence number, the number for the next piece of data will have the sequence number + 1. We'll also explain this more in-depth further on.  <br>在为一条数据指定序列号后，下一条数据的编号将具有序列号 + 1。我们还将进一步更深入地解释这一点。|
|Checksum  校验和|This value is what gives TCP integrity. A mathematical calculation is made where the output is remembered. When the receiving device performs the mathematical calculation, the data must be corrupt if the output is different from what was sent.  <br>此值赋予 TCP 完整性。在记住输出的地方进行数学计算。当接收设备执行数学 计算时，如果输出与发送的数据不同，则数据必须损坏。|
|Data  数据|This header is where the data, i.e. bytes of a file that is being transmitted, is stored.  <br>此标头是存储数据（即正在传输的文件的字节）的位置。|
|Flag  旗|This header determines how the packet should be handled by either device during the handshake process. Specific flags will determine specific behaviours, which is what we'll come on to explain below.  <br>此标头确定任一设备在握手过程中应如何处理数据包。特定标志将决定特定行为，这就是我们将在下面解释的内容。|




接下来，我们将继续讨论 三_次握手 -_  用于在两个设备之间建立连接的过程的术语。  三次握手使用一些特殊消息进行通信 - 下表突出显示了主要消息：

  

|   |   |   |
|---|---|---|
|**Step  步**|**Message  消息**|**Description  描述**|
|1|SYN|A SYN message is the initial packet sent by a client during the handshake. This packet is used to initiate a connection and synchronise the two devices together (we'll explain this further later on).  <br>SYN 消息是客户端在握手期间发送的初始数据包。该数据包用于启动连接并将两个设备同步在一起（我们稍后将进一步解释）。|
|2|SYN/ACK  同义词/确认|This packet is sent by the receiving device (server) to acknowledge the synchronisation attempt from the client.  <br>此数据包由接收设备（服务器）发送，以确认来自客户端的同步尝试。|
|3|ACK|The acknowledgement packet can be used by either the client or server to acknowledge that a series of messages/packets have been successfully received.  <br>客户端或服务器可以使用确认数据包来确认已成功接收一系列消息/数据包。|
|4|DATA|Once a connection has been established, data (such as bytes of a file) is sent via the "DATA" message.  <br>建立连接后，数据（例如文件的字节）将通过“DATA”消息发送。|
|5|FIN|This packet is used to _cleanly (properly)_ close the connection after it has been complete.  <br>此数据包用于在连接完成后_干净（正确）_ 关闭连接。|
|#|RST|This packet abruptly ends all communication. This is the last resort and indicates there was some problem during the process. For example, if the service or application is not working correctly, or the system has faults such as low resources.   <br>此数据包会突然结束所有通信。这是最后的手段，表明在此过程中存在一些问题。例如，如果服务或应用程序无法正常工作，或者系统存在资源不足等故障。|



![[67dc0504ffa42cac0579cfeb64227ccb.svg]]






任何发送的数据都会被赋予一个随机数序列，并使用该数字序列进行重建并递增 1。两台计算机必须就相同的编号规则达成一致，才能以正确的顺序发送数据。此顺序通过三个步骤达成一致：

1. SYN - Client: Here's my Initial Sequence Number(ISN) to SYNchronise with (0)  
    SYN - 客户端：这是我的初始序列号 （ISN） 到 SYN 与 （0） 进行时间记录
2. SYN/ACK - Server: Here's my Initial Sequence Number (ISN) to SYNchronise with (5,000), and I ACKnowledge your initial number sequence (0)  
    SYN/ACK - 服务器：这是我要 SYN 记录的初始序列号 （ISN） （5,000），我 现在确认您的初始序列 （0）
3. ACK - Client: I ACKnowledge your Initial Sequence Number (ISN) of (5,000), here is some data that is my ISN+1 (0 + 1)  
    ACK - 客户端：我现在确认您的初始序列号 （ISN） 为 （5,000），这是一些数据，即我的 ISN+1 （0 + 1）

|   |   |   |
|---|---|---|
|Device  装置|**Initial Number Sequence (ISN)  <br>初始编号规则 （ISN）  <br>**|**Final Number Sequence  最终编号序列  <br>**|
|Client (Sender)  客户端（发送方）|0|0 + 1 = 1|
|Client (Sender)  客户端（发送方）|1|1 + 1 = 2|
|Client (Sender)  客户端（发送方）|2|2 + 1 = 3|


为了启动 TCP 连接的关闭，设备将向另一台设备发送“FIN”数据包。当然，使用 TCP， 其他设备也必须确认此数据包。![[d29463eda80fa9e4cbe78b16aa5d9f87.svg]]






# UDP/IP


UDP 是一种  **无状态**协议，不需要两个设备之间持续连接即可发送数据。例如，不会发生三次握手，两个设备之间也没有任何同步。

也就是说，UDP 用于应用程序可以容忍数据丢失的情况（例如视频流或语音聊天）或连接不稳定不是最终目的的情况。UDP 优缺点比较表如下：

  

|   |   |
|---|---|
|**Advantages of UDP  <br>UDP 的优势**|**Disadvantages of UDP  <br>UDP 的缺点**|
|UDP is much faster than TCP.  <br>UDP 比 TCP 快得多。|UDP doesn't care if the data is received or not.  <br>UDP 不关心是否收到数据。|
|UDP leaves the application (user software) to decide if there is any control over how quickly packets are sent.  <br>UDP 让应用程序（用户软件）决定是否可以控制数据包的发送速度。|It is quite flexible to software developers in this sense.  <br>从这个意义上说，它对软件开发人员来说是相当灵活的。|
|UDP does not reserve a continuous connection on a device as TCP does.  <br>UDP 不会像 TCP 那样在设备上保留连续连接。|This means that unstable connections result in a terrible experience for the user.  <br>这意味着不稳定的连接会给用户带来糟糕的体验。|

UDP 数据包比 TCP 数据包简单得多，并且标头更少。但是，这两个协议共享一些标准标头，这些标头如下表所示：

  

|   |   |
|---|---|
|**Header  页眉**|**Description  描述**|
|Time to Live (TTL)  <br>生存时间 （TTL）|This field sets an expiry timer for the packet, so it doesn't clog up your network if it never manages to reach a host or escape!  <br>此字段为数据包设置过期计时器，因此如果数据包永远无法到达主机或逃逸，它不会堵塞您的网络！|
|Source Address  源地址|The IP address of the device that the packet is being sent from, so that data knows where to return to.  <br>发送数据包的设备的 IP 地址，以便数据知道返回到何处。|
|Destination Address  目标地址|The device's IP address the packet is being sent to so that data knows where to travel next.  <br>数据包发送到的设备的 IP 地址，以便数据知道下一步要去哪里。|
|Source Port  源端口|This value is the port that is opened by the sender to send the UDP packet from. This value is randomly chosen (out of the ports from 0-65535 that aren't already in use at the time).  <br>此值是发送方打开的端口，用于从中发送 UDP 数据包。此值是随机选择的（从 0-65535 中当时尚未使用的端口中选择）。|
|Destination Port  目的港|This value is the port number that an application or service is running on the remote host (the one receiving the data); for example, a webserver running on port 80. Unlike the source port, this value is not chosen at random.  <br>此值是应用程序或服务在远程主机（接收数据的主机）上运行的端口号;例如，在端口 80 上运行的 Web 服务器。与源端口不同，此值不是随机选择的。|
|Data  数据|This header is where data, i.e. bytes of a file that is being transmitted, is stored.  <br>该标头是存储数据（即正在传输的文件的字节）的地方。|





UDP 是**无状态**的。连接期间不会发送任何确认。


![[53d459ccda57e5fdea0dafe7e64ffe7c.svg]]


# Ports端口
|   |   |   |
|---|---|---|
|**Protocol  协议**|**Port Number  端口号**|**Description  描述**|
|**F**ile **T**ransfer **P**rotocol (**FTP**)  <br>**F**ile **T**ransfer **P**rotocol （**FTP**）|21|This protocol is used by a file-sharing application built on a client-server model, meaning you can download files from a central location.  <br>该协议由基于客户端-服务器模型构建的文件共享应用程序使用，这意味着您可以从中央位置下载文件。|
|**S**ecure **Sh**ell (**SSH**)  <br>**S**ecure **Sh**ell （**SSH**）|22|This protocol is used to securely login to systems via a text-based interface for management.  <br>该协议用于通过基于文本的界面安全地登录系统进行管理。|
|**H**yper**T**ext Transfer Protocol (**HTTP**)  <br>**H**yper**T**ext 传输协议 （**HTTP**）|80|This protocol powers the World Wide Web (WWW)! Your browser uses this to download text, images and videos of web pages.  <br>该协议为万维网 （WWW） 提供动力！您的浏览器使用它来下载网页的文本、图像和视频。|
|**H**yper**T**ext **T**ransfer **P**rotocol **S**ecure (**HTTPS**)  <br>**H**yper**T**ext **T**ransfer **P**rotocol **S**ecure （**HTTPS**）|443|This protocol does the exact same as above; however, securely using encryption.  <br>该协议的作用与上述完全相同;但是，安全地使用加密。|
|**S**erver **M**essage **B**lock (**SMB**)  <br>**S**erver **M**essage **B** 锁 （**SMB**）|445|This protocol is similar to the File Transfer Protocol (FTP); however, as well as files, SMB allows you to share devices like printers.  <br>该协议类似于文件传输协议 （FTP）;但是，除了文件之外，SMB 还允许您共享打印机等设备。|
|**R**emote **D**esktop **P**rotocol (**RDP**)  <br>**R** 表情 **D**esktop **P**rotocol （**RDP**）|3389|This protocol is a secure means of logging in to a system using a visual desktop interface (as opposed to the text-based limitations of the SSH protocol).  <br>该协议是使用可视化桌面界面登录系统的一种安全方法（与 SSH 协议基于文本的限制相反）。|
[找到列出的 1024 个常用端口的表格](http://www.vmaxx.net/techinfo/ports.htm)


## Introduction to Port Forwarding  端口转发简介


以下面的网络为例。在此网络中，IP 地址为“192.168.1.10”的服务器在端口 80 上运行 Web 服务器。只有此网络上的另外两台计算机才能访问它（这称为 Intranet）。![[326ef12878c2f669ad2374dba3635a44.svg]]

如果管理员希望公众可以访问该网站（使用 Internet），他们必须实现端口转发，如下图所示：
![[eb63570eb9f31d26ebd8207ec08058bc.svg]]



#  VPN

 **V**irtual **P**rivate **N**etwork(简称 **VPN** ）是一种技术，它允许不同网络上的设备通过通过互联网在彼此之间创建专用路径（称为隧道）来安全通信。在此隧道内连接的设备形成自己的专用网络。



例如，只有同一网络（例如企业内）的设备才能直接通信。但是，VPN 允许连接两个办公室。让我们看下图，其中有三个网络：


![[418b5637e02d3fd7494affc2e9cdcc86.svg]]

1. Network #1 (Office #1)  网络 1（办公室 1）
2. Network #2 (Office #2)  网络 2（办公室 2）
3. Network #3 (Two devices connected via a VPN)  
    网络 3（通过 VPN 连接的两台设备）


在网络 #3 上连接的设备仍然是网络 #1 和网络 #2 的一部分，但也会形成一起创建一个专用网络（网络 3），只有通过此 VPN 连接的设备才能通过该网络进行通信。




多年来，VPN 技术不断改进。让我们在下面探讨一些现有的 VPN 技术：

  

|   |   |
|---|---|
|**VPN Technology  VPN 科技**|**Description  描述**|
|PPP|This technology is used by PPTP (explained below) to allow for authentication and provide encryption of data. VPNs work by using a private key and public certificate (similar to **SSH**). A private key & certificate must match for you to connect.  <br>PPTP（如下所述）使用该技术来允许身份验证并提供数据加密。VPN 使用私钥和公共证书（类似于 **SSH**）工作。必须匹配私钥和证书才能连接。<br><br>This technology is not capable of leaving a network by itself (non-routable).  <br>该技术本身无法离开网络（不可路由）。|
|PPTP|The **P**oint-to-**P**oint **T**unneling **P**rotocol (**PPTP**) is the technology that allows the data from PPP to travel and leave a network. **P**oint-to-P oint **T**unneling **P**rotocol （**PPTP**） 是一种允许来自 PPP 的数据传输和离开网络的技术。 <br><br>PPTP is very easy to set up and is supported by most devices. It is, however, weakly encrypted in comparison to alternatives.  <br>PPTP 非常易于设置，并且大多数设备都支持。然而，与替代品相比，它的加密程度较弱。|
|IPSec|Internet Protocol Security (IPsec) encrypts data using the existing **I**nternet **P**rotocol (**IP**) framework.  <br>互联网协议安全 （IPsec） **使用现有的**互联网**网络网络 （****IP**） 框架对数据进行加密。<br><br>IPSec is difficult to set up in comparison to alternatives; however, if successful, it boasts strong encryption and is also supported on many devices.  <br>与替代方案相比，IPSec 很难设置;但是，如果成功，它拥有强大的加密功能，并且许多设备也支持它。|


# LAN Networking Devices  局域网网络设备


**What is a Router?  什么是路由器？**
路由器的工作是连接网络并在它们之间传递数据。它通过使用路由来做到这一点（因此得名路由器！

路由是给数据跨网络传输过程的标签。路由涉及在网络之间创建路径，以便可以成功传送此数据。路由器在 OSI 模型的第 3 层运行。它们通常具有交互式界面（例如网站或控制台），允许管理员配置各种规则，例如端口转发或防火墙。




当设备通过许多路径连接时，路由非常有用，例如在下面的示例图中，其中采用最佳路径：
![[a47c8c191d308906d91f680a5811e492.svg]]

**什么是交换机**

交换机是一种专用网络设备，负责提供连接到多个设备的方法。交换机可以使用以太网电缆为许多设备（从 3 到 63 个）提供便利。
交换机可以在 OSI 模型的第 2 层和第 3 层运行。然而，从某种意义上说，这些是排他性的，因为第 2 层交换机不能在第 3 层运行。

![[3a3ae0931ed3c36abad80b3cde33dfeb.svg]]

一种称为 **VLAN** （**V**irtual **L**ocal **A**rea **N**etwork） 的技术允许虚拟地拆分网络内的特定设备。这种分裂意味着他们都可以从互联网连接等方面受益，但被分开对待。这种网络分离提供了安全性，因为这意味着现有的规则决定了特定设备之间的通信方式。下图说明了这种隔离：


![[008ae2ff118eeb5680db5fa478fd925d.svg]]

