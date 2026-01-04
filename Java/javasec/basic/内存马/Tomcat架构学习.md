# Java web 三大件

在讲 Tomcat 之前，我们先讲一讲 Java Web 三大件，也就是 Servlet，Filter，Listener

当 Tomcat 接收到请求时候，依次会经过 Listener -> Filter -> Servlet

## Servlet

### 什么是 Servlet

`浏览器 <-> Tomcat <-> [Filter -> Servlet] <-> Service <-> DAO <-> 数据库`
![](picture/Pasted%20image%2020260104194133.png)
Java Servlet 是运行在 Web 服务器或应用服务器上的程序，它是作为来自 Web 浏览器或其他 HTTP 客户端的请求和 HTTP 服务器上的数据库或应用程序之间的中间层。

它在应用程序中一般在这个位置

把整个过程这样来看会清晰很多

## 处理请求的过程
整个过程大致可以分为三个阶段
1. 建立连接
2. 容器内部流转
3. 业务逻辑处理

 一、建立连接：
 用户输入url后先到达tomcat的 `Connector`的组件，他会负责读取原始的二进制数据流，并将其解析成 HTTP 协议格式。
Connector 会创建两个关键对象：`HttpServletRequest`（装请求数据）和 `HttpServletResponse`（准备装返回数据）。

二、进入Tomcat的流程：
Connector 拿到请求后，会把它交给 **Engine（引擎）**，然后一级一级往下找
- **Engine (引擎)**：Tomcat 的最高层，负责寻找匹配的 **Host（虚拟主机）**。
- **Host (主机)**：比如 `localhost`。它负责寻找具体的 **Context（Web 应用）**。
- **Context (应用)**：比如 `/order`。这就是你的具体项目了。在这里，Tomcat 会根据 `web.xml` 或注解寻找匹配的 **Wrapper（Servlet 包装器）**。

三、进入Web 三大件和业务层
在这一步基本上 Listener 已经工作完了。例如，当 Context 应用启动时，`ContextLoaderListener` 就已经把 Spring 容器初始化好了

然后经过Filter 检查登陆呀，编码统一，检查是否有非法请求之类的一套流程，最后进入 `Servlet`

然后开始调用业务逻辑 让DAO与数据库交互。
最后再原路层层返回
Servlet 把处理好的数据（比如 JSON 或 HTML）塞进 `HttpServletResponse` 对象里。
请求走完 Servlet 以后，还会**反向**经过一遍 Filter
Connector 把 `Response` 对象里的内容包装成 HTTP 报文格式，通过 Socket 发送给浏览器。
浏览器再渲染























