# Java web 三大件

在讲 Tomcat 之前，我们先讲一讲 Java Web 三大件，也就是 Servlet，Filter，Listener

当 Tomcat 接收到请求时候，依次会经过 Listener -> Filter -> Servlet

## 处理请求的过程
为了更好的理解这三大件，我们详细讲处理请求的过程
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
## Servlet

### 什么是 Servlet

`浏览器 <-> Tomcat <-> [Filter -> Servlet] <-> Service <-> DAO <-> 数据库`
![](picture/Pasted%20image%2020260104194133.png)
Java Servlet 是运行在 Web 服务器或应用服务器上的程序，它是作为来自 Web 浏览器或其他 HTTP 客户端的请求和 HTTP 服务器上的数据库或应用程序之间的中间层。

它在应用程序中一般在这个位置

把整个过程这样来看会清晰很多



### Servlet生命周期

1）服务器启动时 (web.xml 中配置 load-on-startup=1，默认为 0)或者第一次请求该 servlet 时，就会初始化一个 Servlet 对象，也就是会执行初始化方法 init(ServletConfig conf)。

2）servlet 对象去处理所有客户端请求，在 service(ServletRequest req，ServletResponse res) 方法中执行

3）服务器关闭时，销毁这个 servlet 对象，执行 destroy() 方法。

4）由 JVM 进行垃圾回收。

## Filter
filter 也称之为过滤器，是对 Servlet 技术的一个强补充，其主要功能是在 HttpServletRequest 到达 Servlet 之前，拦截客户的 HttpServletRequest ，根据需要检查 HttpServletRequest，也可以修改 HttpServletRequest 头和数据； 返回时，在 HttpServletResponse 到达客户端之前，拦截 HttpServletResponse ，根据需要检查 HttpServletResponse，也可以修改 HttpServletResponse 头和数据。
![](picture/Pasted%20image%2020260104200029.png)
- 其实这个地方，我们想办法在 Filter 前自己创建一个 filter 并且将其放到最前面，我们的 filter 就会最先执行，当我们在 filter 中添加恶意代码，就会进行命令执行，这样也就成为了一个内存 Webshell

### 基本工作原理
1、Filter 程序是一个实现了特殊接口的 Java 类，与 Servlet 类似，也是由 Servlet 容器进行调用和执行的。

2、当在 web.xml 注册了一个 Filter 来对某个 Servlet 程序进行拦截处理时，它可以决定是否将请求继续传递给 Servlet 程序，以及对请求和响应消息是否进行修改。

3、当 Servlet 容器开始调用某个 Servlet 程序时，如果发现已经注册了一个 Filter 程序来对该 Servlet 进行拦截，那么容器不再直接调用 Servlet 的 service 方法，而是调用 Filter 的 doFilter 方法，再由 doFilter 方法决定是否去激活 service 方法。

4、但在 Filter.doFilter 方法中不能直接调用 Servlet 的 service 方法，而是调用 FilterChain.doFilter 方法来激活目标 Servlet 的 service 方法，FilterChain 对象时通过 Filter.doFilter 方法的参数传递进来的。

5、只要在 Filter.doFilter 方法中调用 FilterChain.doFilter 方法的语句前后增加某些程序代码，这样就可以在 Servlet 进行响应前后实现某些特殊功能。

6、如果在 Filter.doFilter 方法中没有调用 FilterChain.doFilter 方法，则目标 Servlet 的 service 方法不会被执行，这样通过 Filter 就可以阻止某些非法的访问请求。














