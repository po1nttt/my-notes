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

2、当在 web.xml 注册了一个 Filter 来对某个 Servlet 程序进行拦截处理时，它可以决定是否将请求继续传递给 Servlet 程序，以及对请求和响应消息是否进行修改。换句话说：在 `web.xml` 里，你可以为不同的 Filter 定义不同的“捕获网”。

3、当 Servlet 容器开始调用某个 Servlet 程序时，如果发现已经注册了一个 Filter 程序来对该 Servlet 进行拦截，那么容器不再直接调用 Servlet 的 service 方法，而是调用 Filter 的 doFilter 方法，再由 doFilter 方法决定是否去激活 service 方法。

4、但在 Filter.doFilter 方法中不能直接调用 Servlet 的 service 方法，而是调用 FilterChain.doFilter 方法，一层一层走完 FilterChain 后，最终激活目标 Servlet 的 service 方法，FilterChain 对象是通过 Filter.doFilter 方法的参数传递进来的。

5、只要在 Filter.doFilter 方法中调用 FilterChain.doFilter 方法的语句前后增加某些程序代码，这样就可以在 Servlet 进行响应前后实现某些特殊功能。

6、如果在 Filter.doFilter 方法中没有调用 FilterChain.doFilter 方法，则目标 Servlet 的 service 方法不会被执行，这样通过 Filter 就可以阻止某些非法的访问请求。

7、`FilterChain.doFilter` 是一个阻塞调用，代码执行到`FilterChain.doFilter`开始向下传递请求，一直到 `Servlet`执行完，然后返回结果到 `FilterChain.doFilter`接着执行。这也解释了为什么Filter中可以同时实现“请求预处理”和“响应后处理”


### Filter 的生命周期

与 servlet 一样，Filter 的创建和销毁也由 Web 容器负责。Web 应用程序启动时，Web 服务器将创建 Filter 的实例对象，并调用其 init() 方法，读取 web.xml 配置，完成对象的初始化功能，从而为后续的用户请求作好拦截的准备工作（filter 对象只会创建一次，init 方法也只会执行一次）。开发人员通过init方法的参数，可获得代表当前filter配置信息的FilterConfig对象。 Filter 对象创建后会驻留在内存，当 Web 应用移除或服务器停止时才销毁。`destory()` 在 Web 容器卸载 Filter 对象之前被调用。该方法在 Filter 的生命周期中仅执行一次。在这个方法中，可以释放过滤器使用的资源。

先去 web.xml 里面找接口 —> `init()` —> 执行 `doFilter()` —> `destory()`

### Filter链
当多个 Filter 同时存在的时候，组成了 Filter 链。Web 服务器根据 Filter 在 web.xml 文件中的注册顺序，决定先调用哪个 Filter。当第一个 Filter 的 doFilter 方法被调用时，web服务器会创建一个代表 Filter 链的 FilterChain 对象传递给该方法，通过判断 FilterChain 中是否还有 Filter 决定后面是否还调用 Filter。
![](picture/Pasted%20image%2020260104202330.png)
## Listener
Java Web 开发中的监听器（Listener）就是 Application、Session 和 Request 三大对象创建、销毁或者往其中添加、修改、删除属性时自动执行代码的功能组件。

ServletContextListener：对Servlet上下文的创建和销毁进行监听； ServletContextAttributeListener：监听 Servlet 上下文属性的添加、删除和替换；

HttpSessionListener：对 Session 的创建和销毁进行监听。Session 的销毁有两种情况，一个中 Session 超时，还有一种是通过调用 Session 对象的 invalidate() 方法使 session 失效。

HttpSessionAttributeListener：对 Session 对象中属性的添加、删除和替换进行监听；

ServletRequestListener：对请求对象的初始化和销毁进行监听； ServletRequestAttributeListener：对请求对象属性的添加、删除和替换进行监听。

可以使用监听器监听客户端的请求、服务端的操作等。通过监听器，可以自动出发一些动作，比如监听在线的用户数量，统计网站访问量、网站访问监控等。

# Tomcat基础
## 什么是Tomcat
把Tomcat对标Apache来看会更好的理解Tomcat
Apache是反向代理，一般挡在Tomcat的前面，可以把服务器保护在后面。
从功能上来讲Apache主要是处理图片 css js这些静态资源，看到什么jpg html什么的 他会从自己的本地磁盘拿给用户，看到什么.do .jsp他就会交给擅长处理这些java代码的Tomcat

他是帮助Apache来动态解析这些java代码的
所以从本质上来讲，Apache是web服务器只明白前端三件套，Tomcat是web容器，看得懂html和java，但是他拥有JVM，用户有处理jsp中的java代码的能力，执行java后，算出结果（比如 JSON 数据或 HTML 片段），吐给前面的 Apache，再由Apache来包装成http返回客户端。


### Tomcat和Servlet的关系

我们根据上面的基础知识可以知道 **Tomcat 是 Web 应用服务器，是一个 Servlet/JSP 容器**，而 Servlet 容器从上到下分别是 Engine、Host、Context、Wrapper。

在 Tomcat 中 Wrapper 代表一个独立的 servlet 实例， StandardWrapper 是 Wrapper 接口的标准实现类（StandardWrapper 的主要任务就是载入 Servlet 类并且进行实例化），同时其从 ContainerBase 类继承过来，表示他是一个容器，只是他是最底层的容器，不能再含有任何的子容器了，且其父容器只能是 context。而我们在也就是需要在这里去载入我们自定义的 Servlet 加载我们的内存马。

# Tomcat架构原理
Tomcat 的框架如下图所示，主要有 server、service、connector、container 四个部分
![](picture/Pasted%20image%2020260104210749.png)


## Server
 就是Tomcat本体，它要能够提供一个接口让其它程序能够访问到这个 Service 集合、同时要维护它所包含的所有 Service 的生命周期，包括如何初始化、如何结束服务、如何找到别人要访问的 Service。
一个 Server 可以包含多个 Service。

## Service 
是一个逻辑组合。它的核心作用是将“接收请求”的组件和“处理请求”的组件绑定在一起，同时会初始化它下面的其它组件，在 Connector 和 Container 外面多包一层，把它们组装在一起，向外面提供服务，一个 Service 可以设置多个 Connector，但是只能有一个 Container 容器
Tomcat 中 Service 接口的标准实现类是 StandardService ，它不仅实现了 Service 借口同时还实现了 Lifecycle 接口，这样它就可以控制它下面的组件的生命周期了


在每个 Service 内部，有Connector（连接器）和Container（容器）


## Connector
负责监听端口（如 8080），接收 Socket 连接，将原始的字节流解析成  Request 和 Response 对象分别用于和请求端交换数据，然后会产生一个线程来处理这个请求并把产生的 Request 和 Response 对象传给处理这个请求的线程，处理这个请求的线程就是 Container 组件要做的事了。
根据运行的逻辑图，我们也能看到连接器 connector 主要有三个功能：
> socket 通信
> 解析处理应用层协议，如将 socket 连接封装成 request 和 response 对象，后续交给 Container 来处理  
将 Request 转换为 ServletRequest，将 Response 转换为 ServletResponse
其中 Tomcat 设计了三个组件，其负责功能如下：

- EndPoint: 负责网络通信，将字节流传递给 Processor；
- Processor: 负责处理字节流生成 Tomcat Request 对象，将 Tomcat Request 对象传递给 Adapter；
- Adapter: 负责将 Tomcat Request 对象转化成 ServletRequest 对象，传递给容器。****


## Adapter组件
由于协议的不同，Tomcat 定义了自己的 Request 类来存放请求信息，但是这个不是标准的 ServletRequest。于是需要使用 Adapter 将 Tomcat Request 对象转成 ServletRequest 对象，然后就能调用容器的 service 方法。

简而言之，Endpoint 接收到 Socket 连接后，生成一个 SocketProcessor 任务提交到线程池进行处理，SocketProcessor 的 run 方法将调用 Processor 组件进行应用层协议的解析，Processor 解析后生成 Tomcat Request 对象，然后会调用 Adapter 的 Service 方法，方法内部通过如下代码将 Request 请求传递到容器中。
```java
connector.getService().getContainer().getPipeline().getFirst().invoke(request, response);
```
一个总的 Tomcat Connector 功能如图所示
![](picture/Pasted%20image%2020260104212038.png)
## `Container`
负责处理业务逻辑。它里面运行的就是 Servlet。由 Servlet 具体负责处理 Request 请求，对应下图中的 servlet 容器。
![](picture/Pasted%20image%2020260104211221.png)

Container（又名Catalina）用于处理Connector发过来的servlet连接请求，它是容器的父接口，所有子容器都必须实现这个接口，Container 容器的设计用的是典型的责任链的设计模式，它有四个子容器组件构成，分别是：Engine、Host、Context、Wrapper，这四个组件不是平行的，而是父子关系，Engine 包含 Host，Host 包含 Context，Context 包含 Wrapper。

- Engine: 最顶层容器组件，可以包含多个 Host。实现类为 `org.apache.catalina.core.StandardEngine`
- Host: 代表一个虚拟主机，每个虚拟主机和某个域名 Domain Name 相匹配，可以包含多个 Context。实现类为 `org.apache.catalina.core.StandardHost`
- Context: 一个 Context 对应于一个 Web 应用，可以包含多个 Wrapper。实现类为 `org.apache.catalina.core.StandardContext`
- Wrapper: 一个 Wrapper 对应一个 Servlet。负责管理 Servlet ，包括 Servlet 的装载、初始化、执行以及资源回收。实现类为 `org.apache.catalina.core.StandardWrapper`

通常一个 Servlet class 对应一个 Wrapper，如果有多个 Servlet 就可以定义多个 Wrapper，如果有多个 Wrapper 就要定义一个更高的 Container。

例如，a.com和b.com分别对应两个Host
![](picture/Pasted%20image%2020260104212228.png)
每一个 Context 都有唯一的 路由。这里的 路由 不是指 servlet 绑定的 WebServlet 地址，而是指独立的一个 Web 应用地址。就好比 Tomat 默认的 根路由 `/` 和 `/manager` 就是两个不同的 web 应用，所以对应两个不同的 Context。要添加 Context 需要在 server.xml 中配置 docbase。

如下图所示， 在一个 web 应用中创建了 2 个 servlet 服务，WebServlet 地址分别是 /Demo1 和 /Demo2 。 因为它们属于同一个 Web 应用所以 Context 一样，但访问地址不一样所以 Wrapper 不一样。 /manager 访问的 Web 应用是 Tomcat 默认的管理页面，是另外一个独立的 web 应用， 所以 Context 与前两个不一样。
![](picture/Pasted%20image%2020260104212444.png)
# Tomcat的类加载机制
由于Tomcat中有多个WebApp  同时要确保之间相互隔离，所以Tomcat的类加载机制也不是传统的双亲委派

Tomcat 自定义的类加载器 WebAppClassloader 为了确保隔离多个 WebApp 之间相互隔离，所以打破了双亲委托机制。每个 WebApp 用一个独有的 ClassLoader 实例来优先处理加载。它首先尝试自己加载某个类，如果找不到再交给父类加载器，其目的是优先加载 WEB 应用自己定义的类。

同时为了防止 WEB 应用自己的类覆盖 JRE 的核心类，在本地 WEB 应用目录下查找之前，先使用 ExtClassLoader（使用双亲委托机制）去加载，这样既打破了双亲委托，同时也能安全加载类。

说白了就是核心类先用双亲委派，找最上面的类加载器进行加载
但是核心库里面没有，不会像双亲委派从上往下找，而是本地优先，然后往上找，达到隔离的目的


[Java内存马系列-01-基础内容学习 | Drunkbaby's Blog](https://drun1baby.top/2022/08/19/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-01-%E5%9F%BA%E7%A1%80%E5%86%85%E5%AE%B9%E5%AD%A6%E4%B9%A0/)























