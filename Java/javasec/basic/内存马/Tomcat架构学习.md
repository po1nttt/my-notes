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
客户端发起一个http请求，比如 get 类型。

Servlet 容器接收到请求，根据请求信息，封装成 HttpServletRequest 和HttpServletResponse 对象。这步也就是我们的传参。

Servlet容器调用 HttpServlet 的 init() 方法，init 方法只在第一次请求的时候被调用。

Servlet 容器调用 service() 方法。

service() 方法根据请求类型，这里是get类型，分别调用doGet或者doPost方法，这里调用doGet方法。

doXXX 方法中是我们自己写的业务逻辑。

业务逻辑处理完成之后，返回给 Servlet 容器，然后容器将结果返回给客户端。

容器关闭时候，会调用 destory 方法。
































