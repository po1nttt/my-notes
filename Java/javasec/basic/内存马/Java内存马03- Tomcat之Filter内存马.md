之前我们讲，我们的请求会经过 filter 之后才会到 Servlet ，那么如果我们动态创建一个 filter 并且将其放在最前面，我们的 filter 就会最先执行，当我们在 filter 中添加恶意代码，就会进行命令执行，这样也就成为了一个内存 Webshell

所以我们后文的目标：**动态注册恶意 Filter，并且将其放到 最前面**

# Tomcat Filter流程分析

## 项目搭建
Tomcat 8.5.81

自定义Filter
```java
import javax.servlet.*;  
import java.io.IOException;  
  
public class filter implements Filter{  
    @Override  
 public void init(FilterConfig filterConfig) throws ServletException {  
        System.out.println("Filter 初始构造完成");  
 }  
    @Override  
 public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {  
        System.out.println("执行了过滤操作");  
 filterChain.doFilter(servletRequest,servletResponse);  
 }  
    @Override  
 public void destroy() {  
    }  
}
```
然后修改web.xml注册、激活路由
```xml
<?xml version="1.0" encoding="UTF-8"?>  
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"  
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"  
         version="4.0">  
         
    <filter>        
	    <filter-name>filter</filter-name>起名字叫filter 
        <filter-class>filter</filter-class>实现过滤功能的类  
    </filter>
    
    <filter-mapping>
        <filter-name>filter</filter-name>  使用的过滤器，对应刚刚起的名字
        <url-pattern>/filter</url-pattern> 拦截规则是访问/filter才会拦截 
    </filter-mapping>
    
</web-app>
```
启动之后可以看到，我们当前首次访问的时候初始化了Filter 每次访问都会执行过滤操作
![](picture/Pasted%20image%2020260105170610.png)

# 访问 /filter时的源码分析
根据我们前面知道，进入Filter中的时候，会调用 `Filter.doFilter()`内部的 `filterChain.doFilter()`来执行过滤操作，那我们就打断点进去看看
ok，我们首次访问之后初始化，初始化完毕之后进入 `filterChain.doFilter()`
![](picture/Pasted%20image%2020260105172128.png)
这里会进到 `ApplicationFilterChain` 类的 doFilter() 方法，它主要是进行了 `Globals.IS_SECURITY_ENABLED`，也就是全局安全服务是否开启的判断。
![](picture/Pasted%20image%2020260105172327.png)
步过这个`if`
到达了 `internalDoFilter()`
![](picture/Pasted%20image%2020260105172556.png)
通过观察我们也可以发现，其实整个过滤的过程都是在传递request和response对象，让他们走一遍过滤器链。
![](picture/Pasted%20image%2020260105172817.png)
ok我们回到正题，接着进入 `internalDoFilter()`
我们可以发现，源代码也写着 `// Call the next filter if there is one`
这里就是我们之前说到的FilterChain的地方，通过循环，把每一个Filter都过一遍
![](picture/Pasted%20image%2020260105173543.png)
可以看到 `ApplicationFilterConfig filterConfig = filters[pos++];`这行有一个filters数组，
这里数组中有两个对象，\[0\]是我们自己写的名字叫filter 走的逻辑是filter类，
还有一个\[1\]是Tomcat的过滤器，名字叫Tomcat WebSocket Filter ，走的是 `org.apache.tomcat.websocket.server.WsFilter`类的逻辑
![](picture/Pasted%20image%2020260105173703.png)

可以看到，最终执行了 `filter.doFilter()`执行了我们过滤器的主逻辑
![](picture/Pasted%20image%2020260105174954.png)
![](picture/Pasted%20image%2020260105175048.png)
然后再次循环，可以看到pos变为1了

![](picture/Pasted%20image%2020260105175124.png)
循环完毕，可以看到一些释放的操作
![](picture/Pasted%20image%2020260105180108.png)
最终去调用servlet.service()把request 和response传递下去

这里就呼应了我们之前讲Tomcat的时候说的，由最开始的`Filter.doFilter()`调用 `filterChain.doFilter()`然后由最后的 `filterChain`去调用 `Servlet。service()`

# 访问 /filter之前的源码分析

回到主线，我们的思路是要在filter的最前面加上我们的东西，让他执行恶意命令对吧。
那我们就要找找filter是怎么生成的，然后让他能调用到我们的东西就完美了。

这里看到Drun1baby师傅是通过idea的堆栈图来逆向分析的，给我了一些启发。
在这个堆栈图
![](picture/Pasted%20image%2020260105184508.png)
我们之前学习的时候知道，jvm运行当中内存会被划分为堆和栈，堆中存放对象，栈里存放执行中的方法，也就是这里的这个图，这里存放了所有过程中执行过的方法。

看我们这里是从分配线程开始的，通过粗略观察，我们可以发猜测出发生的一些动作。

![](picture/Pasted%20image%2020260105185221.png)
配合我们之前这个图就更加清晰了。
```
Server (整个 Tomcat 服务器)
└── Service (服务：将 Connector 和 Engine 组合在一起)
    ├── Connector (连接器：监听端口，负责 HTTP 协议解析，外交官)
    └── Engine (引擎：管理虚拟主机，Servlet 引擎核心)
        └── Host (虚拟主机：例如 localhost，对应域名)
            └── Context (Web 应用：对应你的项目)
	           ├── Listeners (监听器列表：最先触发) ⭐
	           ├── Filters (过滤器链：请求必经之路) ⭐
	           └── Wrappers (包装器：里面住着具体的 Servlet)⭐
```

那我们
























































