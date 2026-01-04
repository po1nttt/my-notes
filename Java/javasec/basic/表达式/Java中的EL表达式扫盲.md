# 初步了解
在 JSP 页面中，为了不写丑陋的 `<% ... %>` 代码块，人们通常使用 **EL**
```jsp
<b>用户名：</b> <% User u = (User)request.getAttribute("user"); out.print(u.getName()); %>
```
```jsp
<b>用户名：</b> ${user.name}
```
两者差别一目了然

通过上面的案例，我们可以看到 JSP 的很多缺点。

由于 JSP页面内，既可以定义 HTML 标签，又可以定义 Java代码，造成了以下问题：
  难写难读难维护。
  书写麻烦：特别是复杂的页面
  既要写 HTML 标签，还要写 Java 代码
  阅读麻烦
  上面案例的代码，相信你后期再看这段代码时还需要花费很长的时间去梳理
  复杂度高：运行需要依赖于各种环境，JRE，JSP 容器，JavaEE…
  占内存和磁盘：JSP 会自动生成 `.java` 和 `.class` 文件占磁盘，运行的是 `.class` 文件占内存
  调试困难：出错后，需要找到自动生成的.java文件进行调试
  不利于团队协作：前端人员不会 Java，后端人员不精 HTML

如果页面布局发生变化，前端工程师对静态页面进行修改，然后再交给后端工程师，由后端工程师再将该页面改为 JSP 页面非常麻烦。

所以现在jsp已经淡出历史舞台

在现代开发中，它的地位已经被大大削弱了，原因有两点：
现在的流行做法是前后端分离，后端只给 **JSON 数据**，前端用 Vue 或 React 来渲染页面。
即使是后端渲染，大家也更倾向于使用 Thymeleaf或 FreeMarker。

但是不得不使用JSP开发的时候，就可以使用 `EL`来简化冗余的代码

# 基础语法
## 概述
EL（全称 **Expression Language** ）表达式语言。

**作用：**
- 1.用于简化 JSP 页面内的 Java 代码。
- 2.主要作用是 **获取数据**。其实就是从**域对象**中获取数据，然后将数据展示在页面上

**用法：**
要先通过 page 标签设置不忽略 EI 表达式
```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" isELIgnored="false" %>
```

**语法：**
`${expression}`

在 JSP 中我们可以写：
`${brans}`
`${brans}` 是获取域中存储的 key 作为 brands 的数据。

而 JSP 当中有四大域，它们分别是：

- page：当前页面有
- request：当前请求有效
- session：当前会话有效
- application：当前应用有效

el 表达式获取数据，会依次从这 4 个域中寻找，直到找到为止。而这四个域对象的作用范围如下图所示。
![[Pasted image 20260102002634.png]]
例如： `${brands}`，el 表达式获取数据，会先从 `page` 域对象中获取数据，如果没有再到 `requet` 域对象中获取数据，如果再没有再到 `session` 域对象中获取，如果还没有才会到 `application` 中获取数据。

## Demo
要使用 EL 表达式来获取数据，需要按照顺序完成以下几个步骤。

- 获取到数据，比如从数据库中拿到数据
- 将数据存储到 request 域中
- 转发到对应的 jsp 文件中

先定义一个 Servlet
```java
@WebServlet("/demo1")
public class ServletDemo1 extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        //1. 准备数据
        List<Brand> brands = new ArrayList<Brand>();
        brands.add(new Brand(1,"三只松鼠","三只松鼠",100,"三只松鼠，好吃不上火",1));
        brands.add(new Brand(2,"优衣库","优衣库",200,"优衣库，服适人生",0));
        brands.add(new Brand(3,"小米","小米科技有限公司",1000,"为发烧而生",1));
 
        //2. 存储到request域中
        request.setAttribute("brands",brands);
 
        //3. 转发到 el-demo.jsp
        request.getRequestDispatcher("/el-demo.jsp").forward(request,response);
    }
 
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        this.doGet(request, response);
    }
}
```
先准备数据，然后把数据放到request中并起名
然后转发到jsp的web页面。
在jsp中就可以实现用EL表达式来访问数据
这就做到了解耦，前后端分离

## 运算符
### 存取数据的运算符
EL表达式提供 `.   []`两种运算符来存取数据
和SpEL一样，当要存取的属性名称中包含一些特殊字符，如 `.` `-`之类的不是字母或者数字的符号，为避免歧义，就需要使用 `[]`例如 `${user.My-Name}`应该改为 `${user["My-Name"]}`
### empty运算符
empty用来判断是否为空，空或者null返回true 否则false

## 条件表达式

EL 表达式中，条件运算符的语法依旧类似三目运算，和 Java 的完全一致，如下：
`${条件表达式?表达式1:表达式2}`
## 变量
EL 表达式存取变量数据的方法很简单，例如：`${username}`。它的意思是取出某一范围中名称为 username 的变量。因为我们并没有指定哪一个范围的 username，所以它会依序从 Page、Request、Session、Application 范围查找。假如途中找到 username，就直接回传，不再继续找下去，但是假如全部的范围都没有找到时，就回传 `""`。

EL表达式的属性如下：

|四大域|域在EL中的名称|
|---|---|
|Page|PageScope|
|Request|RequestScope|
|Session|SessionScope|
|Application|ApplicationScope|

JSP 表达式语言定义可在表达式中使用的以下文字：

|文字|文字的值|
|---|---|
|Boolean|true 和 false|
|Integer|与 Java 类似。可以包含任何整数，例如 24、-45、567|
|Floating Point|与 Java 类似。可以包含任何正的或负的浮点数，例如 -1.8E-45、4.567|
|String|任何由单引号或双引号限定的字符串。对于单引号、双引号和反斜杠，使用反斜杠字符作为转义序列。必须注意，如果在字符串两端使用双引号，则单引号不需要转义。|
|Null|null|

## 操作符
JSP 表达式语言提供以下操作符，其中大部分是 Java 中常用的操作符：

|术语|定义|
|---|---|
|算术型|+、-（二元）、*、/、div、%、mod、-（一元）|
|逻辑型|and、&&、or、双管道符、!、not|
|关系型|==、eq、!=、ne、<、lt、>、gt、<=、le、>=、ge。可以与其他值进行比较，或与布尔型、字符串型、整型或浮点型文字进行比较。|
|空|empty 空操作符是前缀操作，可用于确定值是否为空。|
|条件型|A ?B :C。根据 A 赋值的结果来赋值 B 或 C。|

## 隐式对象

JSP 表达式语言定义了一组隐式对象，其中许多对象在 JSP scriplet 和表达式中可用：

|术语|定义|
|---|---|
|pageContext|JSP页的上下文，可以用于访问 JSP 隐式对象，如请求、响应、会话、输出、servletContext 等。例如，`${pageContext.response}`为页面的响应对象赋值。|

此外，还提供几个隐式对象，允许对以下对象进行简易访问：

|术语|定义|
|---|---|
|param|将请求参数名称映射到单个字符串参数值（通过调用 ServletRequest.getParameter (String name) 获得）。getParameter (String) 方法返回带有特定名称的参数。表达式`${param . name}`相当于 request.getParameter (name)。|
|paramValues|将请求参数名称映射到一个数值数组（通过调用 ServletRequest.getParameter (String name) 获得）。它与 param 隐式对象非常类似，但它检索一个字符串数组而不是单个值。表达式 `${paramvalues. name}` 相当于 request.getParamterValues(name)。|
|header|将请求头名称映射到单个字符串头值（通过调用 ServletRequest.getHeader(String name) 获得）。表达式 `${header. name}` 相当于 request.getHeader(name)。|
|headerValues|将请求头名称映射到一个数值数组（通过调用 ServletRequest.getHeaders(String) 获得）。它与头隐式对象非常类似。表达式`${headerValues. name}`相当于 request.getHeaderValues(name)。|
|cookie|将 cookie 名称映射到单个 cookie 对象。向服务器发出的客户端请求可以获得一个或多个 cookie。表达式`${cookie. name .value}`返回带有特定名称的第一个 cookie 值。如果请求包含多个同名的 cookie，则应该使用`${headerValues. name}`表达式。|
|initParam|将上下文初始化参数名称映射到单个值（通过调用 ServletContext.getInitparameter(String name) 获得）。|

除了上述两种类型的隐式对象之外，还有些对象允许访问多种范围的变量，如 Web 上下文、会话、请求、页面：

|术语|定义|
|---|---|
|pageScope|将页面范围的变量名称映射到其值。例如，EL 表达式可以使用`${pageScope.objectName}`访问一个 JSP 中页面范围的对象，还可以使用`${pageScope .objectName. attributeName}`访问对象的属性。|
|requestScope|将请求范围的变量名称映射到其值。该对象允许访问请求对象的属性。例如，EL 表达式可以使用`${requestScope. objectName}`访问一个 JSP 请求范围的对象，还可以使用`${requestScope. objectName. attributeName}`访问对象的属性。|
|sessionScope|将会话范围的变量名称映射到其值。该对象允许访问会话对象的属性。例如：`${sessionScope. name}`|
|applicationScope|将应用程序范围的变量名称映射到其值。该隐式对象允许访问应用程序范围的对象。|
#### PageContext对象

pageContext 对象是 JSP 中 pageContext 对象的引用。通过 pageContext 对象，您可以访问 request 对象。比如，访问 request 对象传入的查询字符串，就像这样：
```JSP
${pageContext.request.queryString}
```

### Scope 对象
pageScope，requestScope，sessionScope，applicationScope 变量用来访问存储在各个作用域层次的变量。

举例来说，如果您需要显式访问在 applicationScope 层的 box 变量，可以这样来访问：`applicationScope.box`
### param 和 paramValues 对象

param 和 paramValues 对象用来访问参数值，通过使用 `request.getParameter` 方法和 `request.getParameterValues` 方法。

举例来说，访问一个名为order的参数，可以这样使用表达式：`${param.order}，或者${param["order"]}。`

param 对象返回单一的字符串，而 paramValues 对象则返回一个字符串数组。


### header 和 headerValues 对象
header 和 headerValues 对象用来访问信息头，通过使用 `request.getHeader()` 方法和 `request.getHeaders()` 方法。

举例来说，要访问一个名为 user-agent 的信息头，可以这样使用表达式：`${header.user-agent}`，或者 `${header["user-agent"]}`

接下来的例子表明了如何访问 user-agent 信息头：`<p>${header["user-agent"]}</p>`

## EL中的函数
 
EL允许您在表达式中使用函数。这些函数必须被定义在自定义标签库中。函数的使用语法如下：
`${ns:func(param1, param2, ...)}`

ns 指的是命名空间（namespace），func 指的是函数的名称，param1 指的是第一个参数，param2 指的是第二个参数，以此类推。比如，有函数 `fn:length`，在 JSTL 库中定义，可以像下面这样来获取一个字符串的长度：`${fn:length("Get my length")}`

要使用任何标签库中的函数，您需要将这些库安装在服务器中，然后使用 `<taglib>` 标签在 JSP 文件中包含这些库。

## EL调用Java方法

看个例子即可。

先新建一个 ELFunc 类，其中定义的 `doSomething()` 方法用于给输入的参数字符拼接 `".com"` 形成域名返回：
```java
package eltest;

public class ELFunc {
    public static String doSomething(String str){
        return str + ".com";
    }
}
```
接着在 `WEB-INF` 文件夹下（除 `lib` 和 `classess` 目录外）新建 `test.tld` 文件，其中指定执行的 Java 方法及其 URI 地址：
```xml
<?xml version="1.0" encoding="UTF-8"?>  
<taglib version="2.0" xmlns="http://java.sun.com/xml/ns/j2ee"  
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  
 xsi:schemaLocation="http://java.sun.com/xml/ns/j2ee http://java.sun.com/xml/ns/j2ee/web-jsptaglibrary_2_0.xsd">  
    <tlib-version>1.0</tlib-version>  
    <short-name>ELFunc</short-name>  
    <uri>http://localhost/ELFunc</uri>  
    <function>  
        <name>doSomething</name>  
        <function-class>com.drunkbaby.basicjsp.web.ELFunc</function-class>  
        <function-signature> java.lang.String doSomething(java.lang.String)</function-signature>  
    </function>  
</taglib>
```
**TLD** 的全称是 **Tag Library Descriptor（标签库描述符）**。它就像是一本“花名册”。

- **`<uri>`**：给你的工具箱起个唯一的“身份证号”。不一定非要是真实的网址，只要唯一即可。
- **`<name>`**：在 JSP 里调用时的小名（如 `doSomething`）。
- **`<function-class>`**：告诉服务器，这个功能的真实代码在哪（类的全限定名）。
- **`<function-signature>`**：这是最严格的地方，规定了方法的**返回类型**和**参数类型**（必须写全称，比如 `java.lang.String` 不能简写为 `String`）。

JSP 文件中，先头部导入 `taglib` 标签库，URI 为 `test.tld` 中设置的 URI 地址，prefix 为 `test.tld` 中设置的 short-name，然后直接在 EL 表达式中使用 `类名:方法名()` 的形式来调用该类方法即可：
```java
<%@taglib uri="http://localhost/ELFunc" prefix="ELFunc"%>  
${ELFunc:doSomething("Drunkbaby")}
```


## JSP中启动/禁用EL表达式

### 全局禁用EL
web.xml 中进入如下配置：
```xml
<jsp-config>
    <jsp-property-group>
        <url-pattern>*.jsp</url-pattern>
        <el-ignored>true</el-ignored>
    </jsp-property-group>
</jsp-config>
```

### 单个文件禁用EL表达式
在JSP文件中可以有如下定义：
`<%@ page isELIgnored="true" %>`
该语句表示是否禁用EL表达式，TRUE 表示禁止，FALSE 表示不禁止。

JSP2.0 中默认的启用EL表达式。

例如如下的 JSP 代码禁用EL表达式：
```jsp
<%@ page isELIgnored="true" %>
${pageContext.request.queryString}
```









































































