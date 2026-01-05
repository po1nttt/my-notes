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

那我们想办法把这个命令从 `ServletRequestEvent sre`这个传入的参数中拿出来，然后在`requestInitialized()`种写入我们的木马，传入我们刚刚拿的对象，这样就可以执行命令了。

ok我们先解决第一步，拿到我们传入的get参数或者post传参。所以我们需要寻找 sre 的一个方法来获取到请求

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

























