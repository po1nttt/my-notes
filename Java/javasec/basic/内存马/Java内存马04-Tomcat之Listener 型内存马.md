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

第一个问题现在我们已经想到一种显而易见的方法
在 Listener 这里提供了 ServletRequestEvent 类型的参数，从名字可推测出为 Servlet请求事件
```java
    public void requestInitialized(ServletRequestEvent sre) {  
        System.out.println("requestInitialized!");  
  
    }  
```
我们既然要做内存马所以就必须要获取到发送过来的请求，然后从请求中获取我们要执行的命令然后利用 Runtime 来进行执行，例如：`https://www.xxxx.com/demo?cmd=ls` 这里面 cmd 参数的值，所以我们需要寻找 sre 的一个方法来获取到请求































