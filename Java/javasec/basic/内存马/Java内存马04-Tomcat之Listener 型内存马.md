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




































