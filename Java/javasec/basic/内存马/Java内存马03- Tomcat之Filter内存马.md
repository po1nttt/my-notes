之前我们讲，我们的请求会经过 filter 之后才会到 Servlet ，那么如果我们动态创建一个 filter 并且将其放在最前面，我们的 filter 就会最先执行，当我们在 filter 中添加恶意代码，就会进行命令执行，这样也就成为了一个内存 Webshell

所以我们后文的目标：**动态注册恶意 Filter，并且将其放到 最前面**

# Tomcat Filter流程分析

## 项目搭建
Tomcat 8.5.81

自定义Filter
```java
import javax.servlet.*;  
import java.io.IOException;  
  
public class filter implements Filter{  
    @Override  
 public void init(FilterConfig filterConfig) throws ServletException {  
        System.out.println("Filter 初始构造完成");  
 }  
  
    @Override  
 public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {  
        System.out.println("执行了过滤操作");  
 filterChain.doFilter(servletRequest,servletResponse);  
 }  
  
    @Override  
 public void destroy() {  
  
    }  
}
```
然后修改web.xml注册、激活路由
```xml
<?xml version="1.0" encoding="UTF-8"?>  
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"  
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"  
         version="4.0">  
         
    <filter>        
	    <filter-name>filter</filter-name>起名字叫filter 
        <filter-class>filter</filter-class>实现过滤功能的类  
    </filter>
    
    <filter-mapping>
        <filter-name>filter</filter-name>  使用的过滤器，对应刚刚起的名字
        <url-pattern>/filter</url-pattern> 拦截规则是访问/filter才会拦截 
    </filter-mapping>
    
</web-app>
```































