[Java RMI 安全 | X1r0z Blog](https://exp10it.io/posts/java-rmi-security/#%E6%94%BB%E5%87%BB-registry)
[Java反序列化之RMI专题01-RMI基础 | Drunkbaby's Blog](https://drun1baby.top/2022/07/19/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BRMI%E4%B8%93%E9%A2%9801-RMI%E5%9F%BA%E7%A1%80/)

RMI全称是Remote Method Invocation，远程方法调用。从这个名字就可以看出，他⽬目标和RPC其实 是类似的，是让某个Java虚拟机上的对象调⽤用另一个Java虚拟机中对象上的方法，只不不过RMI是Java独有的一种机制。 我们直接从一个例子开始演示RMI的流程吧。 
# example
## RMI Server端
```java
package org.example;  
  
import java.rmi.Naming;  
import java.rmi.Remote;  
import java.rmi.RemoteException;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
  
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
    }  
}
```
解释一下
大体分为三部分
1.一个继承了`java.rmi.Remote`的接口，其中定义我们要远程调用的函数，比如这里的hello()

```java
public interface IRemoteHelloWorld extends Remote {
    public String hello() throws RemoteException;
}
```
- **`IRemoteHelloWorld`**: 这是定义 **远程服务** 的接口。
    
- **`extends Remote`**: **所有** 远程接口都必须扩展 `java.rmi.Remote` 接口。这告诉 JVM 这个接口的方法是可以在网络上远程调用的。
    
- **`hello() throws RemoteException`**: 远程接口中的所有方法都必须声明抛出 `java.rmi.RemoteException`，因为远程调用可能会因为网络问题等原因失败。


2.一个实现了接口的类
```java
public class RemoteHelloWorld extends UnicastRemoteObject implements IRemoteHelloWorld {
    protected RemoteHelloWorld() throws RemoteException {
        super();
    }
    
    public String hello() throws RemoteException {
        System.out.println("call from");
        return "Hello world";
    }
}
```
- **`RemoteHelloWorld`**: 这是实现了远程接口 `IRemoteHelloWorld` 的 **具体类**，它包含了远程方法的实际逻辑。
    
- **`extends UnicastRemoteObject`**: 这是一个 **方便的基类**，用于实现远程对象。它的构造函数会负责将远程对象 **导出 (export)**，使其能够接收传入的远程调用请求。
    
-  构造函数需要抛出一个RemoteException错误
    
- **`super()`**: 调用父类构造函数，执行导出操作。事实上，在底层实现了一下三个功能

	**开启监听端口**：它会启动一个线程，在指定的端口（如果你传 0，系统会随机分配一个可用端口）上监听远程请求。
    
	**创建代理/存根（Stub）**：在旧版 JDK 中，它会寻找对应的 Stub 类；在现代 JDK 中，它利用动态代理生成一个用于网络传输的代理对象。
    
	**等待连接**：使该 Java 对象“远程化”，让它能够接收来自网络（通过 TCP/IP）的远程方法调用（JRMP 协议）。
    
- **`hello()`**: 实现了远程接口中定义的方法，当客户端远程调用时，服务器端会执行这里的代码。
    
- 实现类中使用的对象必须都可序列化，即都继承`java.io.Serializable`

3.一个主类，用来创建Registry，并将上面的类实例化后绑定到一个地址。这就是我们所谓的Server
```java
private void start() throws Exception {
    RemoteHelloWorld h = new RemoteHelloWorld();
    // 1. 创建 RMI 注册表
    LocateRegistry.createRegistry(1099); 
    // 2. 注册远程对象
    Naming.rebind("rmi://127.0.0.1:1099/Hello", h);
}
```

1. **实例化远程对象**: `RemoteHelloWorld h = new RemoteHelloWorld();` 创建远程服务的一个实例。
    
2. **创建注册表**: `LocateRegistry.createRegistry(1099);` 创建一个运行在 **端口 1099** 上的 **RMI 注册表 (RMI Registry)**。注册表的作用是作为一个 **目录服务**，客户端通过它查找远程对象的引用。默认1099
    
3. **绑定/注册**: `Naming.rebind("rmi://127.0.0.1:1099/Hello", h);` 将远程对象实例 `h` 注册到注册表，并给它起一个名称 `"Hello"`。客户端将使用这个名称来查找并获取远程对象的引用（**stub**）。


## RMI Client端
```java
import org.vulhub.RMI.RMIServer;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
public class TrainMain {
	public static void main(String[] args) throws Exception {
		RMIServer.IRemoteHelloWorld hello =(RMIServer.IRemoteHelloWorld)Naming.lookup("rmi://192.168.135.142:1099/Hello");
		String ret = hello.hello();
		System.out.println(ret);
		
	}
}
```
客户端主要就是从注册表中查找对象之后，正常调用对象的方法

还是简单的讲一下吧
- **`Naming.lookup(...)`**: 这是客户端的核心操作。它负责连接到 RMI 注册表并查找远程对象。
- 顺便说一嘴，这里的强制类型转换时很有必要的，由于java是一个强类型语言，所以如果我想调用`hello()`的时候他的类中必须存在一个`hello()`方法，那我们这里就不能只通过`Naming.lookup()`来返回一个`Remote`对象，必须强制转换为`(RMIServer.IRemoteHelloWorld)`或者`(RemoteHelloWorld)`类型,但是！这里只能使用`(RMIServer.IRemoteHelloWorld)`我们在下面看源码的时候，底层新建一个动态代理的时候传入的第二个参数是一个接口，代理对象只根据我提供的接口来生成方法的签名`Proxy.newProxyInstance(loader, interfaces, handler)`
    
- **`"rmi://192.168.135.142:1099/Hello"`**: 这是一个 **URL 格式的字符串**，它告诉客户端：
    
    - **协议**: `rmi:`
        
    - **服务器地址**: `192.168.135.142` (这是你服务器的 IP 地址)
        
    - **端口**: `1099` (这是 RMI 注册表运行的端口)
        
    - **对象名称**: `/Hello` (这是服务器端使用 `Naming.rebind()` 绑定的名称)
        
- **返回类型**: `lookup()` 方法返回一个 **通用对象**，客户端需要将其 **强制类型转换** 为远程接口类型 `RMIServer.IRemoteHelloWorld`。
    
- **Stub 对象**: 实际返回给客户端的并不是服务器端的真实对象，而是一个 **Stub（存根）** 对象。Stub 负责将客户端的方法调用打包成网络消息发送给服务器，并将服务器的返回值（或异常）带回来。


虽说执行远程方法的时候代码是在远程服务器上执行的，但实际上我们还是需要知道有哪些方法，这时 候接口的重要性就体现了，这也是为什么我们前面要继承 Remote 并将我们需要调用的方法写在接口 IRemoteHelloWorld 里，因为客户端也需要用到这个接口。


整个流程我们粘一下P神的总结

首先客户端连接Registry（注册表），并在其中寻找Name是Hello的对象，这个对应数据 流中的Call消息；然后Registry返回一个序列列化的数据，这个就是找到的Name=Hello的对象，这个对应 数据流中的ReturnData消息；客户端反序列列化该对象，发现该对象是一个远程对象，地址 在192.168.135.142:33769，于是再与这个地址建立TCP连接；在这个新的连接中，才执⾏行行真正远程方法调用，也就是 hello() 。 我们借用下图来说明这些元素间的关系：
![[Pasted image 20251209150736.png]]

RMI Registry就像一个网关，他自己是不会执行远程方法的，但RMI Server可以在上面注册一个Name 到对象的绑定关系；RMI Client通过Name向RMI Registry查询，得到这个绑定关系，然后再连接RMI Server；最后，远程方法实际上在RMI Server上调用。

总结下，RMI过程中有一下三个参与者

- RMI Registry
- RMI Server
- RMI Client

```java
    private void start() throws Exception {  
        RemoteHelloWorld h = new RemoteHelloWorld();  
        LocateRegistry.createRegistry(1099);  
        Naming.rebind("rmi://127.0.0.1:1099/Hello", h);  
    }  
  
```
还记得我们server端中有一步，把对象绑定在Registry上了
所以事实上我们的server端包含了Registry
`Naming.bind`的第一个参数是URL，后面可以绑定远程对象的名字。
>如果在本地运行，host和port可以省略，此时host默认是localhost，port默认1099
`Naming.bind("Hello", new RemoteHelloWorld());`



## RMI Registry端
在这里讲一下**Stub（存根）** 和 **Skeleton（骨架）** 这两个代理对象
### Stub
Stub 运行在客户端中
Stub 是客户端看到的远程对象的**本地替身**
客户端通过Naming.lookup()获得远程引用时，实际获得的时Stub对象
- 客户端调用 Stub 上的远程方法（例如 `hello.sum(...)`）。
- Stub 接收到参数后，执行 **数据编组 (Marshalling)**：将参数对象**序列化**成字节流。
- Stub 负责建立网络连接，将序列化后的字节流发送给服务器端的 Skeleton。
- Stub 阻塞等待，直到接收到 Skeleton 返回的结果，然后执行 **解编组 (Unmarshalling)** 并将结果返回给客户端。
### Skeleton

Skeleton运行在服务端中
充当Stub和真正的远程对象之间的中介

-  Skeleton 接收到来自 Stub 的网络连接和序列化后的字节流。
-  Skeleton 执行 **解编组 (Unmarshalling)**：将字节流反序列化成 Java 对象，恢复客户端发送的参数。
-  Skeleton 调用**真正的远程对象**（例如 `Calc` 实例）上对应的方法，并将恢复的参数传递进去。
-  远程对象执行业务逻辑并返回结果。
-  Skeleton 对结果进行 **数据编组 (Marshalling)**，并将序列化后的结果发送回客户端的 Stub。

### Registry 的代理对象

Registry类似服务器端，同样遵循这个原理
因为它运行在一个独立的进程（或端口）上，并提供了 `bind`、`rebind`、`unbind` 和 `lookup` 等远程可调用的方法。
因此，注册表也必须遵循 Stub/Skeleton 机制：

- **`RegistryImpl_Stub`：** 注册表的客户端代理对象。当服务器（调用 `Naming.rebind()`）或客户端（调用 `Naming.lookup()`）需要与注册表通信时，它们使用的是这个 Stub 对象。
- **`RegistryImpl_Skel`：** 注册表的服务端代理对象。它接收来自 `RegistryImpl_Stub` 的请求，并调用注册表核心服务（`RegistryImpl`）上的 `bind` 或 `lookup` 逻辑。

**总结流程：**

1. **服务器注册时：** 服务器 $\rightarrow$ `RegistryImpl_Stub` $\rightarrow$ Registry $\rightarrow$ 核心服务执行 `bind`。
    
2. **客户端查找时：** 客户端 $\rightarrow$ `RegistryImpl_Stub` $\rightarrow$ Registry $\rightarrow$ 核心服务执行 `lookup`。

查看源码
![[Pasted image 20251209204524.png]]
这里重点关注 dispatch 方法, 该方法是处理请求的核心
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

其中 bind rebind unbind lookup 的操作中都存在对 readObject 方法的调用, 为后面的反序列化漏洞打下了基础


# 总结
在此我们总结一下整个的流程
我们先自定义一下名词，虽然不准确，但是老写客户端服务端，看着看着会看蒙。这样好区分
Client：用户
Server：服务器
Registry：注册表


首先服务器先创建一个包含了我们想上传对象的注册表，其中包含了若干个`Stub`存根，这个存根中包含了对象的一系列信息，当然也包括该对象中方法具体执行的端口（我们上面是用的随机端口）
注意哦，这里的端口不是那个1099的端口


现在用户在已知ip和注册的对象名字的时候就可以远程调用这个对象了！我们需要先向注册表查询到这个对象，这个查询的过程到不如说为查询+下载，在服务器，会用Skeleton中的逻辑序列化一个对象 ， 用户会下载这个对象的stub的序列化字节流，在本地反序列化后一个代理对象（远程对象的stub）就在用户本地存在了。
这里还应该提到，如果这个远程对象的接口被打成jar包发给客户端了，那么客户端有这个接口就可以反序列化出这个对象，并不需要实现类，因为具体的方法在远程的服务器执行，如果用户连接口都没有，那么会通过http从远程服务器下载接口的.class文件。


此时如果我们调用这个远程对象中的任意一个方法，用户端就会通过这个Stub中的信息，向对应的ip和端口，发起请求，服务器接受这个请求就会通过服务器的Skeleton中的逻辑来反序列化一个对象，然后在服务器本地执行代码，最终将返回结果序列化再返回用户，用户反序列化这个序列化流，最终得到执行的结果。

---
# 进入源码打断点跟进流程
该记的都记了，下面就自己跟着打断点进去看看，写的不全，只是让自己过一遍，锻炼下debug的能力，顺便记录一下

## 创建远程服务
我们分析一下他是如何被发布到网络上的（这部分没有漏洞）
由于我们的 `RemoteHelloWorld()`继承于 `UnicastRemoteObject` 他会先调用父类的构造方法

看到传入构造方法的时候这里的port为0 代表这是一个匿名端口，他会从当前可用的端口中随机分配一个空闲的来使用。我们设定的默认1099的端口是让客户端来这里查找服务的地址
而这个匿名端口是将在未来接受客户端的 `Stub`（存根）会将- “方法名”、“参数类型”和“参数值”序列化成二进制流，发送到这个匿名端口。监听到这个请求后，会解析这些数据，找到对应 我们设置的`RemoteHelloWorld`实例，然后在注册端本地运行hello()方法。

那我们就会产生思考，监听在1099端口的一些方法，例如在查询，绑定对象的时候，会执行反序列化，这是注册端的一个攻击面。
其次，在这个执行具体方法的随机匿名端口，如果接受Object类型的参数，也有可能产生反序列化漏洞。例如我们的`Hello()`方法如果接受一个 `Object`类型的参数，那他在执行方法之前是必须要反序列化我们的二进制对象流的，就可以无条件反序列化我们的恶意对象。在**JEP 290** 出现之前，这个漏洞几乎无法从代码层面根治。
![[Pasted image 20251219144045.png]]
![[Pasted image 20251219144456.png]]

我们接着步入 `exportObject()`方法看看
这是一个静态方法，主要负责将远程服务发布到网上
我们来看这个静态函数，第一个参数是 obj 对象，第二个参数是 `new UnicastServerRef(port)`，第二个参数是用来处理网络请求的。继续往下面跟，去到了 `UnicastServerRef` 的构造函数。
![[Pasted image 20251219152052.png]]
跟进去之后 UnicastServerRef 的构造函数，我们看到它 new 了一个 LiveRef(port)，这个非常重要，它算是一个网络引用的类，跟进看一看
![[Pasted image 20251219152323.png]]
跟进去之后，先是一个构造函数，先跳进 this 看一看

![[Pasted image 20251219152350.png]]
构造函数如下
第一个参数 ID，第三个参数为 true，所以我们重点关注一下第二个参数。
```java
public LiveRef(ObjID objID, int port) {  
    this(objID, TCPEndpoint.getLocalEndpoint(port), true);  
}
--------------------------------------------------------------
public LiveRef(ObjID objID, Endpoint endpoint, boolean isLocal) {  
    ep = endpoint;  
    id = objID;  
    this.isLocal = isLocal;  
}
```

第二个参数`TCPEndpoint` 是一个网络请求的类，我们可以去看一下它的构造函数，传参进去一个 IP 与一个端口，也就是说传进去一个 IP 和一个端口，就可以进行网络请求。

![[Pasted image 20251219152756.png]]
跟进进来可以看到 csf  ssf参数都是null
只有port为0，会随机分配一个
![[Pasted image 20251219152820.png]]

好我们出来
接着跟进这里看看构造函数的赋值
发现 host 和 port 是赋值到了 endpoint 里面，而 endpoint 又是被封装在 LiveRef 里面的，所以记住数据是在 LiveRef 里面即可，并且这一 LiveRef 至始至终只会存在一个，可以把这个LiveRef理解为远程对象的唯一标识，里面封装了远程对象的各种信息
![[Pasted image 20251219153053.png]]![[Pasted image 20251219153310.png]]

至此，我们的 `LiveRef`对象已经初始化好了
我们回到刚才出现`LiveRef`的地方
![[Pasted image 20251219181016.png]]

---
跟进super看看他的父类 `UnicastRef`，这里就证明整个**创建远程服务**的过程只会存在一个 LiveRef。一路 步入 到一个静态函数 `exportObject()`我们后续的操作过程都与 `exportObject()` 有关，基本都是在调用它，这一段不是很重要，一路 f7 就好了。直到此处出现 Stub
![[Pasted image 20251219181649.png]]
这说明我们服务端创建远程服务这一步竟然出现了stub的创建

事实上，RMI先在 Service的地方，也就是服务端创建一个 `Stub`再把 `Stub`传入注册表，最后让RMI客户端去取Stub

下面我们研究一下 `Stub`产生的这一步，先进到 createProxy 这个方法里面

先进行了基本的赋值，然后我们继续往下看，
![[Pasted image 20251219183125.png]]
可以看到new了一个动态代理
第一个参数是 AppClassLoader，第二个参数是一个远程接口，第三个参数是调用处理器，调用处理器里面只有一个 ref，它也是和之前我们看到的 ref 是同一个，创建远程服务当中永远只有一个 ref。

![[Pasted image 20251219183230.png]]
可以看到我们从createProxy方法里面出来之后
可以看到我们这个 `Stub`中Proxy对象已经创建好了。
![[Pasted image 20251219201042.png]]
继续向下
看看我们Target对象是怎么new出来的，步入
![[Pasted image 20251219201533.png]]
Target 这里相当于一个总的封装，将所有用的东西放到 Target 里面
更加证明了我们上面说的有且只有一个 `LiveRef`对象
![[Pasted image 20251219201931.png]]
创建好对象之后，把封装好的对象发布出去，后面也是如此，执行一些网络上的东西
![[Pasted image 20251219202050.png]]

最后成功创建一个远程服务
主要是后面懒得写了。。

## 客户端向注册中心进行调用，客户端请求








