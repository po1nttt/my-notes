
# 什么是Java Agent
我们知道Java是一种静态强类型语言，在运行之前必须将其编译成`.class`字节码，然后再交给JVM处理运行。Java Agent就是一种能在不影响正常编译的前提下，修改Java字节码，进而动态地修改已加载或未加载的类、属性和方法的技术。

实际上，平时较为常见的技术如热部署、一些诊断工具等都是基于Java Agent技术来实现的。那么Java Agent技术具体是怎样实现的呢？

对于Agent（代理）来讲，其大致可以分为两种，一种是在JVM启动前加载的`premain-Agent`，另一种是JVM启动之后加载的`agentmain-Agent`。这里我们可以将其理解成一种特殊的Interceptor（拦截器），如下图

**Premain-Agent**
![](picture/Pasted%20image%2020260111232302.png)

**agentmain-Agent**
![](picture/Pasted%20image%2020260111232312.png)
# 几种Java Agent实例

## Premain-Agent
我们首先来实现一个简单的`premain-Agent`，创建一个Maven项目，编写一个简单的premain-Agent
```java
package com.java.premain.agent;
 
import java.lang.instrument.Instrumentation;
 
public class Java_Agent_premain {
    public static void premain(String args, Instrumentation inst) {
        for (int i =0 ; i<10 ; i++){
            System.out.println("调用了premain-Agent！");
        }
    }
}
```
接着在`resource/META-INF/`下创建`MANIFEST.MF`清单文件用以指定`premain-Agent`的启动类
```
Manifest-Version: 1.0
Premain-Class: com.java.premain.agent.Java_Agent_premain
```
将其打包成jar文件

卷构建一个目标类
```java
public class Hello {
    public static void main(String[] args) {
        System.out.println("Hello World!");
    }
}
```
台南佳JVM Oprions(注意冒号之后不能有空格)
```bash
java -javaagent:"out/artifacts/Java_Agent_jar/Java_Agent.jar" Hello
```
运行如下
![](picture/Pasted%20image%2020260111233306.png)
## agentmain-Agent

相较于premain-Agent只能在JVM启动前加载，agentmain-Agent能够在JVM启动之后加载并实现相应的修改字节码功能。下面我们来了解一下和JVM有关的两个类。

### VirtualMachine类
`com.sun.tools.attach.VirtualMachine`类可以实现获取JVM信息，内存dump、现成dump、类信息统计（例如JVM加载的类）等功能。

该类允许我们通过给attach方法传入一个JVM的PID，来远程连接到该JVM上 ，之后我们就可以对连接的JVM进行各种操作，如注入Agent。下面是该类的主要方法
```java
//允许我们传入一个JVM的PID，然后远程连接到该JVM上
VirtualMachine.attach()
 
//向JVM注册一个代理程序agent，在该agent的代理程序中会得到一个Instrumentation实例，该实例可以 在class加载前改变class的字节码，也可以在class加载后重新加载。在调用Instrumentation实例的方法时，这些方法会使用ClassFileTransformer接口中提供的方法进行处理
VirtualMachine.loadAgent()
 
//获得当前所有的JVM列表
VirtualMachine.list()
 
//解除与特定JVM的连接
VirtualMachine.detach()
```

### VirtualMachineDescriptor类

`com.sun.tools.attach.VirtualMachineDescriptor`类是一个用来描述特定虚拟机的类，其方法可以获取虚拟机的各种信息如PID、虚拟机名称等。下面是一个获取特定虚拟机PID的示例
```java
import com.sun.tools.attach.VirtualMachine;
import com.sun.tools.attach.VirtualMachineDescriptor;
 
import java.util.List;
 
public class get_PID {
    public static void main(String[] args) {
        
        //调用VirtualMachine.list()获取正在运行的JVM列表
        List<VirtualMachineDescriptor> list = VirtualMachine.list();
        for(VirtualMachineDescriptor vmd : list){
            
            //遍历每一个正在运行的JVM，如果JVM名称为get_PID则返回其PID
            if(vmd.displayName().equals("get_PID"))
            System.out.println(vmd.id());
        }
 
    }
}
 
 
##
4908
 
Process finished with exit code 0
```
下面我们就来实现一个`agentmain-Agent`。首先我们编写一个Sleep_Hello类，模拟正在运行的JVM
```java
import static java.lang.Thread.sleep;
 
public class Sleep_Hello {
    public static void main(String[] args) throws InterruptedException {
        while (true){
            System.out.println("Hello World!");
            sleep(5000);
        }
    }
}
```
然后编写我们的agentmain-Agent类
```java
package com.java.agentmain.agent;
 
import java.lang.instrument.Instrumentation;
 
import static java.lang.Thread.sleep;
 
public class Java_Agent_agentmain {
    public static void agentmain(String args, Instrumentation inst) throws InterruptedException {
        while (true){
            System.out.println("调用了agentmain-Agent!");
            sleep(3000);
        }
    }
}
```
同时配置MANIFEST.MF文件
```
Manifest-Version: 1.0
Agent-Class: com.java.agentmain.agent.Java_Agent_agentmain
 
```
编译打包成jar文件`out/artifacts/Java_Agent_jar/Java_Agent.jar`

最后编写一个`Inject_Agent`类，获取特定JVM的PID并注入Agent






























