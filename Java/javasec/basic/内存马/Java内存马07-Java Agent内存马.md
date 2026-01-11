
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
```java
package com.java.inject;
 
import com.sun.tools.attach.*;
 
import java.io.IOException;
import java.util.List;
 
public class Inject_Agent {
    public static void main(String[] args) throws IOException, AttachNotSupportedException, AgentLoadException, AgentInitializationException {
        //调用VirtualMachine.list()获取正在运行的JVM列表
        List<VirtualMachineDescriptor> list = VirtualMachine.list();
        for(VirtualMachineDescriptor vmd : list){
 
            //遍历每一个正在运行的JVM，如果JVM名称为Sleep_Hello则连接该JVM并加载特定Agent
            if(vmd.displayName().equals("Sleep_Hello")){
 
                //连接指定JVM
                VirtualMachine virtualMachine = VirtualMachine.attach(vmd.id());
                //加载Agent
                virtualMachine.loadAgent("out/artifacts/Java_Agent_jar/Java_Agent.jar");
                //断开JVM连接
                virtualMachine.detach();
            }
 
        }
    }
}
```
首先启动`Sleep_Hello`目标JVM
![](picture/Pasted%20image%2020260111234416.png)
然后运行`Inject_Agent`类，注入Agent
![](picture/Pasted%20image%2020260111234434.png)
##  Instrumentation
Instrumentation是 JVMTIAgent（JVM Tool Interface Agent）的一部分，Java agent通过这个类和目标 JVM 进行交互，从而达到修改数据的效果。
```java
public interface Instrumentation {
    
    //增加一个Class 文件的转换器，转换器用于改变 Class 二进制流的数据，参数 canRetransform 设置是否允许重新转换。
    void addTransformer(ClassFileTransformer transformer, boolean canRetransform);
 
    //在类加载之前，重新定义 Class 文件，ClassDefinition 表示对一个类新的定义，如果在类加载之后，需要使用 retransformClasses 方法重新定义。addTransformer方法配置之后，后续的类加载都会被Transformer拦截。对于已经加载过的类，可以执行retransformClasses来重新触发这个Transformer的拦截。类加载的字节码被修改后，除非再次被retransform，否则不会恢复。
    void addTransformer(ClassFileTransformer transformer);
 
    //删除一个类转换器
    boolean removeTransformer(ClassFileTransformer transformer);
 
 
    //在类加载之后，重新定义 Class。这个很重要，该方法是1.6 之后加入的，事实上，该方法是 update 了一个类。
    void retransformClasses(Class<?>... classes) throws UnmodifiableClassException;
 
 
 
    //判断一个类是否被修改
    boolean isModifiableClass(Class<?> theClass);
 
    // 获取目标已经加载的类。
    @SuppressWarnings("rawtypes")
    Class[] getAllLoadedClasses();
 
    //获取一个对象的大小
    long getObjectSize(Object objectToSize);
 
}
```
#### 获取目标JVM已加载类
下面我们简单实现一个能够获取目标JVM已加载类的`agentmain-Agent`
```java
package com.java.agentmain.instrumentation;
 
import java.lang.instrument.Instrumentation;
 
public class Java_Agent_agentmain_Instrumentation {
    public static void agentmain(String args, Instrumentation inst) throws InterruptedException {
        Class [] classes = inst.getAllLoadedClasses();
 
        for(Class cls : classes){
            System.out.println("------------------------------------------");
            System.out.println("加载类: "+cls.getName());
            System.out.println("是否可被修改: "+inst.isModifiableClass(cls));
        }
    }
}
```
注入目标进程，结果如下
```
Hello World!
Hello World!
------------------------------------------
加载类: com.java.agentmain.instrumentation.Java_Agent_agentmain_Instrumentation
是否可被修改: true
------------------------------------------
加载类: Sleep_Hello
是否可被修改: true
------------------------------------------
加载类: com.intellij.rt.execution.application.AppMainV2$1
是否可被修改: true
------------------------------------------
加载类: com.intellij.rt.execution.application.AppMainV2
是否可被修改: true
------------------------------------------
加载类: com.intellij.rt.execution.application.AppMainV2$Agent
是否可被修改: true
 
...
```
#### transform 

在Instrumentation接口中，我们可以通过`addTransformer()`来添加一个`transformer`（转换器），关键属性就是`ClassFileTransformer`类。
```java
//增加一个Class 文件的转换器，转换器用于改变 Class 二进制流的数据，参数 canRetransform 设置是否允许重新转换。
    void addTransformer(ClassFileTransformer transformer, boolean canRetransform);
```
`ClassFileTransformer`接口中只有一个`transform()`方法，返回值为字节数组，作为转换后的字节码注入到目标JVM中。
```java
public interface ClassFileTransformer {
 
    /**
     * 类文件转换方法，重写transform方法可获取到待加载的类相关信息
     *
     * @param loader              定义要转换的类加载器；如果是引导加载器如Bootstrap ClassLoader，则为 null
     * @param className           完全限定类内部形式的类名称,格式如:java/lang/Runtime
     * @param classBeingRedefined 如果是被重定义或重转换触发，则为重定义或重转换的类；如果是类加载，则为 null
     * @param protectionDomain    要定义或重定义的类的保护域
     * @param classfileBuffer     类文件格式的输入字节缓冲区（不得修改）
     * @return 返回一个通过ASM修改后添加了防御代码的字节码byte数组。
     */
    
    byte[] transform(  ClassLoader         loader,
                String              className,
                Class<?>            classBeingRedefined,
                ProtectionDomain    protectionDomain,
                byte[]              classfileBuffer)
        throws IllegalClassFormatException;
}
```
在通过 `addTransformer` 注册一个transformer后，每次定义或者重定义新类都会调用transformer。所谓定义，即是通过`ClassLoader.defineClass`加载进来的类。而重定义是通过`Instrumentation.redefineClasses`方法重定义的类。

当存在多个转换器时，转换将由 `transform` 调用链组成。 也就是说，一个 `transform` 调用返回的 byte 数组将成为下一个调用的输入（通过 `classfileBuffer` 参数）。

转换将按以下顺序应用：

- 不可重转换转换器
- 不可重转换本机转换器
- 可重转换转换器
- 可重转换本机转换器
至于transformer中对字节码的具体操作，则需要使用到Javassisit类。

### Javassist
Java 字节码以二进制的形式存储在 .class 文件中，每一个.class文件包含一个Java类或接口。Javaassist 就是一个用来处理Java字节码的类库。它可以在一个已经编译好的类中添加新的方法，或者是修改已有的方法，并且不需要对字节码方面有深入的了解。同时也可以通过手动的方式去生成一个新的类对象。其使用方式类似于反射。

####  ClassPool


















