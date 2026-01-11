
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









































