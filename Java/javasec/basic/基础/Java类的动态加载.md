
# 加载器

我们先讲一下java中的集中加载器
# 引导类加载器
> 引导类加载器(BootstrapClassLoader)，底层原生代码是 C++ 语言编写，属于 JVM 一部分。

不继承 `java.lang.ClassLoader` 类，也没有父加载器，主要负责加载核心 java 库(即 JVM 本身)，存储在 `/jre/lib/rt.jar` 目录当中。(同时处于安全考虑，`BootstrapClassLoader` 只加载包名为 `java`、`javax`、`sun` 等开头的类)。
## 扩展类加载器（ExtensionsClassLoader）
扩展类加载器(ExtensionsClassLoader)，由 `sun.misc.Launcher$ExtClassLoader` 类实现，用来在 `/jre/lib/ext` 或者 `java.ext.dirs` 中指明的目录加载 java 的扩展库。Java 虚拟机会提供一个扩展库目录，此加载器在目录里面查找并加载 java 类。

##  App类加载器（AppClassLoader）
App类加载器/系统类加载器（AppClassLoader），由 `sun.misc.Launcher$AppClassLoader` 实现，一般通过通过( `java.class.path` 或者 `Classpath` 环境变量)来加载 Java 类，也就是我们常说的 classpath 路径。通常我们是使用这个加载类来加载 Java 应用类，可以使用 `ClassLoader.getSystemClassLoader()` 来获取它。

# 双亲委派

## 从报错的角度来看看双亲委派
```java
package java.lang;  
  
// 双亲委派的错误代码  
public class String {  
  
    public String toString(){  
        return "hello";  
 }  
  
    public static void main(String[] args) {  
        String s = new String();  
 s.toString();  
 }  
}
```
看起来一点问题没有哈~
结果居然报错了！而且非常离谱
![[Pasted image 20251130135934.png]]
这不是已经定义了 main 方法吗？？为什么还会报错，这里就提到双亲委派机制了，双亲委派机制是从安全角度出发的。

首先，我们要知道 Java 的类加载器是分很多层的，如图。
![[Pasted image 20251130140028.png]]

我们的类加载器在被调用时，也就是在 new class 的时候，它是以这么一个顺序去找的 BOOT —> EXC —-> APP

如果 BOOT 当中没有，就去 EXC 里面找，如果 EXC 里面没有，就去 APP 里面找。

所以在这里根本的报错原因就是
1.首先我们想加载我们自己的String的时侯，会先委培到他的父类加载器进行加载
2.现在BOOT加载器里加载了java.lang.String（java中jar包自己的String）这个东西
2.于是不会加载我自己String类，导致我们自己的main方法没被加载


##  从正确的角度感受双亲委派机制
```java
package src.DynamicClassLoader;  
  
// 双亲委派的正确代码  
public class Student {  
  
    public String toString(){  
        return "Hello";  
 }  
  
    public static void main(String[] args) {  
        Student student = new Student();  
  
 System.out.println(student.getClass().getClassLoader());  
 System.out.println(student.toString());  
 }  
}
```
![[Pasted image 20251130141112.png]]
加载了APPclassloader

# 类的加载过程
讲完了双亲委派机制我们来看看我们自己写的一个类的加载过程

一个类的加载过程如下
![[Pasted image 20251125100304.png]]

# 使用阶段


![[Pasted image 20251125095950.png]]
我们先定制一个类，然后分别看看这个类里的静态代码块、构造代码块、无参构造器的加载顺序
![[Pasted image 20251125100220.png]]
![[Pasted image 20251125100044.png]]
可以发现，顺序为
静态代码块>构造代码块>有参构造器（无参构造器）

-----


那我们调用一个静态方法，发现只加载了静态代码块和静态方法


![[Pasted image 20251125100612.png]]

---
给类中的public static int属性进行赋值的时候，也会调用静态代码块
![[Pasted image 20251125101032.png]]
所以，我们要分清对    **对象**   还是  **类**    进行操作

如果是对象，肯定要调用构造器
如果是类，就不用调用构造器

----
# 初始化阶段

所以我们可以猜测到，static静态代码块在初始化的时候就已经加载

而其他的静态方法、构造代码块、有参无参构造器，都在使用阶段

# 初始化之前
可以看到我们获取Person的类，调用的是java的内置关键字，并没有调用初始化

![[Pasted image 20251125101937.png]]




---
# 反射Forname的类加载
我们通过forname来获取一个class类看看会怎么样
![[Pasted image 20251125113730.png]]
我们可以看到他进行初始化了
我们跟进forName可以看到forName其实有很多重载版本
最全的是这个，我们需要传入三个参数，类名，是否初始化，类加载器。一共这几个

![[Pasted image 20251125114109.png]]
所以我们试试能不能让他不初始化？
这里的classloader是一个抽象类，但里面有一个静态方法getSystemClassLoader方法，可以拿到这个加载器。这个东西在JVM启动的时候就已经加载好的，跟我们的类没有任何关系，无需考虑太多。
![[Pasted image 20251125114521.png]]
![[Pasted image 20251125114829.png]]
好的哦我们就没有初始化

# Classloador类
先打印出来看看怎么个事
![[Pasted image 20251125115051.png]]
返回的ClassLoaders$AppClassLoader
是一个ClassLoaders的一个内部类。

我们实例化这个对象
发现成功初始化了这个对象并且实例化了
![[Pasted image 20251125132028.png]]
这里我们通过调试我们可以发现，在loadClass时没有初始化，但是在下面
newInstance的时候实例化对象前进行初始化。
![[Pasted image 20251125132859.png]]


---


# 总结
我们定义一个Person类然后对此类进行各种调用

```java
package src.DynamicClassLoader;  
  
// 存放代码块  
public class Person {  
    public static int staticVar;  
 public int instanceVar;  
  
 static {  
        System.out.println("静态代码块");  
 }  
  
    {  
        System.out.println("构造代码块");  
 }  
  
    Person(){  
        System.out.println("无参构造器");  
 }  
    Person(int instanceVar){  
        System.out.println("有参构造器");  
 }  
  
    public static void staticAction(){  
        System.out.println("静态方法");  
 }  
}
```

## 实例化对象
通过 `new` 关键字实例化的对象，先调用**静态代码块**，然后调用**构造代码块**，最后根据实例化方式不同，调用不同的构造器
##  调用静态方法
不实例化对象直接调用静态方法，会先调用类中的**静态代码块**，然后调用**静态方法**

##  对类中的静态成员变量赋值

在对静态成员变量赋值前，会调用**静态代码块**

##  使用 class 获取类
利用 `class` 关键字获取类，并不会加载类，也就是什么也不会输出。

##  使用 forName 获取类

我们写三种 `forName` 的方法调用。
```java
package src.DynamicClassLoader;  
  
// 代码块的启动器  
public class Main {  
    public static void main(String[] args) throws ClassNotFoundException{  
 		Class.forName("src.DynamicClassLoader.Person");
 	}  
}
// 静态代码块
```
```java
package src.DynamicClassLoader;  
  
// 代码块的启动器  
public class Main {  
    public static void main(String[] args) throws ClassNotFoundException{   
 	Class.forName("src.DynamicClassLoader.Person", true, ClassLoader.getSystemClassLoader());  
 }  
}
// 静态代码块
```
```java
package src.DynamicClassLoader;  
  
// 代码块的启动器  
public class Main {  
    public static void main(String[] args) throws ClassNotFoundException{   
 	Class.forName("src.DynamicClassLoader.Person", false, ClassLoader.getSystemClassLoader());
 }  
}
//没有输出
```
`Class.forName(className)`和`Class.forName(className, true, ClassLoader.getSystemClassLoader())`等价，这两个方法都会调用类中的**静态代码块**，如果将第二个参数设置为`false`，那么就不会调用**静态代码块**（因为false本身就是告诉我们不要加载）

##  使用 ClassLoader.loadClass() 获取类
```java
package com.xiinnn.i.test;

public class Main {
    public static void main(String[] args) throws ClassNotFoundException {
        Class.forName("com.xiinnn.i.test.Person", false, ClassLoader.getSystemClassLoader());
    }
}
//没有输出
```

`ClassLoader.loadClass()`方法不会进行类的初始化，当然，如果后面再使用`newInstance()`进行初始化，那么会和`实例化对象`一样的顺序加载对应的代码块。



