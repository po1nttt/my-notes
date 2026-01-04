# 0x01 前言
java不像php一样有那么强的动态特性，php中有很多可以动态执行，所以能衍生出多种多样的一句话木马。

但java中的反射可以提供一些动态特性
比如如下代码，在不知道传入参数值为什么的时候，你是不知道他的作用是什么的
```java
public void execute(String className, String methodName) throws Exception {
		Class clazz = Class.forName(className); 
		clazz.getMethod(methodName).invoke(clazz.newInstance()); 
}
```


# 0x02 初步分析
```java
package test.serilize;  
  
import java.lang.reflect.Constructor;  
  
public class reflection {  
    public static void main(String[] args) throws Exception{  
        Person person=new Person();  
        Class c =person.getClass();
```
以上，我们先用反射调用一个Class
反射就是操作Class
- 从任意一个类的原型class中实例化一个新的对象
-  获取类里的属性
- 调用类里的方法
## 1.从原型class中实例化一个新的对象

有两种情况，一种是无参构造，一种有参构造
**其本质是：由于构造方法可能重载，反射看不到源码上下文，只能通过传参的内容来找到我们想要的那个构造器！所以我们应该先用getConstructor来指定参数类型，拿到我们想要的构造器，再去用这个构造器实例化一个对象**

### 反射进行无参构造
直接使用
```java
package test.serilize;  
  
import java.lang.reflect.Constructor;  
  
public class reflection {  
    public static void main(String[] args) throws Exception{  
        Person person=new Person();  
        Class c =person.getClass();
		c.newInstance();//新建一个无参对象
```
### 反射进行有参构造

![[Pasted image 20251124214425.png]]
如图我们可以看到getConstructor是接受一个class的泛型

我们自己写的Person类中的有参构造需要传入一个String和int
![[Pasted image 20251124214512.png]]

所以我们可以这样来传入参数![[Pasted image 20251124214731.png]]
## 2.获取类中的属性

```java
package test.serilize;  
  
import java.lang.reflect.Constructor;  
  
public class reflection {  
    public static void main(String[] args) throws Exception{  
        Person person=new Person();  
        Class c =person.getClass();
        //获取类里的属性
        
```
```java
package test.serilize;  
  
import java.lang.reflect.Constructor;  
import java.lang.reflect.Field;  
  
public class reflection {  
    public static void main(String[] args) throws Exception{  
        Person person=new Person();  
        Class c =person.getClass();  
  
		Field[] personfields1=c.getFields();//getFields会返回这个类的所有的public成员变量  
        for (Field aaa:personfields1){  
            System.out.println(aaa);  
            System.out.println("----------------------------");  
        }  
        Field[] personfields2=c.getDeclaredFields();//getFields会返回这个类的所有的成员变量  
        for (Field aaa:personfields2){  
            System.out.println(aaa);  
        }  
    }  
}
```
我们定义的Person类中
name是public的
age是private的
所以理解`getDeclaredFields()`可以返回这个类中的所有成员变量
`getFields()`可以返回这个类中的public成员变量，以及其父类的所有public成员变量
![[Pasted image 20251124222537.png]]
也可以尝试修改其中的成员变量
如下
我们修改Person这个对象的name属性，注意`set()`的第一个参数是要修改的对象，第二个参数是要修改的值
![[Pasted image 20251124223524.png]]
public属性我们可以修改的话，那我们自然想到可以用`getDeclearedField()`来修改私有属性吧！

但实则不然...![[Pasted image 20251124224344.png]]
他说这个属性是私有的我们不能修改它
所以我们可以添加一句
`namefield.setAccessible(true);`来让我们可以访问她的私有属性

![[Pasted image 20251124224324.png]]


## 3.调用类里的方法
我们同理使用的是`getMethods()`
![[Pasted image 20251124224831.png]]
看到不仅打印出了我们自己在person中构造的方法
还有继承Object类的各种方法

那我们同理看看能不能调用其中的一个方法呢
使用`invoke`
![[Pasted image 20251124225611.png]]
ok成功，但是要注意，我们思考，由于java中方法的重构，我们在任何时候调用一个方法的时候，都需要考虑会不会有重构的情况出现，所以我们传入一个变量类型，来让java能唯一确定我们想调用的那个方法。
调用私有方法如上同理~
![[Pasted image 20251124230019.png]]




# 0x03 深入分析反射



这里，我们先加载一个传入的类，再获取一个无参方法，实例化对象之后执行刚刚获取的方法

上面的例例子中，演示了几个在反射里极为重要的方法： 
获取类的方法： forName 
实例例化类对象的方法： newInstance 
获取函数的方法： getMethod 
执行函数的方法： invoke

这里补充：
`forname`不是获取类的唯一途径，通常来说有如下三种方式获取一个类，也就是`java.lang.Class`对象：
- `obj.getClass()` 如果上下文中存在某个类的实例例 `obj`，那么我们可以直接通过 `obj.getClass()`来获取她的类
- `Test.class` 如果你已经加载了了某个类，只是想获取到它的` java.lang.Class` 对象，那么就直接 拿它的` class` 属性即可。这个方法其实不不属于反射。 
- `Class.forName` 如果你知道某个类的名字，想获取到这个类，就可以使⽤用 `forName `来获取


在安全研究中，我们使⽤用反射的一大目的，就是绕过某些沙盒。比如，上下文中如果只有Integer类型的 数字，我们如何获取到可以执行行命令的Runtime类呢？也许可以这样（伪代码）： 
`1.getClass().forName("java.lang.Runtime")`

也就是说，我们只需要有任意一个类，都可以通过调用`class.forName()`方法来调用java的可以执行命令类。


## forName方法具体分析

forName有两个函数重载： 
`Class forName(String name) `
`Class forName(String name, **boolean** initialize, ClassLoader loader)`

第一个就是我们最常见的获取class的方式，其实可以理理解为第二种方式的一个封装

```java
Class.forName(className) 
// 等于 
Class.forName(className, true, currentLoader)
```

默认情况下，` forName `的第一个参数是类名；第二个参数表示是否初始化；第三个参数就 是`ClassLoader`。 

`ClassLoader` 是什什么呢？它就是⼀一个“加载器器”，告诉Java虚拟机如何加载这个类。Java默认的 这个类名是类完整路路径，如 java.lang.Runtime 。

`initialize`经常被误解

使用`.class`来创建Class对象的引用的时候，不会自动初始化该Class对象，使用forName()会自动初始化该Class对象
![[Pasted image 20251124132810.png]]


图中说“构造函数，初始化时执行”，其实在`forName`的时候，构造函数并不会执行，即使我们设置initialize=true

所以这个初始化究竟指的是什么？

可以将这个初始化理解为“类的初始化"。我们先看看如下这个类：
```java
public class TrainPrint { 
{ 
System.out.printf("Empty block initial %s\n", this.getClass());
} 
 static { 
 System.out.printf("Static initial %s\n", TrainPrint.class); 
  } 
 public TrainPrint() {
  System.out.printf("Initial %s\n", this.getClass()); 
  } 
}
```

我们运行一下就知道了，首先调用的是static {}，其次是{}，最后是构造函数。


其中静态代码块static{}就是在“类初始化调用的”

而{}中的代码 会放在构造函数的super（）后面，但是再当前构造函数内容的前面。

 `static { ... }`： 在 **类加载时** 执行，只会执行一次。

 `{ ... }`：在 **对象创建时** 执行，每次 `new TrainPrint()` 都会运行。
          执行位置：在构造函数之前，但在 `super()` 调用之后。

 `TrainPrint()`： 在实例初始化块之后执行。



所以说，forName中的initialize=true其实就是告诉Java虚拟机是否执行”类初始化“。

那么我们假设，我们有如下函数，其中函数的参数name可控：
```java
public void ref(String name) throws Exception { 
	Class.forName(name); 
}
```

我们就可以编写一个恶意类，将恶意代码放置在static {}中，从而执行：
```java
import java.lang.Runtime; 
import java.lang.Process; 
public class TouchFile { 
	static { 
		try { 
		Runtime rt = Runtime.getRuntime(); 
		String[] commands = {"touch", "/tmp/success"}; 
		Process pc = rt.exec(commands); 
		pc.waitFor(); 
		} catch (Exception e) { 
		// do nothing 
		} 
 }
```



## 通过反射来实例化一个类
在正常情况下，除了系统类，如果我们想拿到一个类，需要先 import 才能使用。而使用forName就不 需要，这样对于我们的攻击者来说就十分有利，我们可以加载任意类

另外，我们经常在一些源码里看到，类名的部分包含\$符号，比如`fastjson`在 先将`$`替换成`.`

`$`的作用是查找内部类

Java的普通类 C1 中支持编写内部类C2，而在编译的时候，会生成两个文件：` C1.class` 和 `C1$C2.class` ，我们可以把他们看作两个无关的类，通过 `Class.forName("C1$C2") `即可加载这个内 部类。

获得类以后，我们可以继续使用反射来获取这个类中的属性、方法，也可以实例化这个类，并调用方法。

`calss.newInstance()`的作用就是调用这个类的无参构造函数。不过，有的时候`newInstance`总不成功原因可能是：
	1.使用的类里没有无参构造
	 2.使用的类构造函数时私有的
常见又java.lang.Runtime，这个类在我们构造命令执行的Payload时很常见，但我们不能直接这样来执行命令
```java
Class clazz = Class.forName("java.lang.Runtime");
 clazz.getMethod("exec", String.class).invoke(clazz.newInstance(), "id");
```
原因时Runtime类的构造方法是私有的


---
为什么非要写成私有的呢？
在web应用上，数据库连接只需要建立一次，而不是每次用到数据库的时候再建立一个连接，此时作为开发者你就可以将数据库连接使用的构造函数设置为私有，然后写一个静态方法来获取：
这就是--（单例模式）

```java
public class TrainDB {
 private static TrainDB instance = new TrainDB();
 public static TrainDB getInstance() {
	  return instance; 
  } 
  private TrainDB() { // 建立连接的代码... } }

```

这样我们就可以确保，instance为类内部唯一的对象，只能通过`getInstance()`来获取对象

防止外部随意new新对象

---

回过头来，Runtime类就是单例模式，我们只能通过`Runtime.getRuntime()`来获取到`Runtime`对象
```java
Class clazz = Class.forName("java.lang.Runtime"); 
clazz.getMethod("exec",String.class).invoke(clazz.getMethod("getRuntime").invoke(clazz), "calc.exe");
```
`getMethod`的作用是通过反射机制来获取一个类的某个特定的public方法，而我们知道由于重载的原因，我们不能只用过函数名字来确定一个函数，所以在调用`getMethod`的时候，我们需要传给他你需要获取的函数的参数类型列表。
比如这里的 Runtime.exec 方法有6个重载
![[Pasted image 20251124160018.png]]
我们使用`getMethod("exec", String.class)`来获取第一个方法
`invoke`的作用是执行方法，对于第一个参数：
如果这个方法是一个普通方法，那么第一个参数是类对象
如果这个方法是一个静态方法，那么第一个参数是类

我们正常执行方法是` [1].method([2], [3], [4]...)`其实在反射里就是 `method.invoke([1], [2], [3], [4]...)`

所以我们把上述payload分解一下就是：
```java
Class clazz = Class.forName("java.lang.Runtime"); 
Method execMethod = clazz.getMethod("exec", String.class); 
Method getRuntimeMethod = clazz.getMethod("getRuntime"); 
Object runtime = getRuntimeMethod.invoke(clazz); 
execMethod.invoke(runtime, "calc.exe");
```
---

我们思考：
- 如果一个类没有无参构造方法，也没有类似的单例模式里的静态方法，我们怎么通过反射实例化该类呢？
- 如果一个方法或构造方法是私有方法，我们能否执行呢？

回答：
### 第一个问题
我们需要用到一个新的反射方法 `getConstructor`
和`getMethod` 类似， `getConstructor `接收的参数是构造函数列表类型，因为构造函数也支持重载， 所以必须用参数列表类型才能唯一确定一个构造函数。


获取到构造函数后，我们使用`newInstance`来执行。

比如，我们常用的另一种执行命令的方式`ProcessBuilder`，我们使用反射来获取其构造函数，然后调用 start() 来执行命令：

```java
Class clazz = Class.forName("java.lang.ProcessBuilder"); 
((ProcessBuilder)clazz.getConstructor(List.class).newInstance(Arrays.asList("calc.exe"))).start();
```

ProcessBuilder有两个构造函数： 
- `public ProcessBuilder(List<String> command)`
- `public ProcessBuilder(String... command)`
上面用到了第一种形式的构造函数 所以在他调用getConstructor的时候传入的是List.class
 但是我们看到，前面的Payload用到了java里的强制类型转换，有时候在漏洞利用的时候是没有这种语法的，所以我们仍旧需要用反射来完成这一步。
如下

```java
Class clazz = Class.forName("java.lang.ProcessBuilder"); clazz.getMethod("start").invoke(clazz.getConstructor(List.class).newInstance(Arrays.asList("calc.exe")));
```

我们把他拆成两部分
1.`clazz.getMethod("start").invoke(....................)`
这边是获取start方法用来启动外部进程后执行反射得到的方法
2.`clazz.getConstructor(List.class).newInstance(Arrays.asList("calc.exe")`
用来获取ProccessBuilder的构造器并且往里传入一个只有calc.exe的列表准备运行这个程序
也就是我们创造了一个ProccessBuilder的实例

把他放到invoke中进行执行

- 加载 `ProcessBuilder` 类。
    
- 通过反射调用它的构造函数，创建一个对象，命令是 `"calc.exe"`。
    
- 通过反射获取 `start()` 方法。
    
- 用 `invoke` 在这个对象上调用 `start()`。
    
- 结果：启动 Windows 的计算器。


那么如果我们想要使用`public ProcessBuilder(String... command)`这个构造函数呢
我们需要怎样用反射来执行呢？
这里涉及到Java中的可变长参数(varargs)了。
正如其他语言一样，Java也支持可变长参数，就是当你 定义函数的时候不确定参数数量的时候，可以使用 ... 这样的语法来表示“这个函数的参数个数是可变的”
很容易猜到在底层实现的时候应该是会把他编译成一个数组

```java
public void hello(String[] names) {} 
public void hello(String...names) {}
```
以上两者是完全等效的

由此，如果我们有一个数组想给hello函数
只需要
```java
String[] names = {"hello", "world"}; 
hello(names);
```

所以对于反射，如果有可变长参数，我们只需要把他看成数组
所以，我们将字符串数组的类`String[].class`传给`getConstructor`
获取`ProcessBuilder`的第二种构造函数
```java
Class clazz = Class.forName("java.lang.ProcessBuilder"); clazz.getConstructor(String[].class);
```
在调用newInstance的时候，因为这个函数本身接受的是一个可变长参数，我们传给`ProcessBuilder`的也是一个可变长的参数，二者叠加为一个二位数组，所以整个Payload如下：
```java
Class clazz = Class.forName("java.lang.ProcessBuilder"); ((ProcessBuilder)clazz.getConstructor(String[].class).newInstance(new String[][]{{"calc.exe"}})).start();
```



### 第二个问题
这就涉及到 getDeclared 系列的反射了，与普通的 getMethod 、 getConstructor 区别是：
- getMethod 系列方法获取的是当前类中所有公共方法，包括从父类继承的方法 
-  getDeclaredMethod 系列方法获取的是当前类中“声明”的方法，是实在写在这个类里的，包括私 有的方法，但从父类里继承来的就不包含了

用法上`getDeclared`和`getMethod`类似
`getDeclaredConstructor`和`getConstructor`类似

举个例子，我们前文说过`Runtime`这个类的构造函数是私有的，我们需要用Runtime.get
Runtime() 来获取对象,但是现在我们可以用 getDeclaredConstructor 来获取这个私有的构造方法来实例 化对象，进而执行命令：
```java
Class clazz = Class.forName("java.lang.Runtime"); 
Constructor m = clazz.getDeclaredConstructor(); 
m.setAccessible(true); 
clazz.getMethod("exec", String.class).invoke(m.newInstance(), "calc.exe");
```

可见，这里使用了一个方法 setAccessible ，这个是必须的。我们在获取到一个私有方法后，必须用 setAccessible 修改它的作用域，否则仍然不能调用



# 0x03反射在反序列化漏洞中的应用

我们可以通过反射来改属性，方法，来定制一个我们需要的对象

invoke方法中是通过字符串来获取的，是通过字符串来获取方法的，就有点php动态的感觉了

通过Class类来创建对象，因为Class类是可以序列化的，所以我们可以序列化传入Class对象，但在内存中让他序列化另一个我们本不可以序列化的对象。
比如命令执行的Runtime类不可序列化
所以我们可以找某个invoke方法以getRuntime为字符串传进去来调用这个方法。

























































