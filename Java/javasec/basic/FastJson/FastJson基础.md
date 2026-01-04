
# 前言

**Fastjson** 是由阿里巴巴开源的一个高性能 **JSON 解析库**，专门用于 Java 语言。它的主要功能是在 Java 对象（POJO） 与 JSON 字符串之间进行相互转换。

Fastjson 主要解决两个核心问题：

- **序列化（Serialization）：** 将 Java 对象转换成 JSON 格式的字符串。
    
- **反序列化（Deserialization）：** 将 JSON 字符串解析成 Java 对象。

使用 Fastjson 非常简单，通常只需要调用两个静态方法：

- `JSON.toJSONString(obj)`：对象转字符串。
    
- `JSON.parseObject(jsonString, Class.class)`：字符串转对象。

# 代码 demo

## 序列化代码实现
这里通一些小代码来了解下其中的特性

添加fastjson依赖
```xml
<dependency>  
    <groupId>com.alibaba</groupId>  
    <artifactId>fastjson</artifactId>  
    <version>1.2.24</version>  
</dependency>
```


写一个学生类，进行反序列化和输出
```java
package FastJsonTest;  
  
import com.alibaba.fastjson.JSON;  
import com.alibaba.fastjson.serializer.SerializerFeature;  
  
public class Student {  
    private String name;  
    private int age;  
  
    public Student() {  
        System.out.println("构造函数");  
    }  
  
    public String getName() {  
        System.out.println("getName");  
        return name;  
    }  
  
    public void setName(String name) {  
        System.out.println("setName");  
        this.name = name;  
    }  
  
    public int getAge() {  
        System.out.println("getAge");  
        return age;  
    }  
  
    public void setAge(int age) {  
        System.out.println("setAge");  
        this.age = age;  
    }  
  
    public static void main(String[] args) {  
        Student student = new Student();  
        student.setName("po1nt");  
        student.setAge(18);  
        String jsonString = JSON.toJSONString(student, SerializerFeature.WriteClassName);  
        System.out.println(jsonString);  
    }  
}
```

打断点进去看看怎么序列化的
这里值得关注的是
先new了一个 `SerializeWriter`对象，我们的序列化在这一步就完成了
并且值得注意的是其中`DEFAULT_TYPE_KEY` 为 “@type”
![[Pasted image 20251223024706.png]]

![[Pasted image 20251223024838.png]]
其中走入 `SerializeWriter`中有一些初始值，赋值给out对象

![[Pasted image 20251223193431.png]]

在下面作为参数传入 `JSONSerializer()`
里面有一些基本的属性
![[Pasted image 20251223193806.png]]
通过toString，最终把我们的对象通过字符串形式输出
然后释放内存
![[Pasted image 20251223194005.png]]
ok序列化的流程大致是这样，先有一个了解，后面会详细写

其中  第一个参数是我们要序列化的对象，第二个参数 是`JSON.toJSONString()`中的一个设置属性值，设置之后在序列化的时候会多写入一个@type，即写上被序列化的类名，例如 `"@type":"FastJsonTest.Student"`，type 可以指定反序列化时候，告诉JVM应该还原为什么类型的对象，并且调用其 `getXXX`/`setXXX`/`is` 方法，对其中的属性进行赋值。
```java
String jsonString = JSON.toJSONString(student, SerializerFeature.WriteClassName);|
```
直观一点：
```java
// 设置了SerializerFeature.WriteClassName  
构造函数  
setName  
setAge  
getAge  
getName  
{"@type":"org.example.Student","age":6,"name":"John"}  
   
// 未设置SerializerFeature.WriteClassName  
构造函数  
setName  
setAge  
getAge  
getName  
{"age":6,"name":"John"}
```

## 反序列化代码实现
调用 `JSON.parseObject()`，代码如下


```java
package FastJsonTest;  
  
import com.alibaba.fastjson.JSON;  
import com.alibaba.fastjson.parser.Feature;  
  
public class StudentUnserialize1 {  
    public static void main(String[] args) {  
        String jsonString = "{\"@type\":\"FastJsonTest.Student\",\"age\":18,\"name\":\"po1nt\"}";  
        Student student = JSON.parseObject(jsonString, Student.class, Feature.SupportNonPublicField);  
        System.out.println(student);  
        System.out.println(student.getClass().getName());  
    }  
}
```
正如我们刚所说的，先调用构造函数生成一个对象，然后调用里面的 `SetXXX`方法来进行赋值属性，最终还原对象。
![[Pasted image 20251223200710.png]]

其中 `Student student = JSON.parseObject(jsonString, Student.class, Feature.SupportNonPublicField);`

第二个参数是显式告诉JVM对象的类型，那么我们试试只告诉他
@type ,而不显式反序列化会怎么样

```java
package FastJsonTest;  
  
import com.alibaba.fastjson.JSON;  
 
  
public class StudentUnserialize1 {  
    public static void main(String[] args) {  
        String jsonString = "{\"@type\":\"FastJsonTest.Student\",\"age\":18,\"name\":\"po1nt\"}";  
        JSON.parseObject(jsonString);  
        System.out.println("---------");  
        System.out.println(JSON.parseObject(jsonString));  
        System.out.println("---------");  
        System.out.println(JSON.parseObject(jsonString).getClass().getName());  
 
    }  
}
```
输出如下
```
构造函数
setAge
setName
getAge
getName
---------
构造函数
setAge
setName
getAge
getName
{"name":"po1nt","age":18}
---------
构造函数
setAge
setName
getAge
getName
com.alibaba.fastjson.JSONObject

进程已结束，退出代码为 0
```
可以看到我们最终获得了一个 `JSONObject`对象，这是为什么呢？
事实上，我们反序列化的时候，FsatJson看到了 `@type`创建了 `Student`实例，调用set方法来填充属性，但我们不显示指定返回类型时 `JSON.parseObject()`默认返回值类型为`JSONObject`
FastJson 必须把刚刚创建好的 `Student` 对象**转换**成一个 `JSONObject`（本质上是一个 Map）
![[Pasted image 20251223231027.png]]

在将 Java 对象转换为 `JSONObject` 的过程中，FastJson 需要获取该对象的所有属性值。根据 Java Bean 的规范，它会通过**反射**去寻找并调用所有的 **getter 方法**（即 `getName()` 和 `getAge()`）来获取属性值，以便放入 Map 中。

通过打断点进去可以看到 `parseObject`确实会将得到的对象强转为`JSONObject`
![[Pasted image 20251223230828.png]]

---
如果我们把 `parseObject()`更改为 `parse()`呢？

```java
package FastJsonTest;  
  
import com.alibaba.fastjson.JSON;  
  
public class StudentUnserialize1 {  
    public static void main(String[] args) {  
        String jsonString = "{\"@type\":\"FastJsonTest.Student\",\"age\":18,\"name\":\"po1nt\"}";  
        JSON.parse(jsonString);  
        System.out.println("---------");  
        System.out.println(JSON.parse(jsonString));  
        System.out.println("---------");  
        System.out.println(JSON.parse(jsonString).getClass().getName());  
    }  
}
```
输出如下
```
构造函数
setAge
setName
---------
构造函数
setAge
setName
FastJsonTest.Student@38cccef
---------
构造函数
setAge
setName
FastJsonTest.Student

进程已结束，退出代码为 0
```
他会根据JSON中的type恢复为对象原本的类型，如果JSON中不传入type，那么会恢复为`JSONObject`对象。


第三个参数是设置可以获得私有属性

当我们注释掉SetAge()方法的时候，运行如下
![[Pasted image 20251223202423.png]]
可以看到，在反序列化的时候，并未调用SetAge来给age属性赋值

但是调用getAge的时候也可以拿到他的age属性。

---

# 深入反序列化流程

 这里再补充一点零散的底层的东西，一般反序列化无论是 `Parse还是ParseObject`最终都会走到一个 `Parse`里并且调用 `DefaultJSONParser`来对字符串进行解析，这的传参：
 `text`：是想要解析的 **JSON 字符串原文**。
 
 `ParserConfig.getGlobalInstance()`：这是解析器的 配置项
它决定了解析器如何处理特定的类。它包含了： 
AutoType 白名单/黑名单：决定哪些类允许通过 `@type` 加载。
反序列化器注册表：记录了不同类型（如 `Map`、`Collection` 或自定义类）应该使用哪个具体的反序列化实现类。  
 字段处理逻辑：例如是否支持非公开字段等。

`features` ：这是解析时的 **特性标记（位掩码）**。它决定了解析过程中的一些开关行为。
通过这个整数，FastJson 可以高效地检查是否需要支持某些特殊语法，比如是否允许没有双引号的键、是否忽略未知的字段等。

然后通过 `parser.parse();`进行解析，所有的解析逻辑都在这个 `parser.parse()`里
![[Pasted image 20251223231421.png]]
走进 `parser.parse();`里 有一个很大的swich-case
其中最重要的是这个 `parseObject()`
![[Pasted image 20251223232352.png]]

进去之后，有各种各样的边界判断，然后判断各种字符串，重点是走到下面这里
![[Pasted image 20251223233208.png]]
还记得我们之前说 `DEFAULT_TYPE_KEY`其实就是 `@type`吗，这里判断key是 `@type`后
先loadclass，往下走还是一些判断，到了下图这里
`getDeserializer`获取反序列化器
`return deserializer.deserialze(this, clazz, fieldName);`用反序列化器去反序列化
![[Pasted image 20251223234109.png]]
进入 `getDeserializer`可以看到，他先去寻找内置的如下图，提前配置好的反序列化器，然后下面有一个黑名单（但是这个黑名单只有Therad线程类），然后各种方式找 ，找不到最后会当成JavaBean来创建一个。
![[Pasted image 20251223234415.png]]
创建反序列化器之前会先收集你这个javabean中的各种信息，然后进行build
![[Pasted image 20251223234944.png]]
进入这个build之后会发现
其中收集了默认构造器呀，所有私有字段呀
![[Pasted image 20251223235305.png]]
通过for循环，找setter getter
![[Pasted image 20251223235551.png]]
进行一些逻辑，最后创建出了一个 `JavaBeanInfo`
然后 拿到反序列化器，得到反序列化对象
调用里面的 constructor getter setter

## 结论

fastjson 在反序列化的时候会去找我们在 `@type` 中规定的类是哪个类，然后在反序列化的时候会自动调用这些 setter 与 getter 方法的调用，注意！并不是所有的 setter 和 getter 方法。

**下面直接引用结论，Fastjson会对满足下列要求的setter/getter方法进行调用：**

满足条件的setter：

- 非静态函数
- 返回类型为void或当前类
- 参数个数为1个

满足条件的getter：

- 非静态方法
- 无参数
- **返回值类型继承自Collection或Map或AtomicBoolean或AtomicInteger或AtomicLong**

# FastJson反序列化漏洞原理

无论是哪个版本，Fastjson反序列化漏洞的原理都是一样的，只不过不同版本是针对不同的黑名单或者利用不同利用链来进行绕过利用而已。

通过Fastjson反序列化漏洞，攻击者可以传入一个恶意构造的JSON内容，程序对其进行反序列化后得到恶意类并执行了恶意类中的恶意函数，进而导致代码执行。

## 利用点
Fastjson使用`parseObject()`/`parse()`进行反序列化的时候可以指定类型。如果指定的类型太大，包含太多子类，就有利用空间了。例如，如果指定类型为Object或JSONObject，则可以反序列化出来任意类。例如代码写`Object o = JSON.parseObject(poc,Object.class)`就可以反序列化出Object类或其任意子类，而Object又是任意类的父类，所以就可以反序列化出所有类。

## 触发恶意代码执行

由前面知道，攻击者传入要进行反序列化的类中的  构造函数、`getter`方法、`setter`方法中存在危险代码，就能触发危险代码执行。

我们去 `DefaultJSONParser.parseObject()`中看
```java
// JSON.DEFAULT_TYPE_KEY即@type  
    if (key == JSON.DEFAULT_TYPE_KEY && !lexer.isEnabled(Feature.DisableSpecialKeyDetect)) {  
        ...  
        ObjectDeserializer deserializer = config.getDeserializer(clazz);  
        return deserializer.deserialze(this, clazz, fieldName);
```
![[Pasted image 20251223212659.png]]
JSON中以@type形式传入的类的时候，调用`deserializer.deserialize()`处理该类，并去调用这个类的`setter`和`getter`方法：


# 总结

当我们 `FastJson`中传入一个有危险代码的对象，并且这段危险代码在set或者get这种符合JavaBean的方法
就有可能恶意代码执行

如果代码在 `setXXX`方法或者 `getXXX`并且满足下面的条件，就能执行里面的恶意代码
>满足条件的setter：
- 非静态函数
- 返回类型为void或当前类
- 参数个数为1个

>满足条件的getter：
- 非静态方法
- 无参数
- **返回值类型继承自Collection或Map或AtomicBoolean或AtomicInteger或AtomicLong**

但是还记得我们刚测试 `JSON.parseObject(jsonString);` 的时候吗，我们的 `getXXX`方法并未满足上述条件，但是仍然调用了，这是因为我们反序列化的时候，不显示指定返回类型时 `JSON.parseObject()`默认返回值类型为`JSONObject`
FastJson 必须把刚刚按照`@type`创建好的 `Student` 对象**转换**成一个 `JSONObject`（本质上是一个 Map）
这种时候，也会触发get里的代码。

ps：再补充一点，**返回值类型继承自Collection或Map或AtomicBoolean或AtomicInteger或AtomicLong**的getter之所以会被调用，这是因为，普通的属性，像String这种，必须有set方法才能赋值，但是如果像 `Map/集合属性`即使没有写Set方法，也可以调用get方法获取 `Map`容器把数据填进去。

并且，如果有一个符合set get格式的方法里面有恶意执行点，即使没有这个变量，那么反序列化也会执行这段代码
例如 :
```java
public class Test{
	public  void setCmd(String cmd) throws Exception{
		Runtime.getRuntime().exec(cmd);	
	}
}
```
即使没有声明属性，也会执行方法








