# 序列化实现

java的序列化实现，是通过实现java的序列化接口，来实现的

如下就是java的序列化接口
```java
public interface Serializable {
}
```
实则里面并没有需要我们实现的具体方法

```java
public class Student implements Serializable {
  private String name;
  private int age;
  /**
  * Color 类也是需要实现序列化接口的。
  */
  private Color color;//这里如果没有实现序列化接口，那么在 Student 对象序列化时将会报错
}
```

# Serializable 接口的基本使用

java的 IO类是“套娃”似的
最里层是字节流可以写文件、写内存... 在他的外层是加功能的装饰器（加密、加缓冲、加对象序列化）
```
写文件：FileOutputStream        ← 只懂写字节  
        ↑  
     包一层：ObjectOutputStream  ← 额外学会“把对象变成字节”
```

所以外层的 ObjectOutputStream 仅仅是一个装饰器
因此可以通过 ObjectOutStream 包装 FileOutStream 将数据写入到文件中或者包装 ByteArrayOutStream 将数据写入到内存中。
```java
// 1. 写文件
try (ObjectOutputStream oos =
        new ObjectOutputStream(new FileOutputStream("save.bin"))) {
    oos.writeObject(new Person("张三", 18));
}

// 2. 写内存（得到 byte[] 就可以网络传输或暂存）
ByteArrayOutputStream buf = new ByteArrayOutputStream();
try (ObjectOutputStream oos = new ObjectOutputStream(buf)) {
    oos.writeObject(new Person("李四", 20));
}
byte[] data = buf.toByteArray();   // 这一坨字节随便你打包、发送、存库
```
同理，可以通过 ObjectInputStream 将数据从磁盘 FileInputStream 或者内存 ByteArrayInputStream 读取出来然后转化为指定的对象即可。
```java
// 从文件读
try (ObjectInputStream ois =
        new ObjectInputStream(new FileInputStream("save.bin"))) {
    Person p = (Person) ois.readObject();
}

// 从内存读
ByteArrayInputStream bis = new ByteArrayInputStream(data);
try (ObjectInputStream ois = new ObjectInputStream(bis)) {
    Person p = (Person) ois.readObject();
}
```
`ObjectOutputStream`代表对象输出流：

它的`writeObject(Object obj)`方法可对参数指定的obj对象进行序列化，把得到的字节序列写到一个目标输出流中。

`ObjectInputStream`代表对象输入流：

它的`readObject()`方法从一个源输入流中读取字节序列，再把它们反序列化为一个对象，并将其返回



# Serializable 接口的特点
1.  序列化类的属性没有实现 Serializable 那么在序列化就会报错

```java
public class Student implements Serializable {
  private String name;
  private int age;
  /**
  * Color 类也是需要实现序列化接口的。
  */
  private Color color;//这里如果没有实现序列化接口，那么在 Student 对象序列化时将会报错
}
```

2. 在反序列化过程中，它的父类如果没有实现序列化接口，那么将需要提供无参构造函数来重新创建对象。

Animal 是父类，它没有实现 Serilizable 接口
```java
public class Animal {
    private String color;
 
    public Animal() {//没有无参构造将会报错
        System.out.println("调用 Animal 无参构造");
    }
 
    public Animal(String color) {
        this.color = color;
 
            System.out.println("调用 Animal 有 color 参数的构造");
    }
 
    @Override
    public String toString() {
        return "Animal{" +
                "color='" + color + '\'' +
                '}';
    }
}
```
BlackCat 是 Animal 的子类
```java
public class BlackCat extends Animal implements Serializable {
    private static final long serialVersionUID = 1L;
    private String name;
 
    public BlackCat() {
        super();
        System.out.println("调用黑猫的无参构造");
    }
 
    public BlackCat(String color, String name) {
        super(color);
        this.name = name;
        System.out.println("调用黑猫有 color 参数的构造");
    }
 
    @Override
    public String toString() {
        return "BlackCat{" +
                "name='" + name + '\'' +super.toString() +'\'' +
                '}';
    }
}
```

测试类
```java
public class SuperMain {
    private static final String FILE_PATH = "./super.bin";
 
    public static void main(String[] args) throws Exception {
        serializeAnimal();
        deserializeAnimal();
    }
 
    private static void serializeAnimal() throws Exception {
        BlackCat black = new BlackCat("black", "我是黑猫");
        System.out.println("序列化前："+black.toString());
        System.out.println("=================开始序列化================");
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(FILE_PATH));
        oos.writeObject(black);
        oos.flush();
        oos.close();
    }
 
    private static void deserializeAnimal() throws Exception {
        System.out.println("=================开始反序列化================");
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(FILE_PATH));
        BlackCat black = (BlackCat) ois.readObject();
        ois.close();
        System.out.println(black);
    }
}
```
输出
```java
调用 Animal 有 color 参数的构造
调用黑猫有 color 参数的构造
序列化前：BlackCat{name='我是黑猫'Animal{color='black'}'}
=================开始序列化================
=================开始反序列化================
调用 Animal 无参构造
BlackCat{name='我是黑猫'Animal{color='null'}'}
```

如果要序列化的对象的父类 Animal 没有实现序列化接口，那么在反序列化时是会调用对应的无参构造方法的，这样做的目的是重新初始化父类的属性，例如 Animal 因为没有实现序列化接口，因此对应的 color 属性就不会被序列化，因此反序列得到的 color 值就为 null。

3. 如果在属性前加上了`transient`这个形容词 那么就不会被序列化
所以，假如说我们有一个长度为10000000的数组，但是我们只有30个数字，我们就可以通过重写`writeObject`方法来自定义我们的序列化方法
```java
public class MyList implements Serializable {
 
    private String name;
 
 
    /*
    transient 表示该成员 arr 不需要被序列化
     */
    private transient Object[] arr;
 
    public MyList() {
    }
 
    public MyList(String name) {
        this.name = name;
        this.arr = new Object[100];
        /*
        给前面30个元素进行初始化
         */
        for (int i = 0; i < 30; i++) {
            this.arr[i] = i;
        }
    }
 
    @Override
    public String toString() {
        return "MyList{" +
                "name='" + name + '\'' +
                ", arr=" + Arrays.toString(arr) +
                '}';
    }
 
 
    //-------------------------- 自定义序列化反序列化 arr 元素 ------------------
 
    /**
     * Save the state of the <tt>ArrayList</tt> instance to a stream (that
     * is, serialize it).
     *
     * @serialData The length of the array backing the <tt>ArrayList</tt>
     * instance is emitted (int), followed by all of its elements
     * (each an <tt>Object</tt>) in the proper order.
     */
    private void writeObject(java.io.ObjectOutputStream s)
            throws java.io.IOException {
        //执行 JVM 默认的序列化操作
        s.defaultWriteObject();//先调用原生的序列化操作
 
 
        //手动序列化 arr  前面30个元素
        for (int i = 0; i < 30; i++) {
            s.writeObject(arr[i]);
        }
    }
 
    /**
     * Reconstitute the <tt>ArrayList</tt> instance from a stream (that is,
     * deserialize it).
     */
    private void readObject(java.io.ObjectInputStream s)
            throws java.io.IOException, ClassNotFoundException {
 
        s.defaultReadObject();
        arr = new Object[30];
 
        // Read in all elements in the proper order.
        for (int i = 0; i < 30; i++) {
            arr[i] = s.readObject();
        }
    }
}
 
```
4. 静态成员变量是不能被序列化
序列化是针对对象属性的，而静态成员变量是属于类的。
5. 一个实现 Serializable 接口的子类也是可以被序列化的。

---

# 原生反序列化流程
当调用 `ObjectInputStream.readObject()` 时，JVM 会执行一个高度复杂的流程来重建对象。

### 1. 核心流程 (`ObjectInputStream.readObject()`)

#### 阶段 I: 读取流元数据

1. **读取头信息：** 读取流中开头的魔术数（Magic Number, $0xACED$）和版本信息，确认数据是一个合法的 Java 序列化流。
    
2. **定位类定义：** 从流中读取被序列化对象的**类描述符** (`ObjectStreamClass`)。这个描述符包含了类的完整名称、`serialVersionUID` 等信息。
    

#### 阶段 II: 加载类和验证

1. **类加载 (`resolveClass`)：** `ObjectInputStream` 会调用一个内部方法（默认实现是 `ObjectInputStream.resolveClass(ObjectStreamClass desc)`）来查找并加载本地 JVM 中与流中描述符对应的类。
    
    - **职责：** 这个方法负责将流中读取的类名（字符串）转换成 JVM 内部的 `Class` 对象。这是**恶意反序列化漏洞**的关键步骤之一，因为它决定了哪个类会被加载。
        
2. **安全检查：** 检查类描述符中的 `serialVersionUID` 是否与本地类的 `serialVersionUID` 匹配。如果不匹配，会抛出 `InvalidClassException`。
    

#### 阶段 III: 对象实例化（没有调用构造器）

1. **创建实例：** JVM 会使用一种特殊的机制（通常通过 JNI 或内部的 Unsafe API）来创建对象实例。
    
    - **关键点：** 这个过程是**跳过**被反序列化类的**构造函数**的。这是因为反序列化不是创建新对象，而是恢复旧对象的状态。如果调用构造函数，可能会破坏恢复的状态或引入副作用。
        

#### 阶段 IV: 状态恢复和方法回调

1. **字段赋值：** 遍历对象的所有字段，从序列化流中读取数据，并根据字段名和类型，将值赋给新创建的实例。
    
2. **`readObject` 回调 (如果存在)：** 如果被反序列化的类定义了私有的 `private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException` 方法，JVM 会在标准字段赋值完成后**自动调用**这个方法。
    
    - **职责：** 这个方法允许类作者自定义反序列化的逻辑（例如，处理加密数据、验证数据、处理兼容性问题）。这也是 **Shiro-550** 等大多数反序列化漏洞（Gadget Chains）利用的最终触发点，因为代码执行在这里获得了控制权。
        
3. **`readObjectNoData` 回调 (如果存在)：** 如果流版本比本地类版本旧，或者流中没有该类的字段数据，JVM 会调用 `readObjectNoData()`（如果定义了）。
# 安全问题
`readObject`会直接调用危险方法
```java
package test.serilize;  
  
import java.io.IOException;  
import java.io.ObjectInputStream;  
import java.io.Serializable;  
  
public class Person implements Serializable {  
    private transient String name;  
    private int age;  
  
    public Person() {  
    }  
  
    public Person(String name, int age) {  
        this.name = name;  
        this.age = age;  
    }  
  
    @Override  
    public String toString() {  
        return "Person{" +  
                "name='" + name + '\'' +  
                ", age=" + age +  
                '}';  
    }  
    private void readObject(ObjectInputStream ois) throws IOException,ClassNotFoundException{  
        ois.defaultReadObject();  
        Runtime.getRuntime().exec("calc");  //直接调用命令（危险方法 ）
    }  
  
}
```
序列化
```java
package test.serilize;  
  
import javax.imageio.spi.IIORegistry;  
import java.io.FileOutputStream;  
import java.io.IOException;  
import java.io.ObjectOutput;  
import java.io.ObjectOutputStream;  
  
public class serilize {  
    public static void serialize(Object obj) throws IOException{  
        ObjectOutputStream oos =new ObjectOutputStream(new FileOutputStream("ser.bin"));  
        oos.writeObject(obj);  
    }  
  
    public static void main(String[] args) throws Exception{  
        Person person=new Person("AA",22);  
        serialize(person);  
    }  
}
```
反序列化
```java
package test.serilize;  
  
import java.io.FileInputStream;  
import java.io.IOException;  
import java.io.ObjectInputStream;  
  
public class unserilize {  
    public static Object unserialize(String Filename) throws IOException,ClassNotFoundException{  
        ObjectInputStream ois=new ObjectInputStream(new FileInputStream(Filename));  
        Object obj = ois.readObject();  
        return obj;  
  
    }  
  
    public static void main(String[] args)throws Exception {  
        Person person=(Person) unserialize("ser.bin");  
        System.out.println(person);  
    }  
}
```
调用了计算器，说明反序列化的时候执行了我们对象中的方法

---

入口类参数中包含可控类，该类由危险方法，readObject时调用
入口类参数中包含可控类，该类又调用其他有危险方法的类，readObject时调用
加载类的时候也会执行一些方法，可能会有危险

入口类source需要几个条件
1. 重写readObject 
2. 参数类型广泛
3. 最好jdk自带
那么HashMap就是一个完美的入口类![[Pasted image 20251123015607.png]]
计算key的哈希值
![[Pasted image 20251123015734.png]]

如果key是空就返回0，如果不是空的就调用hashCode
![[Pasted image 20251123020107.png]]
所以，当我们找利用链的时候，重写了这几个方法譬如
hashcode，equals，tostring等
并且方法里有潜在危险函数
还可以反序列化，那就有可能可以利用

---
所以先找入口，找到的这个入口最好包着一个类，最好是Object类（因为在最顶层）
并且重写了readObject 调用了常见的函数

加上调用链 gadget chain 相同名称，相同类型
   执行类sink 可以rce ssrf写文件等....
   
所以，java中和http有关的类`URL`
![[Pasted image 20251123135403.png]]可以序列化，很有希望

发起请求时通过openConnection方法
![[Pasted image 20251123135617.png]]
跟进一下
![[Pasted image 20251123140718.png]]
可以看到返回值类型是一个URLConnection对象![[Pasted image 20251123141603.png]]
 跟进之后发现这个对象不仅没法序列化，并且方法名很长不常见。

---
所以我们想找一个常用的方法
![[Pasted image 20251123142354.png]]
跟进
![[Pasted image 20251123142511.png]]
这个`getHostAddress`应该就类似DNS请求，根据域名获取地址呗
如果我们调用URL类的hashCode函数，就会执行dns请求，就有可能SSRF

---
所以最终的链条就是
HashMap中调用->hash方法, 其中有hashCode()方法->(由于同名)正好可以走到URL类中的hashCode方法->从而执行一个DNS解析
![[Pasted image 20251123145237.png]]

我们使用DNSlog生成一个域名，发现可以被解析过来
但事实上，其实在这个put中我们会发现
![[Pasted image 20251123151220.png]]![[Pasted image 20251123151221.png]]
其实调用put的时候已经进行了hashCode的调用，并且在URL类的hashCode初始化的时候为-1，但我们给他赋值之后，他正常来说不是-1，如果不是-1![[Pasted image 20251123151508.png]]
就不会走到下面的handler.hashCode方法了
所以我们想办法
![[Pasted image 20251123152852.png]]

这里我们使用反射来进行修改其内部私有属性
![[Pasted image 20251124235443.png]]
但是这里注意Java9之后的模块系统限制了反射访问JDK内部类的私有成员，这种只能JDK8来进行实现。

# 总结
反序列化的应用有种移花接木的美

我们找到一个B类中的危险方法

但是本身调用的安全的A类，我们可以移花接木通过各种方式来调用B中的危险方法包括单不限于使用同名函数，调用invoke等....