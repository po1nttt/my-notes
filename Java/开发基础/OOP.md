
# 构造器
```java
public class Person{

String name;

//实例化初始值
//1.使用new关键字，本质是在调用有构造器
//2.用来初始化值
public Persion(){             //即使不写这个persion方法，也会由构造器生成一个这个方法
	this.name="point";    
	                            
	}

//有参构造:一旦定义了有参构造，想用无参构造就必须用显示定义
public Persion(String name){             
	this.name = name;    
	                            
	}
	//alt+insert
	//快捷生成有参无参方法
}
```
解释：譬如上图在我调用这个方法的时候
假设我的类写成：

```java
public class Person{

String name;

//有参构造:一旦定义了有参构造，想用无参构造就必须用显示定义
public Persion(String name){             
	this.name = name;    
	                            
	}

}
```
那我想要调用
```java
Persion persion=new Persion();
```

就会报错，因为我在调用无参构造的时候没用显示定义，并且我还定义了有参构造。

所以我们写有参构造之前一定要使用无参定义进行定义


```
构造器：
1.和类名字相同
2.没有返回值
```

# 创建对象内存分析

![[Pasted image 20251104175533.png]]

![[Pasted image 20251104175511.png]]


# 封装

属性私有
所以我你们要提供一些方法来get set这个数据

![[d4f13aea-281f-4c56-a74a-50c83b941b48.png]]
alt+insert可以快捷生成get set方法


我们在封装过程中，在get set种可以设置一些可以检查合法数据的代码
![[Pasted image 20251104180643.png]]

# 继承
![[Pasted image 20251104180854.png]]


子类可以继承父类的全部public方法
cltr+H可以看继承树

我们可以看到所有类都默认继承object类

java只能单继承，一个儿子只能有一个爸爸，一个爸爸可以有多个儿子



## super

注意点：
1.super调用父类的构造方法，必须在构造方法的第一个
2.super必须只能出现在子类的方法或者构造方法中！
3.super和this不能同时调用构造方法！
![[Pasted image 20251104191604.png]]

---


![[Pasted image 20251104181817.png]]

![[038f8812-388f-48af-b29c-8ca292362a1c.png]]
super可以调用父类的protected方法和属性

![[Pasted image 20251104182112.png]]


构造器会在子类的方法中默认调用父类的方法
![[Pasted image 20251104182154.png]]
如果要显式调用父类的构造器，那么必须在子类构造器的第一行


## 方法重写

前提：
需要有继承关系，子类重写父类的方法！
1.方法名字必须相同
2.参数列表列表必须相同
3.修饰符：范围可扩大：public>protected>default>private
4.抛出的异常：范围，可以被缩小，但不能扩大 ClassNotFoundException -->Exception(大)

重写，子类的方法和父类必须要一致：方法体不同！

为什么要重写：
1.父类的功能子类不需要
2.Alt+Insert ：overide；

# 多态

![[Pasted image 20251104192844.png]]
![[Pasted image 20251104193857.png]]


---



![[Pasted image 20251104193507.png]]


![[Pasted image 20251104193549.png]]
可以通过强制类型转换调用子类的方法

总结来说，正常来说子类没重写父类就调用父类，子类重写父类就调用子类，子类独有的方法不能从父类直接调用，可以使用强制类型转换来调用



## instanceof 和类型转换


![[Pasted image 20251104194902.png]] 




类型转换

父类转子类：
可以使用子类方法
```java
//高   ->低
person s =new student();

//将这个对象转换为student类型，我们就可以使用student的方法了！

Student student1=(student) s;
或者

（（student）s）.方法名（）；




```
子类转父类：
会丢失子类方法


![[Pasted image 20251104195916.png]]


# 抽象类

abstract

我们可以创建一个
public abstract class A
其中
我们可以写一个方法只有名字，没有具体怎么实现
public abstract void dosomething();
这就是抽象方法

我们需要一个新类继承抽象类，继承它的子类，并且必须实现他的方法

特点：
1.不能new出来抽象类，只能靠子类去实现。
2.抽象类中可以写普通的方法
3.抽象方法必须在抽象类中

# 接口（interface）

![[Pasted image 20251104203527.png]]

实现接口：
public class 类名 implements 接口名{

}
接口默认是public abstract的
接口中的常量默认是public satic final的（但一般不在接口定义常量）

并且实现接口的类，必须要重写接口的方法

并且类是单继承的，接口可以多继承，一个类可以继承多个接口
![[Pasted image 20251104204329.png]]
































