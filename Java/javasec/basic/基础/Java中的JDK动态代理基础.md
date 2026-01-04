# 代理模式的意义

  代理模式可以在不修改被代理的对象的基础上，通过扩展代理类，进行功能的附加和加强，值得注意的是，代理类和被代理类应该共同实现一个接口，或者是共同继承某个类。

譬如我们租房子可以直接找房东或者中介

中介可以类比为代理

中介不仅可以租房子还可以维修，收中介费，所以中介就是房东的一个代理（扩展）。
![[Pasted image 20251130142517.png]]
# 静态代理

首先我们有一个接口

![[Pasted image 20251125003649.png]]
我们把接口进行实现
![[Pasted image 20251125003701.png]]
在实现的基础上写一个代理类，并对他进行一些扩展
![[Pasted image 20251125003718.png]]

调用的时候我们在使用代理的时候要把被代理的对象作为参数传进去
![[Pasted image 20251125003811.png]]

# 动态代理
每多一个房东就需要多一个中介，这显然不符合生活认知（对于租客来说，如果是用静态代理模式，每当想要换一个房东，那就必须要再换一个中介，在开发中，如果有多个中介代码量就更大了）

静态代理有一个缺点就是如果需要实现很多个方法，但是代理中所做的工作比较类似，比如都是输出日志。那我们需要每实现一个接口，写一个代理，会很冗杂。

 动态代理有两个要点
 1. 我们代理的是接口，而不是单个用户
 2. 代理类是动态生成的，而非静态定死的。

首先我们先写一个接口类
```java
package src.JdkProxy.DynamicProxy;  
  
  
public interface UserService {  
    public void add();  
 public void delete();  
 public void update();  
 public void query();  
}
```
接着，我们需要用实体类去实现这个抽象类

```java
package src.JdkProxy.DynamicProxy;  
  
public class UserServiceImpl implements UserService{  
    @Override  
 public void add() {  
        System.out.println("增加了一个用户");  
 }  
  
    @Override  
 public void delete() {  
        System.out.println("删除了一个用户");  
 }  
  
    @Override  
 public void update() {  
        System.out.println("更新了一个用户");  
 }  
  
    @Override  
 public void query() {  
        System.out.println("查询了一个用户");  
 }  
}
```

接着，是动态代理的实现类
```java
package src.JdkProxy.DynamicProxy;  
  
import java.lang.reflect.InvocationHandler;  
import java.lang.reflect.Method;  
import java.lang.reflect.Proxy;  
  
public class UserProxyInvocationHandler implements InvocationHandler {  
  
    // 被代理的接口  
 private UserService userService;  
  
 public void setUserService(UserService userService) {  
        this.userService = userService;  
 }  
  
    // 动态生成代理类实例  
 public Object getProxy(){  
        Object obj = Proxy.newProxyInstance(this.getClass().getClassLoader(), userService.getClass().getInterfaces(), this);  
 return obj;  
 }  
  
    // 处理代理类实例，并返回结果  
 @Override  
 public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {  
        log(method);  
 Object obj = method.invoke(userService, args);  
 return obj;  
 }  
  
    //业务自定义需求  
 public void log(Method method){  
        System.out.println("[Info] " + method.getName() + "方法被调用");  
 }  
}
```
最后编写我们的 Client，也就是启动器
```java
package src.JdkProxy.DynamicProxy;  
  
import src.JdkProxy.DynamicProxy.UserServiceImpl;  
  
public class Client {  
    public static void main(String[] args) {  
        // 真实角色  
 UserServiceImpl userServiceImpl = new UserServiceImpl();  
 // 代理角色，不存在  
 UserProxyInvocationHandler userProxyInvocationHandler = new UserProxyInvocationHandler();  
 userProxyInvocationHandler.setUserService((UserService) userServiceImpl); // 设置要代理的对象  
  
 // 动态生成代理类  
 UserService proxy = (UserService) userProxyInvocationHandler.getProxy();  
  
 proxy.add();  
 proxy.delete();  
 proxy.update();  
 proxy.query();  
 }  
}
```
![[Pasted image 20251130145007.png]]





```java
package proxy;  
  
import java.lang.reflect.InvocationHandler;  
import java.lang.reflect.Proxy;  
  
public class ProxyTest {  
    public static void main(String[] args) {  
        UserImpl user = new UserImpl();  
//        user.show();  
  
        //静态代理  
//        IUser userProxy = new UserProxy(user);  
//        userProxy.show();  
        //动态代理  
        //要代理的接口是？要执行的方法？我们怎么加载这个类？  
        InvocationHandler userinvocationhandler =new UserInvocationHandler(user);  
        IUser userProxy2 = (IUser) Proxy.newProxyInstance(user.getClass().getClassLoader(), user.getClass().getInterfaces(), userinvocationhandler);  
        userProxy2.show();  
    }  
}
```
![[Pasted image 20251125090126.png]]
![[Pasted image 20251125090057.png]]


# 反序列化中动态代理的作用？

我们先假设存在一个能够漏洞利用的类为 `B.f`，比如 `Runtime.exec` 这种。  
我们将入口类定义为 `A`，我们最理想的情况是 `A[O] -> O.f`，那么我们将传进去的参数 `O` 替换为 `B` 即可。但是在实战的情况下这种情况是极少的。


而 O 呢，如果是一个动态代理类，`O` 的 `invoke` 方法里存在 `.f` 的方法，便可以漏洞利用了，我们展示一下。
```java
A[O] -> O.abc
O[O2] invoke -> O2.f // 此时将 B 去替换 O2
最后  ---->
O[B] invoke -> B.f // 达到漏洞利用效果
```

 入口类 A 调用的是 O 的 `abc` 方法，而不是我们想要的 `f` 方法。
 
 表面上看，这条调用链没法直接利用。
但是，如果 **O 是一个动态代理对象**，情况就不一样了：
态代理的本质是：调用 O 的任何方法（比如 `abc`），都会被转发到它的 `InvocationHandler.invoke()` 方法。
在 `invoke()` 方法里，开发者可以决定调用哪个真实对象的方法。

如果我们让 O 的代理逻辑去调用 O2 的 `f` 方法，那么就能把调用链“转向”到我们想要的危险方法。

最终达成执行B.f的效果



