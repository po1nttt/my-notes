# SpEL表达式扫盲

## 简介
在 Spring3 中引入了 Spring 表达式语言（Spring Expression Language，简称 SpEL），这是一种功能强大的表达式语言，支持在运行时查询和操作对象图，可以与基于 XML 和基于注解的 Spring 配置还有 bean 定义一起使用。

在 Spring 系列产品中，SpEL 是表达式计算的基础，实现了与 Spring 生态系统所有产品无缝对接。Spring 框架的核心功能之一就是通过依赖注入的方式来管理 Bean 之间的依赖关系，而 SpEL 可以方便快捷的对 `ApplicationContext` 中的 Bean 进行属性的装配和提取。由于它能够在运行时动态分配值，因此可以为我们节省大量 Java 代码。

SpEL 有许多特性：

- 使用 Bean 的 ID 来引用 Bean
- 可调用方法和访问对象的属性
- 可对值进行算数、关系和逻辑运算
- 可使用正则表达式进行匹配
- 可进行集合操作
例如：
### 引用与属性访问
你可以直接操作 Spring 容器中的其他 Bean：
- `#{userBean}`：引用 ID 为 `userBean` 的对象。
- `#{userBean.name}`：访问该对象的 `name` 属性（本质是调用 `getName()`）。
- `#{userBean.calculateAge()}`：直接调用该对象的方法。
### 类型安全的操作符
SpEL 支持非常强大的运算符，甚至包括**安全导航运算符**，防止空指针异常：
- **算术运算**：`#{2 * (3 + 4)}`
- **逻辑运算**：`#{user.age > 18 and user.role == 'ADMIN'}`
- **安全导航**：`#{user?.contact?.email}`（如果 user 为空，直接返回 null，不会报 NPE）。
### 集合处理
这是 SpEL 区别于普通表达式语言的地方，它支持**投影（Projection）和选择（Selection）**：
- **选择（过滤）**：`#{userList.?[age > 20]}`（过滤出所有年龄大于 20 的用户）。
- **投影（提取列）**：`#{userList.![name]}`（提取所有用户的姓名，返回一个字符串列表）。


### `#{}`属性占位符

`#{}`和 `${}` 的区别如下：

|**特性**|**属性占位符 ${}**|**SpEL 表达式 #{}**|
|---|---|---|
|**主要功能**|读取配置文件（.properties/yml）中的值|在运行时动态计算、操作对象图|
|**能力范围**|仅限静态值的替换|支持方法调用、逻辑运算、集合操作|
|**执行时机**|容器启动时加载配置|运行时动态求值|
|**嵌套关系**|不能嵌套 SpEL|**可以**嵌套占位符，如 `#{'${path}' + '/test'}`|

## SpEL表达式类型

### 字面值
最简单的 SpEL 表达式就是仅包含一个字面值。

下面我们在 XML 配置文件中使用 SpEL 设置类属性的值为字面值，此时需要用到 `#{}` 定界符，注意若是指定为字符串的话需要添加单引号括起来：

```xml
<property name="message1" value="#{666}"/>
<property name="message2" value="#{'John'}"/>
```
还可以直接与字符串混用：
```xml
<property name="message" value="the value is #{666}"/>
```
Java 基本数据类型都可以出现在 SpEL 表达式中，表达式中的数字也可以使用科学计数法：
```xml
<property name="salary" value="#{1e4}"/>
```
###  Demo

**HelloWorld.java**
```java
package com.example;
 
public class HelloWorld {
    private String message;
 
    public void setMessage(String message){
        this.message  = message;
    }
 
    public void getMessage(){
        System.out.println("Your Message : " + message);
    }
}
```

**Demo.xml**

```java
<?xml version="1.0" encoding="UTF-8"?>  
<beans xmlns="http://www.springframework.org/schema/beans"  
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  
 xsi:schemaLocation="http://www.springframework.org/schema/beans  
 http://www.springframework.org/schema/beans/spring-beans-3.0.xsd ">  
  
    <bean id="helloWorld" class="com.drunkbaby.pojo.HelloWorld">  
        <property name="message" value="Your name is #{systemProperties['user.name']}" />  
    </bean>  
  
</beans>
```
简单解释一下， 首先给这个bean 起了一个代号叫“helloWorld”，其中实例化的类是 `com.drunkbaby.pojo.HelloWorld`，下面实例化中 `name="message"`会寻找 `setMessage()`其中传入与参数 `"Your name is #{systemProperties['user.name']}"`
通过这里我们可以看到这个东西的动态感。这里会动态解析你的主机名，所以也很危险。
**MainTestDemo.java**
```java
public class MainTestDemo {  
    public static void main(String[] args) {  
        ApplicationContext context = new ClassPathXmlApplicationContext("Demo.xml");  
        HelloWorld helloWorld = context.getBean("helloWorld", HelloWorld.class);  
        helloWorld.getMessage();  
    }  
}
```
spEL主要由以下三个元素来组成：
**ExpressionParser（解析器）**：负责将字符串（如 `#{beanId.property}`）解析成一个 **Expression 对象**。

**EvaluationContext（上下文）**：这是 SpEL 的“运行环境”。它告诉解析器去哪里找 Bean、变量或方法。

**Expression（表达式对象）**：最后由它根据上下文计算出最终的结果。

### 引用 Bean、属性和方法

#### 引用 Bean

SpEL 表达式能够通过其他 Bean 的 ID 进行引用，直接在 `#{}` 符号中写入 ID 名即可，无需添加单引号括起来。如：

原来的写法是这样的

```xml
<constructor-arg ref="test"/>
```
在 SpEL 表达式中
```xml
<constructor-arg value="#{test}"/>
```
#### 引用类属性

SpEL 表达式能够访问类的属性。

比如，Po1nt 参赛者是一位模仿高手， Khalil Fong唱什么歌，弹奏什么乐器，Po1nt就唱什么歌，弹奏什么乐器：

```xml
<bean id="Fong" class="com.spring.entity.Instrumentalist"
    p:song="Love Song"
    p:instrument-ref="piano"/>
<bean id="Po1nt" class="com.spring.entity.Instrumentalist">
    <property name="Fong" value="#{Fong.instrument}"/>
    <property name="song" value="#{Fong.song}"/>
</bean>
```

key 指定 `Fong<bean>` 的 id  
value 指定 `Fong<bean>`的 song 属性。其等价于执行下面的代码：
```java
Instrumentalist carl = new Instrumentalist();
carl.setSong(Fong.getSong());
```
#### 引用类方法

SpEL 表达式还可以访问类的方法。

SpEL 表达式还可以访问类的方法。

假设现在有个 `SongSelector` 类，该类有个 `selectSong()` 方法，这样的话 Po1nt 就可以不用模仿别人，开始唱 `songSelector` 所选的歌了：
```xml
<property name="song" value="#{SongSelector.selectSong()}"/>
```

 有个癖好，歌曲名不是大写的他就浑身难受，我们现在要做的就是仅仅对返回的歌曲调用 `toUpperCase()` 方法：
```xml
 <property name="song" value="#{SongSelector.selectSong().toUpperCase()}"/>
```
注意：这里我们不能确保不抛出 `NullPointerException`，为了避免这个讨厌的问题，我们可以使用 SpEL 的 `null-safe` 存取器：
```xml
<property name="song" value="#{SongSelector.selectSong()?.toUpperCase()}"/>
```

`?.` 符号会确保左边的表达式不会为 `null`，如果为 `null` 的话就不会调用 `toUpperCase()` 方法了。
#### Demo —— 引用 Bean
这里我们修改基于构造函数的依赖注入的示例。
**SpellChecker.java**
```java
public class SpellChecker {  
    public SpellChecker(){  
        System.out.println("Inside SpellChecker constructor." );  
    }  
    public void checkSpelling() {  
        System.out.println("Inside checkSpelling." );  
    }  
}
```
**TextEditor.java**
```java
public class TextEditor {  
    private SpellChecker spellChecker;  
    public TextEditor(SpellChecker spellChecker) {  
        System.out.println("Inside TextEditor constructor." );  
        this.spellChecker = spellChecker;  
    }  
    public void spellCheck() {  
        spellChecker.checkSpelling();  
    }  
}
```
**editor.xml**
```xml
<?xml version="1.0" encoding="UTF-8"?>  
<beans xmlns="http://www.springframework.org/schema/beans"  
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  
 xsi:schemaLocation="http://www.springframework.org/schema/beans  
 http://www.springframework.org/schema/beans/spring-beans-3.0.xsd ">  
  
    <!-- Definition for spellChecker bean -->  
 <bean id="spellChecker" class="com.drunkbaby.pojo.SpellChecker" />  
  
    <!-- Definition for textEditor bean -->  
 <bean id="textEditor" class="com.drunkbaby.pojo.TextEditor">  
        <!--<constructor-arg ref="spellChecker"/>-->  
 <constructor-arg value="#{spellChecker}"/>  
    </bean>  
  
</beans>
```

启动类 **RefSpellAndEditor.java**
```java
public class RefSpellAndEditor {  
    public static void main(String[] args) {  
        ApplicationContext context = new ClassPathXmlApplicationContext("editor.xml");  
  
        TextEditor te = (TextEditor) context.getBean("textEditor");  
        te.spellCheck();  
    }  
}
```


## 类类型表达式 T(Type)

`T()` 是 SpEL 中的一个运算符，用于**获取指定类的 `java.lang.Class` 实例**。

你可以把它理解为 Java 代码中的 `ClassName.class` 或者 `Class.forName("ClassName")`。它的存在是为了让表达式能够访问类的**静态方法（Static Methods）**和**静态字段（Static Fields）**，而不仅仅是操作已经存在的对象实例。

在 SpEL 表达式中，使用 `T(Type)` 运算符会调用类的作用域和方法。换句话说，就是可以通过该类类型表达式来操作类。

其中 `Type` 有两种使用方法

**定位类**： `T()` 括号内必须是类的**全限定名**，例如 `T(java.util.Date)`。
**默认包免写**： 正如你所提到的，为了开发方便，SpEL 预定义了 `java.lang` 包。因此，`T(String)` 等同于 `T(java.lang.String)`。

这里就有潜在的攻击面了  
因为我们 `java.lang.Runtime` 这个包也是包含于 `java.lang` 的包的，所以如果能调用 `Runtime`  
就可以进行命令执行

在 XML 配置文件中的使用示例，要调用 `java.lang.Math` 来获取 0~1 的随机数

```xml
<property name="random" value="#{T(java.lang.Math).random()}"/>
```
Expression 中使用示例：
```java
ExpressionParser parser = new SpelExpressionParser();//new一个SpEL表达式
// java.lang 包类访问
Class<String> result1 = parser.parseExpression("T(String)").getValue(Class.class);
System.out.println(result1);
//其他包类访问
String expression2 = "T(java.lang.Runtime).getRuntime().exec('open /Applications/Calculator.app')";
Class<Object> result2 = parser.parseExpression(expression2).getValue(Process.class);
System.out.println(result2);
//类静态字段访问
int result3 = parser.parseExpression("T(Integer).MAX_VALUE").getValue(int.class);
System.out.println(result3);
//类静态方法调用
int result4 = parser.parseExpression("T(Integer).parseInt('1')").getValue(int.class);
System.out.println(result4);
```
当`parser.parseExpression(expression)` 时，Spring 把字符串解析成了一棵 **表达式树（Expression Object）**
执行 `getValue()`会真正执行里面的内容，并且 `getValue()`中的参数是类型转换检查，会自动把结果转换成指定的类型，如果计算出的类型和预期结果不匹配就会抛出异常，如果不带参数，会返回一个Object。

### 命令执行
 弹计算器
```xml
<bean id="helloWorld" class="com.drunkbaby.pojo.HelloWorld">  
    <property name="message" value="#{'Po1nt'} is #{T(java.lang.Runtime).getRuntime.exec('calc')}" />  
</bean>
```

![[Pasted image 20251231162433.png]]

## SpEL用法
其用法有三种形式
 1 . 一种是在注解 `@Value`中
 2 .一种是XML配置中
 3 .一种是在代码块中使用 `Expression`

刚已经写了XML配置中使用SpEL表达式， `@Value`的用法例子如下

```java
public class EmailSender {
    @Value("${spring.mail.username}")
    private String mailUsername;
    @Value("#{ systemProperties['user.region'] }")    
    private String defaultLocale;
    //...
}
```
---
### Expression用法
`SpEL`在求表达式值得时候一般分为四步，其中第三步可选：
1. 构造解析器：SpEL 使用 `ExpressionParser` 接口表示解析器，提供 `SpelExpressionParser` 默认实现；
2. 解析器解析字符串表达式：使用 `ExpressionParser` 的 `parseExpression` 来解析相应的表达式为 `Expression` 对象；
3. 在此构造上下文：准备比如变量定义等等表达式需要的上下文数据；
4. 最后根据上下文得到表达式运算后的值：通过 `Expression` 接口的 `getValue` 方法根据上下文获得表达式值；
```java
ExpressionParser parser = new SpelExpressionParser();
Expression expression = parser.parseExpression("('Hello' + ' Po1nt').concat(#end)");
EvaluationContext context = new StandardEvaluationContext();
context.setVariable("end", "!");
System.out.println(expression.getValue(context));
```
`context.setVariable("end", "!");`这里在上下文自定义了一个变量
名字为end 值为 `！`

`Expression expression = parser.parseExpression("('Hello' + ' Drunkbaby').concat(#end)");`将一个字符串转换成一个可执行的 `Experssion`对象，其中引用上下文中的变量时 需要使用 `#变量名`格式 

最终输出 `Hello Po1nt!`

#### 主要接口
- **ExpressionParser 接口**：表示解析器，默认实现是 `org.springframework.expression.spel.standard` 包中的 `SpelExpressionParser` 类，使用 `parseExpression` 方法将字符串表达式转换为 Expression 对象，对于 ParserContext 接口用于定义字符串表达式是不是模板，及模板开始与结束字符；
- **EvaluationContext 接口**：表示上下文环境，默认实现是 `org.springframework.expression.spel.support` 包中的 `StandardEvaluationContext` 类，使用 `setRootObject` 方法来设置根对象，使用 `setVariable` 方法来注册自定义变量，使用 `registerFunction` 来注册自定义函数等等。
- **Expression 接口**：表示表达式对象，默认实现是 `org.springframework.expression.spel.standard` 包中的 `SpelExpression`，提供 `getValue` 方法用于获取表达式值，提供 `setValue` 方法用于设置对象值。
Demo如下：
![[Pasted image 20251231180055.png]]
相当于不使用 `#{}`就可以通过使用 `parseExpression()`来将字符串转化成SpEL表达式来解析

#### 类实例化
其中类实例化的时候可以把new关键字写入字符串进行解析，其中类名，除了 `java.lang`包内的类，其他必须是全限定名。
```java
public class newClass {  
    public static void main(String[] args) {  
        String spel = "new java.util.Date()";  
        ExpressionParser parser = new SpelExpressionParser();  
        Expression expression = parser.parseExpression(spel);  
        System.out.println(expression.getValue());  
    }  
}
```

## 表达式运算

SpEL 提供了以下几种运算符

|运算符类型|运算符|
|---|---|
|算数运算|+, -, *, /, %, ^|
|关系运算|<, >, ==, <=, >=, lt, gt, eq, le, ge|
|逻辑运算|and, or, not, !|
|条件运算|?:(ternary), ?:(Elvis)|
|正则表达式|matches|

### 算数运算
加法运算：
```xml
<property name="add" value="#{counter.total+42}"/>
```
这里获取 `counter`对象的 `total`属性，让其加上42 并把值赋给当前bean对象的 `add` 属性

当然  `+`还可以用于字符串的拼接。
例如：
```xml
<property name="blogName" value="#{ 'my blog name is' + ' ' + mrBird }"/>
```
`blogName`属性的值是 字符串 `my blog name is`拼接一个空格 再拼接一个mrBird变量

`^`这个运算符在java原生中是按位异或
但在SpEL表达式中是 幂运算
其余算数运算和原生的java都是一样的

### 关系运算

判断一个 Bean 的某个属性是否等于 100：
```xml
<property name="eq" value="#{counter.total==100}"/>
```
返回值是一个 `boolean`类型，关系运算符唯一需要注意的是：
在Spring XML配置文件中直接写 `>=` 和`<=`会报错，因为XML是标签语言，使用 `>`和 `<`容易出问题。
所以可以使用文本类型代替符号

|运算符|符号|文本类型|
|---|---|---|
|等于|==|eq|
|小于|<|lt|
|小于等于|<=|le|
|大于|>|gt|
|大于等于|>=|ge|

例如：
```xml
<property name="eq" value="#{counter.total le 100}"/>
```

### 逻辑运算
SpEL表达式提供了多种逻辑运算符
例如 `and`运算符

```xml
<property name="largeCircle" value="#{shape.kind == 'circle' and shape.perimeter gt 10000}"/>
```
两边同时为 `true`的时候才返回 `true`
其余操作一样，只不过非运算 写成 `not`或者 `!`都是可以的
```xml
<property name="outOfStack" value="#{!product.available}"/>
```

条件运算符类似三目运算

```xml
<property name="instrument" value="#{songSelector.selectSong() == 'Love Song' ? piano:saxphone}"/>
```
当 `songSelector.selectSong()`执行后得到的字符串为 `Love Song`的时候，会把 `instrument`属性赋值为 id 是piano的Bean  否则赋值为 saxphone

### 正则表达式
例如 写一个正则匹配来验证邮箱
```xml
<property name="email" value="#{admin.email matches '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.com'}"/>
```
### 集合操作
SpEL表达式支持对集合进行操作

Demo如下
先写一个经典的javaBean
**City.java**

```java
package Demo;  
  
public class City {  
    private String name;  
    private String state;  
    private int population;  
  
    public void setName(String name) {  
        this.name = name;  
    }  
  
    public void setState(String state) {  
        this.state = state;  
    }  
  
    public void setPopulation(int population) {  
        this.population = population;  
    }  
  
    public String getName() {  
        return name;  
    }  
  
    public String getState() {  
        return state;  
    }  
  
    public int getPopulation() {  
        return population;  
    }  
}
```
修改 `city.xml`，使用 `<util:list>` 元素配置一个包含 City 对象的 List 集合：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:p="http://www.springframework.org/schema/p"
       xmlns:util="http://www.springframework.org/schema/util"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
    http://www.springframework.org/schema/beans/spring-beans-3.0.xsd
    http://www.springframework.org/schema/util
    http://www.springframework.org/schema/util/spring-util-4.0.xsd">
 
    <util:list id="cities">
        <bean class="com.example.City" p:name="Chicago"
              p:state="IL" p:population="2853114"/>
        <bean class="com.example.City" p:name="Atlanta"
              p:state="GA" p:population="537958"/>
        <bean class="com.example.City" p:name="Dallas"
              p:state="TX" p:population="1279910"/>
        <bean class="com.example.City" p:name="Houston"
              p:state="TX" p:population="2242193"/>
        <bean class="com.example.City" p:name="Odessa"
              p:state="TX" p:population="90943"/>
        <bean class="com.example.City" p:name="El Paso"
              p:state="TX" p:population="613190"/>
        <bean class="com.example.City" p:name="Jal"
              p:state="NM" p:population="1996"/>
        <bean class="com.example.City" p:name="Las Cruces"
              p:state="NM" p:population="91865"/>
    </util:list>
 
</beans>
```
其中 `util:list`标签，不仅仅定义了一个列表，他自己就是一个 Bean
然后通过id 来进行唯一标识
其中在这个列表里，先声是哪个类
后的 `p:name="Houston"`
p是命名空间，等同于 `<property name="name" value="Houston"/>` 

#### 访问集合成员
访问集合成成员是用 `[]`来实现的
`[]`有三种用法
**查字典**（Map/Properties）、**查下标**（List/数组）或者**摘字符**（String）。

1.查下标
SpEL 表达式支持通过 `#{集合ID[i]}` 的方式来访问集合中的成员。

写一个POJO
**ChoseCity.java** 
```java
public class ChoseCity {
    private City city;
    public void setCity(City city) {
        this.city = city;
    }
    public City getCity() {
        return city;
    }
}
```
我们在xml中加上
```xml
<bean id="choseCity" class="com.drunkbaby.service.ChoseCity">  
    <property name="city" value="#{cities[0]}"/>  
</bean>
```

然后运行这个xml 进行启动
**CityDemo.java**
```java
public class CityDemo {  
    public static void main(String[] args) {  
        ApplicationContext context = new ClassPathXmlApplicationContext("city.xml");  
        ChoseCity c = (ChoseCity)context.getBean("choseCity");  
        System.out.println(c.getCity().getName());  
    }  
}
```
![[Pasted image 20260101214727.png]]

这里其实还可以很灵活
假如我们想随机选一个city 中括号 `[]`运算符始终通过索引访问集合中的成员：
```xml
<property name="city" value="#{cities[T(java.lang.Math).random()*cities.size()]}"/>
```
`[]`运算符同样可以用来获取 `java.util.Map` 集合中的成员。例如，假设 City 对象以其名字作为键放入 Map 集合中，在这种情况下，我们可以像下面那样获取键为 Dalian 的 entry：

**注意前提：是 City 对象以其名字作为键放入 Map 集合中**

```xml
<property name="chosenCity" value="#{cities['Dalian']}"/>
```



2.查字典
`[]` 运算符的另一种用法是从 `java.util.Properties` 集合中取值。例如，假设我们需要通过 `<util:properties>` 元素在 Spring 中加载一个 properties 配置文件：

```xml
<util:properties id="settings" loaction="classpath:settings.properties"/>
```
现在要在这个配置文件 Bean 中访问一个名为 `twitter.accessToken` 的属性：
```xml
<property name="accessToken" value="#{settings['twitter.accessToken']}"/>
```

`settings` 是一个配置集合（类似字典）。因为配置文件里的 Key 经常包含“点”（如 `twitter.accessToken`），如果直接用 `#{settings.twitter.accessToken}`，Spring 会误以为你要找 `settings` 对象里的 `twitter` 属性下的 `accessToken` 属性。

使用 `['key']` 可以明确告诉 Spring：请帮我把括号里这一整串字符串当成一个完整的名字，去 `settings` 里面搜。




3.摘字符
例如下面的表达式，可以获取第四个字符，也就将返回 s：
```java
'This is a test'[3]
```


#### 查询集合成员

SpEL 表达式中提供了查询运算符来实现查询符合条件的集合成员：

- `.?[]`：返回所有符合条件的集合成员；
- `.^[]`：从集合查询中查出第一个符合条件的集合成员；
- `.$[]`：从集合查询中查出最后一个符合条件的集合成员；

新建一个 `ListChoseCity`，代码如下

```java
public class ListChoseCity {  
    private List<City> city;  
  
    public List<City> getCity() {  
        return city;  
    }  
    public void setCity(List<City> city) {  
        this.city = city;  
    }  
}
```

修改 `city.xml`
```xml
<bean id="listChoseCity" class="Demo.ListChoseCity">  
    <property name="city" value="#{cities.?[population gt 100000]}" />  
</bean>
```

启动器 
```java
public class ListCityDemo {  
    public static void main(String[] args) {  
        ApplicationContext context = new ClassPathXmlApplicationContext("city.xml");  
        ListChoseCity listChoseCity = context.getBean("listChoseCity",ListChoseCity.class);  
        for (City city:listChoseCity.getCity()){  
            System.out.println(city.getName());  
        }  
    }  
}
```
输出了所有人口大于 10000 的城市

#### 集合投影
可以看作，你拿着一张白纸，在名片“城市名”的位置挖个洞，往下一照，所有名片的城市名就被“投影”到了这张白纸上，形成了一个**新的、只包含名字的清单**。

更直白点说，集合投影就是从集合的每一个成员中选择特定的属性放入到一个新的集合中。

其中 `.![]`就是所谓“挖洞的模具”

Demo1：
提取单个属性
```XMl
<property name="cityNames" value="#{cities.![name]}"/>
```
投影后会得到一个全新的List\<String\>
其中包含了cities列表中所有的name

Demo2：
当然可以加工之后再投影
```xml
<property name="cityNames" value="#{cities.![name + ',' + state]}"/>
```
他会把 `["Chicago,IL", "Atlanta,GA,  .... "]`名字和大洲通过逗号拼在一起然后投影。

Demo3：
也可以结合我们刚才说的查询集合成员的方法来进行投影

```xml
<property name="cityNames" value="#{cities.?[population gt 100000].![name+','+state]}"/>
```
`cities.?[population gt 100000]`先查询所有人口大于 100000 的城市，然后进行投影


## 变量定义及引用

在 SpEL 表达式中，变量定义通过 `EvaluationContext` 类的 `setVariable(variableName, value)` 函数来实现；在表达式中使用 ”`#variableName`” 来引用；除了引用自定义变量，SpEL 还允许引用根对象及当前上下文对象：

- `#this`：使用当前正在计算的上下文；
- `#root`：引用容器的 root 对象；

先使用 `setVariable` 存入一个值。

```java
EvaluationContext context = new StandardEvaluationContext();
context.setVariable("threshold", 100); // 定义一个叫 threshold 的变量
```
在表达式中加一个 `#`来引用定义的变量

```xml
<property name="isRich" value="#{cities.![population > #threshold]}"/>
```
## instanceof表达式
SpEL 支持 instanceof 运算符，跟 Java 内使用同义；如 ”`'haha' instanceof T(String)`” 将返回 true。

## 自定义函数
目前只支持类静态方法注册为自定义函数。SpEL 使用 `StandardEvaluationContext` 的 `registerFunction()` 方法进行注册自定义函数，其实完全可以使用 `setVariable` 代替，在 `registerFunction()`底层 事实上也是通过调用 `setVariable()`把一个名字和一个方法对象传入，本质一样的

示例，用户自定义实现字符串反转的函数：
```java
public class ReverseString {  
    public static String reverseString(String input) {  
        StringBuilder backwards = new StringBuilder();  
        for (int i = 0; i < input.length(); i++) {  
            backwards.append(input.charAt(input.length() - 1 - i));  
        }  
        return backwards.toString();  
    }  
}
```

通过如下代码将方法注册到 `StandardEvaluationContext` 并且来使用它：
```java
public class CustomFunctionReverse {  
    public static void main(String[] args) throws NoSuchMethodException {  
        ExpressionParser parser = new SpelExpressionParser();  
        StandardEvaluationContext context = new StandardEvaluationContext();  
        context.registerFunction("reverseString",  
                ReverseString.class.getDeclaredMethod("reverseString", new Class[] { String.class }));  
        String helloWorldReversed = parser.parseExpression("#reverseString('Drunkbaby')").getValue(context, String.class);  
        System.out.println(helloWorldReversed);  
    }  
}
```


