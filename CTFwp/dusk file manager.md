##  dusk file manager

首先拿到项目之后我们先看看文件名称，找找有什么比较有用
例如index.php
auth.php
setting.php
login-callback.php
register.php
等有关登录逻辑，鉴权，初始化的东西
怎么登录
首先看看index.php的登录逻辑
![[Pasted image 20251108162651.png]]
我们看到登录过程中，每一步都需要认证我们的身份，并且，我们还不能注册合法账号，没有可以供我们利用的，但是注意到这个开头有一个
```
$allowed_levels = array(9, 8, 7, 0);  
和
require_once 'bootstrap.php';
```

我们跟进这个bootstrap.php
发现是一个初始化的入口
不了了之了

第一行它定义了四个用户组
我们思考，是什么来鉴定用户组的权限的呢？
注意到他把这个数组赋给了变量$allowed_levels
我们全局搜索allowed_levels
![[Pasted image 20251108163745.png]]
找到header.php
发现在这里有来鉴定用户组
![[Pasted image 20251110125953.png]]

这里鉴定用户组
我们全局搜索什么地方引入了header.php
![[Pasted image 20251108164138.png]]
找到了setting.php（设置）
可能跟一些权限有关


但是更有意思的是
在这个设置中所有的执行逻辑都在这个header.php前![[Pasted image 20251108164230.png]]
整个代码先执行，再去include   header.php
有逻辑漏洞。
![[Pasted image 20251108164631.png]]
重点在这，在设置中，我们可以控制用户可不可以注册，可不可以无需审核自行创建账号。所以我们可以自行创建账号
先修改设置
![[Pasted image 20251110133657.png]]


我们再去regisrer.php看看注册逻辑
![[Pasted image 20251108165050.png]]
修改设置之后去这个注册路由注册一个账号
就可以登陆了
我们注册一个账号
![[Pasted image 20251110133721.png]]
![[Pasted image 20251110133800.png]]


登陆上之后,就可以打一个正常的文件上传了
![[Pasted image 20251108171243.png]]
看这里

我们还可以更改上传文件的白名单，我们先修改.htaccess配置文件
![[Pasted image 20251110140648.png]]



然后上传一个
![[Pasted image 20251110140742.png]]


再上个马，直接蚁剑连
![[Pasted image 20251110141300.png]]
发现已经被解析了
发现权限不够看不了flag
![[Pasted image 20251110141513.png]]

发现suid可以提权哦
![[24844fafd1ef89aeb56978a9c2c4c5be.png]]
发现suid可以提权哦



grep提权![[Pasted image 20251108171640.png]]

grep "{" /flag
直接拿
![[Pasted image 20251110141544.png]]



