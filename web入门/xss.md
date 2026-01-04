## 常见的绕过技术

### [](https://joner11234.github.io/article/ee2d094d.html#%E9%98%B2%E8%BF%87%E6%BB%A4 "防过滤")防过滤

有的网站会直接过滤`"<script>"、"<a>"、"<img>"`这些标签。在测试过程中，我们可以改变测试语句的大小写来绕过XSS规则.比如：

`<script>alert("xss");</script>`  
可以转换为：  
`<ScRipt>ALeRt("XSS");</sCRipT>`  
对于只过滤一次“script”的情况我们还可以很巧合地把请求构造成这样：  
`<scr<script>ipt>alert("XSS")</scr<script>ipt>`  
对于完全过滤”script”、”javascript”等脚本相关的字符时，我们可以使用DOM Based XSS，例如：  
`<img src=1 onerror=alert(1)>`

#### [](https://joner11234.github.io/article/ee2d094d.html#JS%E8%BF%98%E5%8E%9F%E5%87%BD%E6%95%B0 "JS还原函数")JS还原函数

JS中的编码还原函数最常用的就是`String.fromCharCode`了，这个函数用于ascii码的还原，一般来说，这个函数都要配合EVAL来使用才有效果。

在跨站中，`String.fromCharCode`主要是使到一些已经被列入黑名单的关键字或语句安全通过检测，把关键字或语句转换成为ASCII码，然后再用`String.fromCharCode还原，因为大多数的过滤系统都不会把String.fromCharCode`加以过滤，例如关键字alert被过滤掉，那就可以这么利用：

`<img src="x"/**/onerror="eval(String.fromCharCode(97,108,101,114,116,40,39,112,111,114,117,105,110,39,41))"></img>`

#### [](https://joner11234.github.io/article/ee2d094d.html#%E7%BC%96%E7%A0%81%E7%B1%BB%EF%BC%9A "编码类：")编码类：

编码类绕过主要有URL编码，unicode编码，HTML编码，CSS编码和非常冷门的js-fuck编码

1. URL编码

URL编码最常见的是在用GET/POST传输时，顺序是把字符改成%+ASCII两位十六进制(先把字符串转成ASCII编码，然后再转成十六进制)。js处理URL编码的时候有三个函数可以使用，分别是escape()函数、encodeURI()函数 、encodeURIComponent()函数，对应的解码函数分别是unescape()、decodeURI()、decodeURIComponent()；

2. unicode编码

Unicode编码的字符以%u为前缀，后面是这个字符的十六进制unicode的码点。当有些站点的后端验证可以识别Unicode编码的字符时，就可以用这个方法绕过了。

3. HTML编码

HTML编码的存在就是让他在代码中和显示中分开， 避免错误。他的命名实体：构造是&加上希腊字母，字符编码：构造是&#加十进制、十六进制ASCII码或unicode字符编码，而且浏览器解析的时候会先把html编码解析再进行渲染。但是有个前提就是必须要在“值”里。

4. CSS编码

主要是利用css中的expression()表达式表达式中可以执行js脚本来达到攻击的目的，但是我刚刚测试了一下expression()表达式在IE7及以下是有效的，在IE8及以上就失效了，无法识别。这种方法目前应该是无法使用了。

5. Ascii编码

这种方式主要利用了js的eval()函数和String.fromCharCode()函数。eval()函数是一个神奇的函数，可以用来计算一个字符串，将字符串变为js的表达式或者可执行语句,String.fromCharCode()函数则是将一段Ascii码转化为字符串。配合起来就例如下面的这一句代码：

|   |   |
|---|---|
|1|<script>eval(String.fromCharCode(97,108,101,114,116,40,47,120,115,115,47,41));</script>|

其作用相当于

|     |                               |
| --- | ----------------------------- |
| 1   | <script>alert(/xss/)</script> |