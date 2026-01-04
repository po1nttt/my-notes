# 工具
```
编码会话cookie
python flask_session_cookie_manager3.py encode -s 'your_secret_key' -t '{"username": "admin", "number": "123456"}'

```

```
解码会话cookie

python flask_session_cookie_manager3.py decode -c 'your_encoded_cookie' -s 'your_secret_key'


```




# flask session扫盲



## [0x01 什么是客户端session](https://www.leavesongs.com/PENETRATION/client-session-security.html#0x01-session)

在传统PHP开发中，`$_SESSION`变量的内容默认会被保存在服务端的一个文件中，通过一个叫“PHPSESSID”的Cookie来区分用户。这类session是“服务端session”，用户看到的只是session的名称（一个随机字符串），其内容保存在服务端。

然而，并不是所有语言都有默认的session存储机制，也不是任何情况下我们都可以向服务器写入文件。所以，很多Web框架都会另辟蹊径，比如Django默认将session存储在数据库中，而对于flask这里并不包含数据库操作的框架，就只能将session存储在cookie中。

因为cookie实际上是存储在客户端（浏览器）中的，所以称之为“客户端session”。


session生成的主要过程为

1. json.dumps 将对象转换成json字符串，作为数据
2. 如果数据压缩后长度更短，则用zlib库进行压缩
3. 将数据用base64编码
4. 通过hmac算法计算数据的签名，将签名附在数据后，用“.”分割

第4步就解决了用户篡改session的问题，因为在不知道secret_key的情况下，是无法伪造签名的。

最后，我们在cookie中就能看到设置好的session了：

注意到，在第4步中，flask仅仅对数据进行了签名。众所周知的是，签名的作用是防篡改，而无法防止被读取。而flask并没有提供加密操作，所以其session的全部内容都是可以在客户端读取的，这就可能造成一些安全问题。

## flask session 的组成


```css
[payload] . [timestamp] . [signature]
```
由payload   时间戳   签名来组成
由于payload 的生成方式固定，也就是说，我们不需要密钥也可以解密payload的内容。
这时我们就可以使用工具进行解密。



## 密钥

这时候最大的难题就是拿到密钥，我们只要拿到密钥就可以随意伪造session
密钥就会放在很多地方具体见下




# [ flask验证码绕过漏洞](https://www.leavesongs.com/PENETRATION/client-session-security.html#0x04-flask)

这是客户端session的另一个常见漏洞场景。

我们用一个实际例子认识这一点：[https://github.com/shonenada/flask-captcha](https://github.com/shonenada/flask-captcha) 。这是一个为flask提供验证码的项目，我们看到其中的view文件：
```python
import random
try:
    from cStringIO import StringIO
except ImportError:
    from io import BytesIO as StringIO

from flask import Blueprint, make_response, current_app, session
from wheezy.captcha.image import captcha
from wheezy.captcha.image import background
from wheezy.captcha.image import curve
from wheezy.captcha.image import noise
from wheezy.captcha.image import smooth
from wheezy.captcha.image import text
from wheezy.captcha.image import offset
from wheezy.captcha.image import rotate
from wheezy.captcha.image import warp

captcha_bp = Blueprint('captcha', __name__)

def sample_chars():
    characters = current_app.config['CAPTCHA_CHARACTERS']
    char_length = current_app.config['CAPTCHA_CHARS_LENGTH']
    captcha_code = random.sample(characters, char_length)
    return captcha_code

@captcha_bp.route('/captcha', endpoint="captcha")
def captcha_view():
    out = StringIO()
    captcha_image = captcha(drawings=[
        background(),
        text(fonts=current_app.config['CAPTCHA_FONTS'],
             drawings=[warp(), rotate(), offset()]),
        curve(),
        noise(),
        smooth(),
    ])
    captcha_code = ''.join(sample_chars())
    imgfile = captcha_image(captcha_code)
    session['captcha'] = captcha_code
    imgfile.save(out, 'PNG')
    out.seek(0)
    response = make_response(out.read())
    response.content_type = 'image/png'
    return response

```


可见，其生成验证码后，就存储在session中了：`session['captcha'] = captcha_code`。

我们用浏览器访问`/captcha`，即可得到生成好的验证码图片，此时复制保存在cookie中的session值，用0x03中提供的脚本进行解码：![[Pasted image 20251013220750.png]]
可见，我成功获取了验证码的值，进而可以绕过验证码的判断。

这也是客户端session的一种错误使用方法。



