# 前言

漏洞影响版本是 1.2.5 <= Apache Shiro <= 1.4.1

Apache Shiro Padding Oracle Attack 的漏洞利用必须满足如下前提条件：

- 开启 rememberMe 功能；
- rememberMe 值使用 AES-CBC 模式解密；
- 能获取到正常 Cookie，即用户正常登录的 Cookie 值；
- 密文可控；

