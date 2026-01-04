
```diff
Hashcat 常用选顶参数

-a                                #指定破解模式
-m                                #指定Hash类型（ 默认MD5 ）
-o                                #将输出结果储存到指定的文件
--force                           #忽略警告信息
--show                            #仅显示已经破解的Hash及其对应的明文（近期破解的存放在hashcat.potfile文件中）
--incremen                        #启用增量破解模式， 可以利用此模式让Hashcat     
--increment-min                   #在指定的密码长度范围内执行破解过程


Hashcat 的破解模式（ 用 -a 选顶指定）

-a  0         										#Straight （ 字典破解）
-a  1         										#Combination （ 组合破解）
-a  3         										#Brute-force （ 掩码暴力破解）
-a  6         										#Hybrid Wordlist + Mask （ 字典+掩码破解）
-a  7         										#Hybrid Mask + WordIist （ 掩码+字典破解）


Hashcat 的Hash 类型（ 用 -m 选项指定）
-m 900                           MD4
-m 0                       			 MD5
-m 100                           SHAI
-m 1300             		         SHA2-224
-m 1400              		         SHA2-256
-m 10800             		         SHA2-384
-m 1700              		         SHA2-512
-m 10                 	         MD5($pass.$salt)
-m 20                 	         MD5($salt.$pass)
-m 3800              		         MD5($saIt.$pass.$salt)
-m 3000               	         LM
-m 1000               	         N

```

```bash
sudo hashcat -m 0 -a 0 9d2f75377ac0ab991d40c91fd27e52fd    /usr/share/wordlists/rockyou.txt

-m                                #指定Hash类型（ 默认MD5 ）
-a  0         										#Straight （ 字典破解）

```
