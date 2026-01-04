```bash
grep -R -i pass /home/* 2>/dev/null
```
# -R 
递归搜索，会进入子目录逐层查找。

# -i
忽略大小写。比如 `Pass`、`PASS`、`pass` 都会匹配

# /home/*
搜索范围，表示 `/home/` 目录下的所有文件和子目录。

# 2>/dev/null
把错误输出（文件描述符 2）重定向到 `/dev/null`，即丢弃错误信息。 这样如果某些文件没有权限访问，就不会显示报错。