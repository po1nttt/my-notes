# 0x01 什么是IO流 
IO是指 Input/Output，即输入和输出。以内存为中心：

通过input把代码数据读到内存中
并且以Java 提供的某种数据类型表示，例如，`byte[]`，`String`，这样，后续代码才能处理这些数据。

因为内存有“易失性”的特点，所以必须把处理后的数据以某种方式输出，例如，写入到文件。Output 实际上就是把 Java 表示的数据格式，例如，`byte[]`，`String`等输出到某个地方。

IO 流是一种顺序读写数据的模式，它的特点是单向流动。数据类似自来水一样在水管中流动，所以我们把它称为 IO 流。

# 0x02java中创建文件的三种方式

### 1. 根据路径创建一个 File 对象

- 方法 `new File(String pathname)`
```java
package src.IOStream;  
  
import java.io.File;  
import java.io.IOException;  
  
// 根据路径创建一个 File 对象  
public class newFile {  
    public static void main(String[] args) {  
        createFile();  
 }  
    public static void createFile(){  
        File file = new File("Serialable/src/IOStream/CreateForFile/new1.txt");  
 try{  
            file.createNewFile();  
 System.out.println("Create Successfully");  
 } catch (IOException e){  
            e.printStackTrace();  
 }  
    }  
  
}
```



### [](https://drun1baby.top/2022/05/30/Java-IO%E6%B5%81/#2-%E6%A0%B9%E6%8D%AE%E7%88%B6%E7%9B%AE%E5%BD%95-File-%E5%AF%B9%E8%B1%A1%EF%BC%8C%E5%9C%A8%E5%AD%90%E8%B7%AF%E5%BE%84%E5%88%9B%E5%BB%BA%E4%B8%80%E4%B8%AA%E6%96%87%E4%BB%B6 "2. 根据父目录 File 对象，在子路径创建一个文件")2. 根据父目录 File 对象，在子路径创建一个文件

- 方法 `new File(File parent, String child)`

```java
package src.IOStream;  
  
import java.io.File;  
import java.io.IOException;  
  
// 根据父目录File对象，在子路径创建一个文件  
public class newFile02 {  
    public static void main(String[] args) {  
        createFile();  
 }  
    public static void createFile(){  
        File parentFile = new File("Serialable/src/IOStream/CreateForFile");  
 File file = new File(parentFile, "new2.txt");  
 try{  
            file.createNewFile();  
 System.out.println("Create Successfully");  
 } catch (IOException e){  
            e.printStackTrace();  
 }  
    }  
}
```
其实和第一个方法大同小异。

### [](https://drun1baby.top/2022/05/30/Java-IO%E6%B5%81/#3-%E6%A0%B9%E6%8D%AE%E7%88%B6%E7%9B%AE%E5%BD%95%E8%B7%AF%E5%BE%84%EF%BC%8C%E5%9C%A8%E5%AD%90%E8%B7%AF%E5%BE%84%E4%B8%8B%E7%94%9F%E6%88%90%E6%96%87%E4%BB%B6 "3. 根据父目录路径，在子路径下生成文件")3. 根据父目录路径，在子路径下生成文件

- 方法 `new File(String parent, String child)`

和之前两种方法还是有一些差距的。

```java
package src.IOStream;  
  
import java.io.File;  
import java.io.IOException;  
  
// 根据父目录路径，在子路径下生成文件  
public class newFile03 {  
    public static void main(String[] args) {  
        createFile();  
 }  
    public static void createFile(){  
        String parentPath = "Serialable/src/IOStream/CreateForFile";  
 String fileName = "new3.txt";  
 File file = new File(parentPath, fileName);  
 try{  
            file.createNewFile();  
 System.out.println("Create Successfully");  
 } catch (IOException e){  
            e.printStackTrace();  
 }  
    }  
}
```
创建三个 txt 文件。

# 0x03获取文件信息

我们在文本中编辑一些信息![[Pasted image 20251123154838.png]]
我们通过 `file` 类的方法名进行一些基本信息的获取
```java
package src.IOStream;  
  
import java.io.File;  
  
public class GetFileInfo {  
    public static void main(String[] args) {  
        getFileContents();  
 }  
  
    public static void getFileContents(){  
        File file = new File("Serialable/src/IOStream/CreateForFile/new1.txt");  
 System.out.println("文件名称为：" + file.getName());  
 System.out.println("文件的绝对路径为：" + file.getAbsolutePath());  
 System.out.println("文件的父级目录为：" + file.getParent());  
 System.out.println("文件的大小(字节)为：" + file.length());  
 System.out.println("这是不是一个文件：" + file.isFile());  
 System.out.println("这是不是一个目录：" + file.isDirectory());  
 }  
}
```
![[Pasted image 20251123173002.png]]

# 0x04 目录与文件操作
# 1.文件删除
- 使用 `file.delete(文件)`
```java
package src.IOStream;  
  
import java.io.File;  
import java.lang.reflect.Field;  
  
// 文件删除  
public class FileDelete {  
    public static void main(String[] args) {  
        deleteFile();  
 }  
    public static void deleteFile(){  
        File file = new File("Serialable/src/IOStream/CreateForFile/new1.txt");  
 System.out.println(file.delete() ? "Delete Successfully":"Delete failed");  
 }  
}
```
## 2.目录删除

- 方法 `file.delete(目录)`，这里有个小坑，只有空的目录才可以删除，不然会显示删除失败。
- 我在 `CreateForFile` 同级目录下新建了一个文件夹 `CreateForDelete` 用以测试。

```java
package src.IOStream;  
  
import java.io.File;  
  
//删除目录  
public class DirectoryDelete {  
    public static void main(String[] args) {  
        deleteDirectory();  
 }  
    public static void deleteDirectory(){  
        File file = new File("Serialable/src/IOStream/CreateForDelete");  
 System.out.println(file.delete()? "Delete Successfully":"Delete failed");  
 }  
}
```

## 3.创建单级目录
- 方法 `file.mkdir()`
```java
package src.IOStream;  
  
import java.io.File;  
  
// 创建单级目录  
public class CreateSingleDirectory {  
    public static void main(String[] args) {  
        createSingleDir();  
 }  
    public static void createSingleDir(){  
        File file = new File("Serialable/src/IOStream/CreateForDirectory");  
 System.out.println(file.mkdir() ? "Create Successfully":"Create failed");  
 }  
}
```

成功创建
## 创建多级目录

- 方法 `file.mkdirs()`，注意多了个 **s** 别搞错了。

```java
package src.IOStream;  
  
import java.io.File;  
  
// 创建多级目录  
public class CreateMultiDirectory {  
    public static void main(String[] args) {  
        createMultiDir();  
 }  
  
    public static void createMultiDir(){  
        File file = new File("Serialable/src/IOStream/CreateMultiDirectory/test");  
 System.out.println(file.mkdirs() ? "Create Successfully":"Create failed");  
  
 }  
}
```

![[Pasted image 20251123173442.png]]


# 0x05 IO流分类

按照操作数据单位不同分为：**字节流**和**字符流**

- 字节流（8bit，适用于二进制文件）
- 字符流（按字符，因编码不同而异，适用于文本文件）

按照数据流流向不同分为：**输入流**和**输出流**

按照流的角色不同分为：**节点流**，**处理流/包装流**

|抽象基类|字节流|字符流|
|---|---|---|
|输入流|InputStream|Reader|
|输出流|OutputStream|Writer|

- 到这里就非常重要了，因为它与我们后续的命令执行直接相关。这些 IO 流在我们命令执行的 Payload 当中充当着缓冲的作用。

# 0x06 关于文件流的一些操作
我们先来看看一些payload
# 1.Runtime 命令执行操作的Payload

```java
package src.CommandExec;  
  
import java.io.ByteArrayOutputStream;  
import java.io.InputStream;  
  
// 使用 Runtime 类进行命令执行  
public class RuntimeExec {  
    public static void main(String[] args) throws Exception {  
        InputStream inputStream = Runtime.getRuntime().exec("whoami").getInputStream();  
 byte[] cache = new byte[1024];  
 ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();  
 int readLen = 0;  
 while ((readLen = inputStream.read(cache))!=-1){  
            byteArrayOutputStream.write(cache, 0, readLen);  
 }  
        System.out.println(byteArrayOutputStream);  
 }  
}
```
其中，`byte[] cache = new byte[1024]` 用来缓存数据，我们结合这一串 Payload 来学习 Java IO 流甚好。 


## 2. FileInputStream
### read()方法
read方法如下
```java
read() 
	public int read() throws IOException 
	从此输入流中读取一个数据字节。
	
	如果没有输入可用，则此方法将阻塞。 
	
	指定者： 类 InputStream 中的 read 
	
	返回： 下一个数据字节；如果已到达文件末尾，则返回 -1。 
	
	抛出： IOException - 如果发生 I/O 错误。

```
之前我们用 `file` 的一系列操作读取过文件的信息，现在我们用 `FileInputStream.read()` 来读取文件内容。
```java
package src.IOStream;  
  
import java.io.FileInputStream;  
import java.io.IOException;  
  
// 使用 FileInputStream.read 读取文件  
public class FileInputRead {  
    public static void main(String[] args) {  
        readFile();  
 }  
    public static void readFile(){  
        String filePath = "Serialable/src/IOStream/CreateForFile/new1.txt";  
 FileInputStream fileInputStream = null;  
 int readData = 0;  
 try{  
            fileInputStream = new FileInputStream(filePath);  
 while((readData = fileInputStream.read())!=-1){  
                System.out.print((char)readData);  
 }  
        } catch (IOException e){  
            e.printStackTrace();  
 } finally {  
            try{  
                fileInputStream.close();  
 } catch (IOException e){  
                e.printStackTrace();  
 }  
        }  
    }  
}
```
成功读取到文件内容，这里有个小坑，若我们 sout ，则每一个字符都会经过换行。而如果不设置换行使用print而非println，才是正常的输出。

### read(byte\[\] d) 方法


允许在方法中添加一个字节数组。  
这种方式很有意思，当我们设置缓冲区的值为 8 时，若文件中的字符长度超过了 8，则会换行输出。这和上面的换行实际上是异曲同工。

再回到之前我们讲的 `Runtime` 类进行命令执行的 Payload，在那里，我们设置的 Cache 缓冲区的值为 1024.
```java
package src.IOStream;  
  
import java.io.FileInputStream;  
import java.io.IOException;  
  
// read(byte[] d) 方法，允许在方法中添加一个字节数组  
public class FileInputRead02 {  
    public static void main(String[] args) {  
        readFile();  
 }  
    public static void readFile(){  
        String filePath = "Serialable/src/IOStream/CreateForFile/new1.txt";  
 FileInputStream fileInputStream = null;  
 byte[] cache = new byte[8]; // 设置缓冲区，缓冲区大小为 8 字节  
 int readLen = 0;  
 try {  
            fileInputStream = new FileInputStream(filePath);  
 while((readLen = fileInputStream.read(cache)) != -1){  
                System.out.println(new String(cache, 0, readLen));  
 }  
        } catch (IOException e){  
                e.printStackTrace();  
 } finally {  
            try {  
                fileInputStream.close();  
 } catch (IOException e){  
                e.printStackTrace();  
 }  
        }  
    }  
}
```
这里的 while 会运行三次，会读取文件当中所有的字符。

## 3.  FileOutputStream


### write(byte[] b) 方法

```java
write(byte[] b)
public void write(byte[] b)
           throws IOException
将 b.length 个字节从指定 byte 数组写入此文件输出流中。
覆盖：
类 OutputStream 中的 write
参数：
b - 数据。
抛出：
IOException - 如果发生 I/O 错误。
```
我们尝试向文件当中写入数据，这里写代码的时候小心一点，容易踩坑的。
```java
package src.IOStream;  
  
import java.io.FileNotFoundException;  
import java.io.FileOutputStream;  
import java.io.IOException;  
  
// write(byte[] b) 方法  
public class FileOutputWrite01 {  
    public static void main(String[] args) {  
        writeFile();  
 }  
  
    public static void writeFile() {  
        String filePath = "Serialable/src/IOStream/CreateForFile/new1.txt";  
 FileOutputStream fileOutputStream = null;  
 try { // 注意fileOutputStream的作用域，因为fileOutputStream需要在finally分支中被异常捕获  
 // 所以这里的 try 先不闭合  
 fileOutputStream = new FileOutputStream(filePath);  
 String content = "gulugulu";  
 try {  
                //write(byte[] b) 将 b.length 个字节从指定 byte 数组写入此文件输出流中  
 //String类型的字符串可以使用getBytes()方法将字符串转换为byte数组  
 fileOutputStream.write(content.getBytes());  
 } catch (IOException e) {  
                e.printStackTrace();  
 }  
        }catch (FileNotFoundException e){  
            e.printStackTrace();  
 }  
        finally {  
            try {  
                fileOutputStream.close();  
 } catch (IOException e){  
                e.printStackTrace();  
 }  
        }  
    }  
}

```
### write(byte[] b, int off, int len) 方法

- 将指定 byte 数组中从偏移量 off 开始的 len 个字节写入此文件输出流。

这里的长度一定要与输入的字符相等。
```java
package src.IOStream;  
  
import java.io.FileNotFoundException;  
import java.io.FileOutputStream;  
import java.io.IOException;  
import java.nio.charset.StandardCharsets;  
  
// write(byte[] b) 方法  
public class FileOutputWrite02 {  
    public static void main(String[] args) {  
        writeFile();  
 }  
  
    public static void writeFile() {  
        String filePath = "Serialable/src/IOStream/CreateForFile/new1.txt";  
 FileOutputStream fileOutputStream = null;  
 try { // 注意fileOutputStream的作用域，因为fileOutputStream需要在finally分支中被异常捕获  
 // 所以这里的 try 先不闭合  
 fileOutputStream = new FileOutputStream(filePath);  
 String content = "drinkdrink";  
 try {  
                //write(byte[] b) 将 b.length 个字节从指定 byte 数组写入此文件输出流中  
 //String类型的字符串可以使用getBytes()方法将字符串转换为byte数组  
 fileOutputStream.write(content.getBytes(StandardCharsets.UTF_8), 0, 10);  
 } catch (IOException e) {  
                e.printStackTrace();  
 }  
        }catch (FileNotFoundException e){  
            e.printStackTrace();  
 }  
        finally {  
            try {  
                fileOutputStream.close();  
 } catch (IOException e){  
                e.printStackTrace();  
 }  
        }  
    }  
}
```


### 追加写入

如果想要写入的数据不被覆盖，可以设置 `FileOutputStream` 的构造方法 `append` 参数设置为 `true`
```java
fileOutputStream = new FileOutputStream(filePath);
// 设置追加写入
fileOutputStream = new FileOutputStream(filePath), true;
```



## 4.文件拷贝 ———— input outp 结合

利用前文讲的 `fileInputStream` 和 `fileOutputStream` 进行文件拷贝。

原理上来说，先将文件的内容(注意，其实图片当中也是内容，这个内容不光是文字！) 读取出来，再写入新的文件当中。
```java
package src.IOStream;  
  
import java.io.FileInputStream;  
import java.io.FileOutputStream;  
import java.io.IOException;  
  
// 文件拷贝操作  
public class FileCopy {  
    public static void main(String[] args) {  
            copyFile();  
 }  
    public static void copyFile(){  
        String srcFilename = "Serialable/src/IOStream/CreateForFile/new1.txt";  
 String desFilename = "Serialable/src/IOStream/CreateForFile/new2.txt";  
 FileInputStream fileInputStream = null;  
 FileOutputStream fileOutputStream = null;  
 try {  
            fileInputStream = new FileInputStream(srcFilename);  
 fileOutputStream = new FileOutputStream(desFilename);  
 byte[] cache = new byte[1024];  
 int readLen = 0;  
 while((readLen = fileInputStream.read(cache)) != -1){  
                fileOutputStream.write(cache, 0, readLen);  
 }  
    } catch (IOException e){  
            e.printStackTrace();  
 } finally {  
            try {  
                fileInputStream.close();  
 fileOutputStream.close();  
 } catch (IOException e){  
                e.printStackTrace();  
 }  
        }  
        }  
}
```


## 5 FileReader
```java
public class FileReader extends InputStreamReader
用来读取字符文件的便捷类。此类的构造方法假定默认字符编码和默认字节缓冲区大小都是适当的。要自己指定这些值，可以先在 FileInputStream 上构造一个 InputStreamReader。
FileReader 用于读取字符流。要读取原始字节流，请考虑使用 FileInputStream。
```
下方测试代码将会将 `Serialable/src/IOStream/CreateForFile/new1.txt` 中的 new1.tx 文件打印输出至控制台：
```java
package src.IOStream;  
  
import java.io.FileReader;  
import java.io.IOException;  
  
// 读取文件的字符流  
public class FileReaderPrint {  
    public static void main(String[] args) {  
        readFile();  
 }  
    public static void readFile(){  
        String filePath = "Serialable/src/IOStream/CreateForFile/new1.txt";  
 FileReader fileReader = null;  
 try {  
            fileReader = new FileReader(filePath);  
 int readLen = 0;  
 char[] cache = new char[8];  
 while ((readLen = fileReader.read(cache))!=-1){  
                System.out.println(new String(cache, 0, readLen));  
 }  
        } catch (IOException e){  
            e.printStackTrace();  
 } finally {  
            try {  
                fileReader.close();  
 } catch (IOException e){  
                e.printStackTrace();  
 }  
        }  
    }  
}
```
- `FileReader` 将会一个一个**字符**读取，因此可以不乱码输出中文