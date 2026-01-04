import os
import re

def replace_image_links(directory):
    # 定义匹配图片链接的正则表达式
    pattern = r'<div\s+align=center><img\s+src="(\./images/[^"]+)"\s*></div>'

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".md"):  # 假设要处理的文件扩展名为 .html
                filepath = os.path.join(root, file)
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # 使用正则表达式查找匹配的内容并替换
                replaced_content = re.sub(pattern, r'![[\1]]', content)

                # 将替换后的内容写回文件
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(replaced_content)

if __name__ == "__main__":
    current_directory = os.getcwd()  # 获取当前文件夹路径
    replace_image_links(current_directory)
