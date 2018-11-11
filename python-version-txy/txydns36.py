#!/usr/bin/env python
# coding:utf-8

import base64
import urllib
import hmac
import hashlib
import pytz
import time
import random
import string
import json
from urllib import request
from sys import argv

SecretId = "AKIDOdgU3M5Dl47vTlvZ6NO9j37va5PWG1Ui"
SecretKey = "7yaw2sSnshGZbMq40g6F8k59wVotlNAj"
URL = "cns.api.qcloud.com/v2/index.php?"

class TxyDns:
    def __init__(self, secretId, secretKey, domainName):
        self.secretId = secretId
        self.secretKey = secretKey
        self.domainName = domainName

    @staticmethod
    def generate_random_str(length=5):
        """
        生成一个指定长度(默认14位)的随机数值，其中
        string.digits = "0123456789'
        """
        str_list = [random.choice(string.digits) for i in range(length)]
        random_str = ''.join(str_list)
        return random_str

    @staticmethod
    def percent_encode(str):
        res = urllib.quote(str.encode('utf-8'), '')
        res = res.replace('+', '%20')
        res = res.replace('*', '%2A')
        res = res.replace('%7E', '~')
        return res

    @staticmethod
    def sign_string(url_param):
        """
            排序、拼接参数
        """
        sorted_url_param = sorted(url_param.items(), key=lambda x: x[0])
        can_string = ''
        for k, v in sorted_url_param:
            can_string += '&' + k + '=' + v
        string_to_sign = can_string[1:]
        return string_to_sign

    @staticmethod
    def utc_time():
        """
        请求的时间戳。
        """
        timestamp = str(int (time.time()))
        return timestamp

    def visit_url(self, action_param):
        common_param = {
            'Nonce': TxyDns.generate_random_str(),
            'SecretId': self.secretId,
            'Timestamp': TxyDns.utc_time(),
        }
        url_param = dict(common_param, **action_param)

        # 签名原文串的拼接规则为:
        # 请求方法(GET/POST) + 请求主机 +请求路径(v2/index.php) + ? + 请求字符串
        string_to_sign = "GET" + URL + TxyDns.sign_string(url_param)
        # print(string_to_sign)

        # 开始签名
        hash_bytes = self.secretKey
        h = hmac.new(hash_bytes.encode('utf-8'), string_to_sign.encode('utf-8'), digestmod=hashlib.sha1)
        signature = base64.encodestring(h.digest()).strip()

        url_param.setdefault('Signature', signature)
        url = "https://" + URL + urllib.parse.urlencode(url_param)
        return TxyDns.access_url(url)

    @staticmethod
    def access_url(url):
        req = request.Request(url)
        with request.urlopen(req) as f:
            result = f.read().decode('utf-8')
            print(result)
            return json.loads(result)

    # 显示所有
    def describe_domain_records(self):
        action_param = dict(
            Action='RecordList',
            offset='0',
            length='100',
            domain=self.domainName,
        )
        result = self.visit_url(action_param)
        return result

    # 删除解析
    def delete_domain_record(self, id):
        action_param = dict(
            Action="RecordDelete",
            domain=self.domainName,
            recordId=str(id),
        )
        result = self.visit_url(action_param)
        return result

    # 增加解析
    def add_domain_record(self, type, subDomain, value):
        action_param = dict(
            Action='RecordCreate',
            domain=self.domainName,
            subDomain=subDomain,
            recordType=type,
            recordLine="默认",
            value=value
        )
        result = self.visit_url(action_param)
        return result

if __name__ == '__main__':
    print(argv)
    file_name, certbot_domain, acme_challenge, certbot_validation = argv

    myDns = TxyDns(SecretId, SecretKey, certbot_domain)
    data = myDns.describe_domain_records()
    record_list = data["data"]["records"]
    if record_list:
        for item in record_list:
            if acme_challenge == item['name']:
                myDns.delete_domain_record(item['id'])

    myDns.add_domain_record("TXT", acme_challenge, certbot_validation)
