#!/bin/bash

# 腾讯云操作 DNS Hook

PATH=$(cd `dirname $0`; pwd)

echo $PATH"/txydns.py"

# 调用 python 脚本，自动设置 DNS TXT 记录。
# CERTBOT_DOMAIN: The domain being authenticated
# CERTBOT_VALIDATION: The validation string (HTTP-01 and DNS-01 only)

echo $CERTBOT_DOMAIN"_acme-challenge"$CERTBOT_VALIDATION

# 第一个参数：需要为那个域名设置 DNS 记录
# 第二个参数：需要为具体那个 RR 设置
# 第三个参数: letsencrypt 动态传递的 RR 值
python3  $PATH"/txydns36.py"  $CERTBOT_DOMAIN "_acme-challenge"  $CERTBOT_VALIDATION >"/var/log/certdebug.log"

# DNS TXT 记录刷新时间
/bin/sleep 20

echo "END"
###

