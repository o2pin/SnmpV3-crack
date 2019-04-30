# network
用来进行snmpv3协议的MD5暴力破解
-------------------
两个文件\n
authparam.py\n
dico.txt

修改authparam.py中参数，分别为msgAuthoritativeEngineID / msgAuthenticationParameters / msgraw
dico.txt是md5字典


运行
python3 authparam.py
