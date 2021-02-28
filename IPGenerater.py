# -*- codeing = utf-8 -*-

import re
import argparse
import sys

ip_list = []


def parse_args():
    parser = argparse.ArgumentParser(
        epilog='\tExample: \r\npython3 ' + sys.argv[0] + ' -c 172.20.10.1/26 -p 80,443 -o ip.txt')
    parser.add_argument('-c', dest='cip', default='172.20.10.1/24', help='172.20.10.1/24,172.20.10.253-172.20.11.6')
    parser.add_argument('-f', dest='file', help='file.txt')
    parser.add_argument('-p', dest='port', help='80,7001,8080-8081')
    parser.add_argument('-o', dest='out_file', default='ip_out.txt',
                        help='Result ip list out file(default save in ip_out.txt)')
    return parser.parse_args()


# IP_Create comes form  https://github.com/grayddq/IPCreate
class IPCreate():
    def __init__(self, cip):
        self.cip = cip
        self.result_info = []

    def isIP(self, str):
        p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
        if p.match(str):
            return True
        else:
            return False

    def ip2num(self, ip):
        ips = [int(x) for x in ip.split('.')]
        return ips[0] << 24 | ips[1] << 16 | ips[2] << 8 | ips[3]

    def num2ip(self, num):
        return '%s.%s.%s.%s' % ((num >> 24) & 0xff, (num >> 16) & 0xff, (num >> 8) & 0xff, (num & 0xff))

    def getIPs(self, ips):
        start, end = [self.ip2num(x) for x in ips.split('-')]
        return [self.num2ip(num) for num in range(start, end + 1) if num & 0xff]

    def dec255_to_bin8(self, dec_str):
        bin_str = bin(int(dec_str, 10)).replace("0b", '')
        headers = ['', '0', '00', '000', '0000', '00000', '000000', '0000000']
        if len(bin_str) < 8:
            bin_str = headers[8 - len(bin_str)] + bin_str
        return bin_str

    def ipstr_to_binstr(self, ip):
        a, b, c, d = ip.split(".")
        ipbin = self.dec255_to_bin8(a) + self.dec255_to_bin8(b) + self.dec255_to_bin8(c) + self.dec255_to_bin8(d)
        return ipbin

    def binstr_to_ipstr(self, binstr):
        return str(int(binstr[0:8], base=2)) + "." + str(int(binstr[8:16], base=2)) + "." + str(
            int(binstr[16:24], base=2)) + "." + str(int(binstr[24:32], base=2))

    # 把带有子网掩码的网段转成-格式
    def FormtIP(self, ips):
        if ips.find('/') > 0:
            ip, mask = ips.split("/")
            ipbin = self.ipstr_to_binstr(ip)
            ipnet_bin = ipbin[0:int(mask)] + ipbin[int(mask):32].replace("1", "0")
            ipstart_bin = bin(int(ipnet_bin, base=2) + 1).replace("0b", '')
            ipend_bin = bin(int(ipnet_bin, base=2) + pow(2, 32 - int(mask)) - 2).replace("0b", '')
            if(len(ipstart_bin)<32):
                ipstart_bin='00'+ipstart_bin
                ipend_bin='00'+ipend_bin
            ipstart = self.binstr_to_ipstr(ipstart_bin)
            ipend = self.binstr_to_ipstr(ipend_bin)
            return ipstart + "-" + ipend
        # 把单独的IP转成-格式
        elif self.isIP(ips):
            return ips + '-' + ips
        return ips

    def run(self):
        self.result_info += self.getIPs(self.FormtIP(self.cip))
        return self.result_info


def get_ip_port(curl, port):
    list = IPCreate(curl).run()
    if ',' in port:
        port_list = port.split(',')
        for ip in list:
            for p in port_list:
                p = str(p)
                url = ip + ":" + p
                ip_list.append(url)
    elif "-" in port:
        port_list = port.split('-')
        for ip in list:
            for p in range(int(port_list[0]), int(port_list[1]) + 1):
                p = str(p)
                url = ip + ":" + p
                ip_list.append(url)
    else:
        for ip in list:
            p = str(port)
            url = ip + ":" + p
            ip_list.append(url)


def get_file_ip_port(file, port):
    file_ip = []
    with open(file, 'r') as f:
        for i in f:
            i = i.strip()
            file_ip.append(i)
    f.close()
    if ',' in port:
        port_list = port.split(',')
        for ip in file_ip:
            for p in port_list:
                p = str(p)
                url = ip + ":" + p
                ip_list.append(url)
    elif "-" in port:
        port_list = port.split('-')
        for ip in file_ip:
            for p in range(int(port_list[0]), int(port_list[1]) + 1):
                p = str(p)
                url = ip + ":" + p
                ip_list.append(url)
    else:
        for ip in file_ip:
            p = str(port)
            url = ip + ":" + p
            ip_list.append(url)


def save(file):
    f = open(file, 'w')
    for i in ip_list:
        f.write(i + '\r\n')
    f.close()


if __name__ == '__main__':
    if sys.version_info < (3, 0):
        sys.stdout.write("Sorry,requires Python 3.x\n")
        sys.exit(1)
    arags = parse_args()

    if (arags.port == None):
        ip_list = IPCreate(arags.cip).run()
        save(arags.out_file)
    elif (arags.file != None):
        get_file_ip_port(arags.file, arags.port)
        save(arags.out_file)
    else:
        get_ip_port(arags.cip, arags.port)
        save(arags.out_file)
