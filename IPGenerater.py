# -*- codeing = utf-8 -*-
# Author:Zz

import re, optparse
import sys

ip_list = []

class IPCreate():
    def __init__(self, cip):
        self.cip = cip
        self.ip_list = []
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
    parser = optparse.OptionParser('python3 %prog -c 172.20.10.254-172.20.11.6 -o ip.txt\n'
                                   'python3 %prog -c 172.20.10.1 -p 8080,7001 -o ip.txt\n'
                                   'python3 %prog -c 172.20.10.1/26 -p 8080-8085 -o ip.txt\n'
                                   'python3 %prog -f ip.txt -p 8080-8085 -o ip.txt')

    parser.add_option('-c', dest='cip', default='172.20.10.1/24', help='172.20.10.1/24,172.20.10.253-172.20.11.6')
    parser.add_option('-f', dest='file', help='file.txt')
    parser.add_option('-p', dest='port', help='80,7001,8080-8081')
    parser.add_option('-o', dest='out_file', default='ip_out.txt',
                      help='Result ip list out file(default save in ip_out.txt)')
    (opts, args) = parser.parse_args()
    if (opts.port == None):
        ip_list = IPCreate(opts.cip).run()
        save(opts.out_file)
    elif (opts.file != None):
        get_file_ip_port(opts.file, opts.port)
        save(opts.out_file)
    else:
        get_ip_port(opts.cip, opts.port)
        save(opts.out_file)
