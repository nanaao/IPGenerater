# IPGenerater
- - - -
根据指定的IP段,端口,或者文件，批量生成IP或IP加端口的工具。

According to the specified IP segment, port, or file, batch generated IP or IP plus port tools.


### 用法 / example
- - - -
* 生成172.20.10.1/28 IP段到res.txt文件中 (不指定-o则结果默认保存到当前目录生成的ip_out.txt文件中)
```
 python3 generate_ip.py -c 172.20.10.1/28 -o res.txt
```

* 生成 172.20.10.253 - 172.20.11.6 IP段
```
 python3 generate_ip.py -c 172.20.10.253-172.20.11.6
```

* 生成172.20.10.1/28  IP段加指定端口80,443
```
python3 generate_ip.py -c 172.20.10.1/28 -p 80,443
```

*  生成172.20.10.1/28  IP段加指定端口 8080 到 8085
```
python3 generate_ip.py -c 172.20.10.253-172.20.11.6 -p 8080-8085
```

* 根据文件内url或者IP添加指定端口
```
 python3 generate_ip.py -f ip.txt -p 80,443
```


- - - -

### Options
```
  -h, --help   show this help message and exit
  -c CIP       172.20.10.1/24,172.20.10.253-172.20.11.6
  -f FILE      file.txt
  -p PORT      80,7001,8080-8081
  -o OUT_FILE  Result ip list out file (default save in ip_out.txt)
```