- [1. usage](#1-usage)
  - [1.1. Pipline](#11-pipline)
    - [1.1.1. 数据流方向](#111-数据流方向)
    - [1.1.2. experiment deploy](#112-experiment-deploy)
- [2.  HTML applications](#2-html-applications)
  - [2.1. how to install ``lexbor`` library](#21-how-to-install-lexbor-library)
  - [2.2. how to add the ``lexbor`` library](#22-how-to-add-the-lexbor-library)
  - [2.3. dynamic link error](#23-dynamic-link-error)
  - [2.4. how to get the inner element ``streams_`` in ``Client`` Class](#24-how-to-get-the-inner-element-streams_-in-client-class)
  - [2.5. 多网站测量](#25-多网站测量)
    - [2.5.1. 相关配置](#251-相关配置)
    - [2.5.2. 脚本执行测试](#252-脚本执行测试)
- [3. construct DNS server](#3-construct-dns-server)
  - [3.1. setting](#31-setting)
    - [3.1.1. 安装BIND软件](#311-安装bind软件)
    - [3.1.2. options](#312-options)
      - [3.1.2.1. sudo vim /etc/bind/named.conf.options](#3121-sudo-vim-etcbindnamedconfoptions)
      - [3.1.2.2. sudo named-checkconf](#3122-sudo-named-checkconf)
      - [3.1.2.3. sudo vim /etc/bind/named.conf.local](#3123-sudo-vim-etcbindnamedconflocal)
      - [3.1.2.4. sudo mkdir /etc/bind/zones](#3124-sudo-mkdir-etcbindzones)
      - [3.1.2.5. sudo vim /etc/bind/zones/db.example.com](#3125-sudo-vim-etcbindzonesdbexamplecom)
      - [3.1.2.6. sudo named-checkzone example.com /etc/bind/zones/db.example.com](#3126-sudo-named-checkzone-examplecom-etcbindzonesdbexamplecom)
      - [3.1.2.7. sudo vim /etc/bind/zones/db.10.128.0](#3127-sudo-vim-etcbindzonesdb101280)
      - [3.1.2.8. sudo named-checkzone 0.128.10.in-addr.arpa /etc/bind/zones/db.10.128.0](#3128-sudo-named-checkzone-012810in-addrarpa-etcbindzonesdb101280)
      - [3.1.2.9. sudo service bind9 restart](#3129-sudo-service-bind9-restart)
  - [3.2. 去另一台机子test上进行配置](#32-去另一台机子test上进行配置)
      - [3.2.0.1. sudo vim /etc/resolvconf/resolv.conf.d/head](#3201-sudo-vim-etcresolvconfresolvconfdhead)
      - [3.2.0.2. sudo vim /etc/resolv.conf](#3202-sudo-vim-etcresolvconf)
      - [3.2.0.3. nameserver  10.128.0.9](#3203-nameserver-1012809)
      - [3.2.0.4. sudo resolvconf -u](#3204-sudo-resolvconf--u)
  - [3.3. 进行测试](#33-进行测试)
- [4. ngtcp2 loadbalancer](#4-ngtcp2-loadbalancer)
  - [4.1. 安装dev包、mysqlclient](#41-安装dev包mysqlclient)
  - [4.2. SSL_CTX_set_ciphersuites@OPENSSL_1_1_1 问题时](#42-ssl_ctx_set_ciphersuitesopenssl_1_1_1-问题时)
  - [4.3. openssl/build/lib/pkgconfig 在这个目录下创建一个文件mysqlclient.pc](#43-opensslbuildlibpkgconfig-在这个目录下创建一个文件mysqlclientpc)
  - [4.4. 在configure.ac里面把[mysqlclient >= 5.7.23]改成mysqlclient >= 5.6.47](#44-在configureac里面把mysqlclient--5723改成mysqlclient--5647)
  - [4.5. configure.sh](#45-configuresh)
  - [4.6. 运行方法：](#46-运行方法)
    - [4.6.1. Client：](#461-client)
    - [4.6.2. server：](#462-server)
    - [4.6.3. balancer](#463-balancer)
- [5. ngtcp2 master](#5-ngtcp2-master)
- [6. ngtcp2 legacy](#6-ngtcp2-legacy)
- [7. 编译guide](#7-编译guide)
  - [7.1. Second Implementation Draft](#71-second-implementation-draft)
  - [7.2. Requirements](#72-requirements)
  - [7.3. Build from git](#73-build-from-git)
  - [7.4. Client/Server](#74-clientserver)


# 1. usage
## 1.1. Pipline
### 1.1.1. 数据流方向
test -> router -> server
对应的程序为client, balancer, server


### 1.1.2. experiment deploy
``` bash
# 在test上
cd /home/johnsonli1993/Hestia
# 先删除experiment.gcloud.main.py文件中的最后几条预设值的sql语句
# 这是启动机子并进行相关的配置，配置内容包括复制程序、配置数据库。
# 配置内容包括复制server，balancer到/home/wch19990119/data下，并且根据服务器的名字自动启动对应的server/balancer。
# data.zip 中的文件来自于/home/johnsonli1993/Hestia/experiment/gcloud/data文件夹进行压缩
python -m  experiment.gcloud.main 
python -m  experiment.gcloud.main # 这条命令需要运行两次，第一次似乎是22端口配置有问题无法访问
cd /home/1019735081/ngtcp2-loadbalancer
sudo ./examples/client <某一台router的公网ip> 4433
```


# 2.  HTML applications
## 2.1. how to install ``lexbor`` library 
- LINK: http://lexbor.com/docs/lexbor/
- Download Lexbor signing key used for our repositories and packages and add it to apt’s keyring:
``` bash
curl -O https://lexbor.com/keys/lexbor_signing.key
apt-key add lexbor_signing.key
```

- To configure Lexbor repository, create the following file named ``/etc/apt/sources.list.d/lexbor.list``:
    - Ubuntu 18.04:
``` bash
deb https://packages.lexbor.com/ubuntu/ bionic liblexbor
deb-src https://packages.lexbor.com/ubuntu/ bionic liblexbor
```

- Install Lexbor base package and additional packages you would like to use.
```bash
apt update
apt install liblexbor
apt install liblexbor-dev
```
## 2.2. how to add the ``lexbor`` library
- in configure running:
  - ./configure PKG_CONFIG_PATH=$PWD/../../openssl/build/lib/pkgconfig LDFLAGS="-Wl,-rpath,$PWD/../../openssl/build/lib -llexbor" --host=arm
  - this means you need add ``llexbor`` and ``--host=arm``
## 2.3. dynamic link error 
- echo $LD_LIBRARY_PATH
- LD_LIBRARY_PATH=/usr/local/lib
- export LD_LIBRARY_PATH
## 2.4. how to get the inner element ``streams_`` in ``Client`` Class
- 通过增加了一个messages的全局变量数组，数据类型是message
- message struct 主要包括了client类中的conn_, streams_, 还有HTML的content信息。
- message中有一个``message_complete_cb_called``，用来控制收到data是否需要http解析
## 2.5. 多网站测量
### 2.5.1. 相关配置
- 在ngtcp目录下增加index.csv，每一行是一个网站（eg: google.com）
- 在ngtcp目录下增加websites，其中放有har文件解析后的文件
### 2.5.2. 脚本执行测试
``` bash
./evaluate_top.sh
```



# 3. construct DNS server
## 3.1. setting
### 3.1.1. 安装BIND软件
sudo apt-get install bind9 bind9utils bind9-doc resolvconf -y

### 3.1.2. options
#### 3.1.2.1. sudo vim /etc/bind/named.conf.options
``` vim
acl "trusted" {
    10.128.0.9;
    10.128.0.2;
};
options {
        directory "/var/cache/bind";

        recursion no;
        // allow-recursion {
        //    trusted;
        // };
        listen-on {10.128.0.9;};
        allow-transfer {none;};
        
        // If there is a firewall between you and nameservers you want
        // to talk to, you may need to fix the firewall to allow multiple
        // ports to talk.  See http://www.kb.cert.org/vuls/id/800113

        // If your ISP provided one or more IP addresses for stable
        // nameservers, you probably want to use them as forwarders.
        // Uncomment the following block, and insert the addresses replacing
        // the all-0's placeholder.

        // forwarders {
        //      114.114.114.114;
        // };

        //========================================================================
        // If BIND logs error messages about the root key being expired,
        // you will need to update your keys.  See https://www.isc.org/bind-keys
        //========================================================================
        dnssec-validation auto;

        auth-nxdomain no;    # conform to RFC1035
        listen-on-v6 { any; };
};
```
#### 3.1.2.2. sudo named-checkconf

#### 3.1.2.3. sudo vim /etc/bind/named.conf.local 
``` vim
zone "example.com" {
    type master;
    file "/etc/bind/zones/db.example.com";
};

zone "0.128.10.in-addr.arpa" {
    type master;
    file "/etc/bind/zones/db.10.128.0";
};
```
#### 3.1.2.4. sudo mkdir /etc/bind/zones

#### 3.1.2.5. sudo vim /etc/bind/zones/db.example.com
``` vim
;
; BIND data file for local loopback interface
$TTL    604800
@       IN      SOA     ns2.example.com. admin.example.com. (
          2         ; Serial
     604800         ; Refresh
      86400         ; Retry
    2419200         ; Expire
     604800 )       ; Negative Cache TTL
;
;
; name servers - NS records
     IN      NS      ns2.example.com.
; name servers - A records
ns2.example.com.          IN      A       10.128.0.9

ns1.example.com.          IN      A       10.128.0.8

host1.example.com.        IN      A      10.128.0.2
```
#### 3.1.2.6. sudo named-checkzone example.com /etc/bind/zones/db.example.com

#### 3.1.2.7. sudo vim /etc/bind/zones/db.10.128.0
``` vim
$TTL    604800
@       IN      SOA     example.com. admin.example.com. (
          1         ; Serial
     604800         ; Refresh
      86400         ; Retry
    2419200         ; Expire
     604800 )       ; Negative Cache TTL
; name servers
      IN      NS      ns2.example.com.

; PTR Records
8   IN      PTR     ns1.example.com.  ; 这一行的第一个数字对应10.128.0.8中的8
9   IN      PTR     ns2.example.com.
2   IN      PTR     host1.example.com.
```

#### 3.1.2.8. sudo named-checkzone 0.128.10.in-addr.arpa /etc/bind/zones/db.10.128.0

#### 3.1.2.9. sudo service bind9 restart

## 3.2. 去另一台机子test上进行配置
#### 3.2.0.1. sudo vim /etc/resolvconf/resolv.conf.d/head
``` vim
nameserver 10.128.0.9
```
#### 3.2.0.2. sudo vim /etc/resolv.conf
``` vim
options timeout:1 attempts:1 rotate
```
#### 3.2.0.3. nameserver  10.128.0.9

#### 3.2.0.4. sudo resolvconf -u

## 3.3. 进行测试
```shell
nslookup example.com 10.128.0.9
nslookup host1.example.com 10.128.0.9
nslookup ns1.example.com 10.128.0.9
nslookup ns2.example.com 10.128.0.9
nslookup 10.128.0.2 10.128.0.9
nslookup 10.128.0.8 10.128.0.9
```


# 4. ngtcp2 loadbalancer
**balancer是负责数据包转发的proxy**
## 4.1. 安装dev包、mysqlclient
- sudo apt install libev-dev  mysql-client libmysql++-dev mysql-server -y

## 4.2. SSL_CTX_set_ciphersuites@OPENSSL_1_1_1 问题时
- 把libmysqlclient-dev的版本降一下
  - sudo apt install libmysqlclient-dev=5.7.21-1ubuntu1
- 若有用apt安装发现有冲突，可以手动安装
    ```vim
    sudo apt install -y libmysql++3v5
    wget http://launchpadlibrarian.net/355857431/libmysqlclient20_5.7.21-1ubuntu1_amd64.deb
    sudo apt install -y ./libmysqlclient20_5.7.21-1ubuntu1_amd64.deb
    wget http://launchpadlibrarian.net/355857415/libmysqlclient-dev_5.7.21-1ubuntu1_amd64.deb
    sudo apt install -y ./libmysqlclient-dev_5.7.21-1ubuntu1_amd64.deb
    ```

## 4.3. openssl/build/lib/pkgconfig 在这个目录下创建一个文件mysqlclient.pc
- 这个是pkg-config用来发现动态链接库的。之前的错误是./configure的时候没有通过pkg-config找到mysqlclient的动态链接库的描述文件 也就是这个.pc文件
```
exec_prefix=/usr/bin
libdir=/usr/lib/x86_64-linux-gnu/
includedir=/usr/include/mysql 

Name: mysqlclient
Description: MysqlClient 
Version: 5.6.47 # 版本可能需要根据环境change
Libs: -L${libdir} -lmysqlclient -L ssl
Clibs
```
## 4.4. 在configure.ac里面把[mysqlclient >= 5.7.23]改成mysqlclient >= 5.6.47

## 4.5. configure.sh
- ./configure PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/:$PWD/../openssl/build/lib/pkgconfig LDFLAGS="-Wl,-rpath,$PWD/../openssl/build/lib"


## 4.6. 运行方法：
### 4.6.1. Client：
- start-client.sh
- sudo ./examples/client <本机外网ip> 4433 

### 4.6.2. server：
- start_server.sh
- sudo ./examples/server 0.0.0.0 4433 --interface eth0 --unicast <本机外网ip> server.key server.crt

### 4.6.3. balancer
- start-balancer.sh
- sudo ./examples/balancer --datacenter test --user johnson --password johnson eth0 0.0.0.0 4433 ~/keys/server.key ~/keys/server.crt
- 本地dc名称：--datacenter <本机绑定的local datecenter名字>
- 数据库用户名 --user johnson
- 数据库密码 --password johnson


# 5. ngtcp2 master
**支持late binding的quic库**
1. server.cc
    - 改用ipv6

2. server端的命令改用这个命令 since we use the ipv6
> examples/server ::1 4433 server.key server.crt

3. client.cc
    - 加了hash
    - 在get_hashed_ip中已经设置了默认ip为ipv6
    - send -> sendto， read -> recvfrom。这两个都是socket包中的函数
    - OnMigration 函数进行转移？
    - server_unicast_ip进行绑定

4. client端最好也改用
> examples/client ::1 4433 -i


"Call it TCP/2.  One More Time."

ngtcp2 project is an effort to implement QUIC protocol which is now
being discussed in IETF QUICWG for its standardization.


# 6. ngtcp2 legacy
1. 获取ngtcp2的源代码 https://github.com/johnson-li/ngtcp2，checkout legacy branch，这个是原始的quic库。按照readme编译并运行client和server

2. checkout master分支，这个是支持late binding的quic库。因为缺乏文档，建议先查看一下我们与legacy分支相比改了哪些代码，再尝试编译运行client和server

3. checkout loadbalancer分支，这个是负责数据包转发的proxy。同样缺乏文档，建议先查看一下我们与legacy分支相比改了哪些代码，再尝试编译运行client和server

这个过程应该会有一些GCC编译的坑。。。建议直接在我们给Google cloud 上的Debian服务器做测试


# 7. 编译guide
## 7.1. Second Implementation Draft

We are focusing on implementing [Second Implementation Draft](<https://github.com/quicwg/base-drafts/wiki/Second-Implementation-Draft>)

* https://quicwg.github.io/base-drafts/draft-ietf-quic-transport.html
* https://quicwg.github.io/base-drafts/draft-ietf-quic-tls.html

## 7.2. Requirements
The libngtcp2 C library itself does not depend on any external
libraries.  The example client, and server are written in C++14, and
should compile with the modern C++ compilers (e.g., clang >= 4.0, or
gcc >= 5.0).

The following packages are required to configure the build system:

* pkg-config >= 0.20
* autoconf
* automake
* autotools-dev
* libtool

libngtcp2 uses cunit for its unit test frame work:

* cunit >= 2.1

To build sources under the examples directory, libev is required:

* libev

The client and server under examples directory require OpenSSL (master
branch) as crypto backend:

* OpenSSL (https://github.com/openssl/openssl/)

At the moment, the patched OpenSSL is required to compile ngtcp2 to
enable 0-RTT.  See below.

## 7.3. Build from git

```
$ git clone --depth 1 -b quic https://github.com/tatsuhiro-t/openssl
$ cd openssl

$ # For Linux
$ ./config enable-tls1_3 --prefix=$PWD/build
$ make -j$(nproc)
$ make install_sw
$ cd ..
$ git clone https://github.com/ngtcp2/ngtcp2
$ cd ngtcp2
$ autoreconf -i

$ # For Mac users who have installed libev with MacPorts, append
$ # ',-L/opt/local/lib' to LDFLAGS, and also pass
$ # CPPFLAGS="-I/opt/local/include" to ./configure.

$ ./configure PKG_CONFIG_PATH=$PWD/../openssl/build/lib/pkgconfig LDFLAGS="-Wl,-rpath,$PWD/../openssl/build/lib"
$ make -j$(nproc) check
$ openssl genrsa -out server.key 2048
$ openssl req -new -x509 -key server.key -out server.crt -days 3650
```

## 7.4. Client/Server
After successful build, the client and server executable should be
found under examples directory.

examples/client has ``-i`` option to read data from stdin, and send
them as STREAM data to server.  examples/server parses stream data as
HTTP/1.x request.

Both program have ``--tx-loss`` and ``--rx-loss`` to simulate packet
loss.

```
$ examples/client 127.0.0.1 4433 -i
t=0.000359 TX Client Initial(0x02) CID=0x737b2c1ecd75d64b PKN=139454351 V=0xff000005
            STREAM(0xc1) F=0x00 SS=0x00 OO=0x00 D=0x01
            stream_id=0x00000000 fin=0 offset=0 data_length=274
            PADDING(0x00)
            length=949
t=0.002420 RX Server Cleartext(0x04) CID=0xfdeb3167833b8859 PKN=2044202911 V=0xff000005
            ACK(0xa8) N=0x00 LL=0x02 MM=0x00
            num_blks=0 num_ts=0 largest_ack=139454351 ack_delay=1708
            first_ack_block_length=0; [139454351..139454351]
            STREAM(0xc1) F=0x00 SS=0x00 OO=0x00 D=0x01
            stream_id=0x00000000 fin=0 offset=0 data_length=1203
            ; TransportParameter received in EncryptedExtensions
            ; supported_version[0]=0xff000005
            ; initial_max_stream_data=262144
            ; initial_max_data=1024
            ; initial_max_stream_id=199
            ; idle_timeout=30
            ; omit_connection_id=0
            ; max_packet_size=65527
            ; stateless_reset_token=8ed8f8a7f38d83318fc9aeac43baf2ae
t=0.002913 RX Server Cleartext(0x04) CID=0xfdeb3167833b8859 PKN=2044202912 V=0xff000005
            STREAM(0xc3) F=0x00 SS=0x00 OO=0x01 D=0x01
            stream_id=0x00000000 fin=0 offset=1203 data_length=302
            ; Negotiated cipher suite is TLS13-AES-128-GCM-SHA256
            ; Negotiated ALPN is hq-05
t=0.003159 QUIC handshake has completed
Interactive session started.  Hit Ctrl-D to end the session.
The stream 1 has opened.
t=0.003235 TX Client Cleartext(0x05) CID=0xfdeb3167833b8859 PKN=139454352 V=0xff000005
            ACK(0xa8) N=0x00 LL=0x02 MM=0x00
            num_blks=0 num_ts=0 largest_ack=2044202912 ack_delay=323
            first_ack_block_length=1; [2044202912..2044202911]
            STREAM(0xc3) F=0x00 SS=0x00 OO=0x01 D=0x01
            stream_id=0x00000000 fin=0 offset=274 data_length=58
t=0.028792 RX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=2044202913
            ACK(0xa8) N=0x00 LL=0x02 MM=0x00
            num_blks=0 num_ts=0 largest_ack=139454352 ack_delay=25442
            first_ack_block_length=0; [139454352..139454352]
GET /helloworld
t=5.139039 TX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=139454353
            STREAM(0xc1) F=0x00 SS=0x00 OO=0x00 D=0x01
            stream_id=0x00000001 fin=0 offset=0 data_length=16
t=5.140105 RX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=2044202914
            STREAM(0xe1) F=0x01 SS=0x00 OO=0x00 D=0x01
            stream_id=0x00000001 fin=1 offset=0 data_length=177
            ordered STREAM data stream_id=0x00000001
00000000  3c 68 74 6d 6c 3e 3c 62  6f 64 79 3e 3c 68 31 3e  |<html><body><h1>|
00000010  49 74 20 77 6f 72 6b 73  21 3c 2f 68 31 3e 0a 3c  |It works!</h1>.<|
00000020  70 3e 54 68 69 73 20 69  73 20 74 68 65 20 64 65  |p>This is the de|
00000030  66 61 75 6c 74 20 77 65  62 20 70 61 67 65 20 66  |fault web page f|
00000040  6f 72 20 74 68 69 73 20  73 65 72 76 65 72 2e 3c  |or this server.<|
00000050  2f 70 3e 0a 3c 70 3e 54  68 65 20 77 65 62 20 73  |/p>.<p>The web s|
00000060  65 72 76 65 72 20 73 6f  66 74 77 61 72 65 20 69  |erver software i|
00000070  73 20 72 75 6e 6e 69 6e  67 20 62 75 74 20 6e 6f  |s running but no|
00000080  20 63 6f 6e 74 65 6e 74  20 68 61 73 20 62 65 65  | content has bee|
00000090  6e 20 61 64 64 65 64 2c  20 79 65 74 2e 3c 2f 70  |n added, yet.</p|
000000a0  3e 0a 3c 2f 62 6f 64 79  3e 3c 2f 68 74 6d 6c 3e  |>.</body></html>|
000000b0  0a                                                |.|
000000b1
t=5.165618 TX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=139454354
            ACK(0xa8) N=0x00 LL=0x02 MM=0x00
            num_blks=0 num_ts=0 largest_ack=2044202914 ack_delay=25490
            first_ack_block_length=1; [2044202914..2044202913]
t=5.165781 RX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=2044202915
            ACK(0xa8) N=0x00 LL=0x02 MM=0x00
            num_blks=0 num_ts=0 largest_ack=139454353 ack_delay=26023
            first_ack_block_length=0; [139454353..139454353]
t=5.166209 RX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=2044202916
            RST_STREAM(0x01)
            stream_id=0x00000001 error_code=NO_ERROR(0x80000000) final_offset=177
t=5.166325 TX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=139454355
            RST_STREAM(0x01)
            stream_id=0x00000001 error_code=QUIC_RECEIVED_RST(0x80000035) final_offset=16
t=5.191574 TX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=139454356
            ACK(0xa8) N=0x00 LL=0x02 MM=0x00
            num_blks=0 num_ts=0 largest_ack=2044202916 ack_delay=25359
            first_ack_block_length=1; [2044202916..2044202915]
t=5.191928 RX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=2044202917
            ACK(0xa8) N=0x00 LL=0x02 MM=0x00
            num_blks=0 num_ts=0 largest_ack=139454355 ack_delay=25257
            first_ack_block_length=1; [139454355..139454354]
t=35.220960 Timeout
t=35.221026 TX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=139454357
            CONNECTION_CLOSE(0x02)
            error_code=NO_ERROR(0x80000000) reason_length=0
```

```
$ examples/server 127.0.0.1 4433 server.key server.crt
t=8.165451 RX Client Initial(0x02) CID=0x737b2c1ecd75d64b PKN=139454351 V=0xff000005
            STREAM(0xc1) F=0x00 SS=0x00 OO=0x00 D=0x01
            stream_id=0x00000000 fin=0 offset=0 data_length=274
            ; TransportParameter received in ClientHello
            ; negotiated_version=0xff000005
            ; initial_version=0xff000005
            ; initial_max_stream_data=262144
            ; initial_max_data=1024
            ; initial_max_stream_id=0
            ; idle_timeout=30
            ; omit_connection_id=0
            ; max_packet_size=65527
            PADDING(0x00)
            length=949
t=8.167158 TX Server Cleartext(0x04) CID=0xfdeb3167833b8859 PKN=2044202911 V=0xff000005
            ACK(0xa8) N=0x00 LL=0x02 MM=0x00
            num_blks=0 num_ts=0 largest_ack=139454351 ack_delay=1708
            first_ack_block_length=0; [139454351..139454351]
            STREAM(0xc1) F=0x00 SS=0x00 OO=0x00 D=0x01
            stream_id=0x00000000 fin=0 offset=0 data_length=1203
t=8.167202 TX Server Cleartext(0x04) CID=0xfdeb3167833b8859 PKN=2044202912 V=0xff000005
            STREAM(0xc3) F=0x00 SS=0x00 OO=0x01 D=0x01
            stream_id=0x00000000 fin=0 offset=1203 data_length=302
t=8.168142 RX Client Cleartext(0x05) CID=0xfdeb3167833b8859 PKN=139454352 V=0xff000005
            ACK(0xa8) N=0x00 LL=0x02 MM=0x00
            num_blks=0 num_ts=0 largest_ack=2044202912 ack_delay=323
            first_ack_block_length=1; [2044202912..2044202911]
            STREAM(0xc3) F=0x00 SS=0x00 OO=0x01 D=0x01
            stream_id=0x00000000 fin=0 offset=274 data_length=58
            ; Negotiated cipher suite is TLS13-AES-128-GCM-SHA256
            ; Negotiated ALPN is hq-05
t=8.168343 QUIC handshake has completed
t=8.193589 TX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=2044202913
            ACK(0xa8) N=0x00 LL=0x02 MM=0x00
            num_blks=0 num_ts=0 largest_ack=139454352 ack_delay=25442
            first_ack_block_length=0; [139454352..139454352]
t=13.304143 RX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=139454353
            STREAM(0xc1) F=0x00 SS=0x00 OO=0x00 D=0x01
            stream_id=0x00000001 fin=0 offset=0 data_length=16
            ordered STREAM data stream_id=0x00000001
00000000  47 45 54 20 2f 68 65 6c  6c 6f 77 6f 72 6c 64 0a  |GET /helloworld.|
00000010
t=13.304766 TX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=2044202914
            STREAM(0xe1) F=0x01 SS=0x00 OO=0x00 D=0x01
            stream_id=0x00000001 fin=1 offset=0 data_length=177
t=13.330176 TX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=2044202915
            ACK(0xa8) N=0x00 LL=0x02 MM=0x00
            num_blks=0 num_ts=0 largest_ack=139454353 ack_delay=26023
            first_ack_block_length=0; [139454353..139454353]
t=13.330642 RX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=139454354
            ACK(0xa8) N=0x00 LL=0x02 MM=0x00
            num_blks=0 num_ts=0 largest_ack=2044202914 ack_delay=25490
            first_ack_block_length=1; [2044202914..2044202913]
t=13.330848 TX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=2044202916
            RST_STREAM(0x01)
            stream_id=0x00000001 error_code=NO_ERROR(0x80000000) final_offset=177
t=13.331299 RX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=139454355
            RST_STREAM(0x01)
            stream_id=0x00000001 error_code=QUIC_RECEIVED_RST(0x80000035) final_offset=16
t=13.356579 TX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=2044202917
            ACK(0xa8) N=0x00 LL=0x02 MM=0x00
            num_blks=0 num_ts=0 largest_ack=139454355 ack_delay=25257
            first_ack_block_length=1; [139454355..139454354]
t=13.356769 RX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=139454356
            ACK(0xa8) N=0x00 LL=0x02 MM=0x00
            num_blks=0 num_ts=0 largest_ack=2044202916 ack_delay=25359
            first_ack_block_length=1; [2044202916..2044202915]
t=43.386083 Timeout
t=43.386132 TX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=2044202918
            CONNECTION_CLOSE(0x02)
            error_code=NO_ERROR(0x80000000) reason_length=0
t=43.386317 Closing QUIC connection
```
