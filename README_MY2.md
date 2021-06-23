# 1. Aladdin
A behavior-aware CDN distribution system.
- [1. Aladdin](#1-aladdin)
- [2. motivation experiment](#2-motivation-experiment)
  - [2.1. HAR](#21-har)
  - [2.2. experiment setup](#22-experiment-setup)
  - [2.3. main experiment](#23-main-experiment)
- [3. Log Analysis](#3-log-analysis)
  - [3.1. server_data](#31-server_data)
  - [3.2. router_data](#32-router_data)
  - [3.3. client_data](#33-client_data)
- [4. RUN experiment](#4-run-experiment)
  - [4.1. server](#41-server)
    - [4.1.1. 启机子](#411-启机子)
      - [4.1.1.1. 数据传输](#4111-数据传输)
      - [4.1.1.2. 环境配置](#4112-环境配置)
    - [4.1.2. start experiment](#412-start-experiment)
  - [4.2. client](#42-client)
    - [4.2.1. client 启机子](#421-client-启机子)
    - [4.2.2. 数据传输](#422-数据传输)
    - [4.2.3. start exp](#423-start-exp)
    - [4.2.4. 监听iftop](#424-监听iftop)
  - [4.3. stop experiment - 在server测，但是影响所有的机子](#43-stop-experiment---在server测但是影响所有的机子)
  - [4.4. 传数据 - download to test instead of nds  - 在server测，但是影响所有的机子](#44-传数据---download-to-test-instead-of-nds----在server测但是影响所有的机子)
  - [4.5. re-limit wondershaper - 在server测，但是影响所有的机子](#45-re-limit-wondershaper---在server测但是影响所有的机子)
  - [MySQL](#mysql)
  - [Redis](#redis)
- [5. Code Log](#5-code-log)
  - [5.1. 环境配置 & 编译](#51-环境配置--编译)
    - [5.1.1. Requirements](#511-requirements)
    - [5.1.2. environment](#512-environment)
    - [5.1.3. mysql dev](#513-mysql-dev)
    - [5.1.4. openssl](#514-openssl)
    - [5.1.5. lexbor](#515-lexbor)
    - [5.1.6. ngtcp 编译](#516-ngtcp-编译)
    - [5.1.7. ngtcp client 和 server 直连](#517-ngtcp-client-和-server-直连)
  - [5.2. gcd deploy 配置](#52-gcd-deploy-配置)
    - [5.2.1. 配置Git](#521-配置git)
    - [5.2.2. 配置gcloud](#522-配置gcloud)
    - [5.2.3. vpc配置谷歌环境](#523-vpc配置谷歌环境)
    - [5.2.4. 配置master-salve](#524-配置master-salve)
    - [5.2.5. 配置语言环境](#525-配置语言环境)
  - [5.3. experiment deploy - Hestia](#53-experiment-deploy---hestia)
  - [5.4. 测量Google cloud 上 机子的BW，RTT和region的关系](#54-测量google-cloud-上-机子的bwrtt和region的关系)
  - [5.5. How to do the measurements](#55-how-to-do-the-measurements)
    - [5.5.1. 修改好配置后一键启动](#551-修改好配置后一键启动)
    - [5.5.2. step1  启动server机器](#552-step1--启动server机器)
    - [5.5.3. step2 在aws上启动client机器并运行实验](#553-step2-在aws上启动client机器并运行实验)
    - [5.5.4. step3 查看并存储数据](#554-step3-查看并存储数据)
      - [5.5.4.1. 查看数据](#5541-查看数据)
      - [5.5.4.2. 存储数据](#5542-存储数据)
    - [5.5.5. step4 删除机器](#555-step4-删除机器)
  - [5.6. motivation 实验部署](#56-motivation-实验部署)
    - [5.6.1. 修改实验配置](#561-修改实验配置)
    - [5.6.2. 跑实验](#562-跑实验)
    - [5.6.3. 看数据](#563-看数据)
    - [5.6.4. TODO](#564-todo)
  - [5.7. ngtcp2 master -- 支持late binding的版本](#57-ngtcp2-master----支持late-binding的版本)
  - [5.8. ngtcp2 loadbalancer --- balancer是负责数据包转发的proxy](#58-ngtcp2-loadbalancer-----balancer是负责数据包转发的proxy)
    - [5.8.1. 安装dev包、mysqlclient](#581-安装dev包mysqlclient)
    - [5.8.2. SSL_CTX_set_ciphersuites@OPENSSL_1_1_1 问题](#582-ssl_ctx_set_ciphersuitesopenssl_1_1_1-问题)
    - [5.8.3. 运行方法：](#583-运行方法)
  - [5.9. HTML applications](#59-html-applications)
    - [5.9.1. install ``lexbor`` library](#591-install-lexbor-library)
    - [5.9.2. add ``lexbor`` library](#592-add-lexbor-library)
    - [5.9.3. dynamic link error](#593-dynamic-link-error)
    - [5.9.4. get the inner element ``streams_`` in ``Client`` Class](#594-get-the-inner-element-streams_-in-client-class)
    - [5.9.5. 多网站测量](#595-多网站测量)
  - [5.10. DNS server](#510-dns-server)
    - [5.10.1. setting](#5101-setting)
    - [5.10.2. DNS server 上 安装BIND软件](#5102-dns-server-上-安装bind软件)
    - [5.10.3. options](#5103-options)
      - [5.10.3.1. sudo vim /etc/bind/named.conf.options](#51031-sudo-vim-etcbindnamedconfoptions)
      - [5.10.3.2. sudo named-checkconf](#51032-sudo-named-checkconf)
    - [5.10.4. 简易设置【只有domain->ip】](#5104-简易设置只有domain-ip)
      - [5.10.4.1. sudo vim /etc/bind/named.conf.local](#51041-sudo-vim-etcbindnamedconflocal)
      - [5.10.4.2. sudo mkdir /etc/bind/zones](#51042-sudo-mkdir-etcbindzones)
      - [5.10.4.3. sudo vim /etc/bind/zones/db.example.com](#51043-sudo-vim-etcbindzonesdbexamplecom)
      - [5.10.4.4. sudo named-checkzone example.com /etc/bind/zones/db.example.com](#51044-sudo-named-checkzone-examplecom-etcbindzonesdbexamplecom)
      - [5.10.4.5. sudo service bind9 restart](#51045-sudo-service-bind9-restart)
    - [5.10.5. 完整设置【包括ip->domain的设置】](#5105-完整设置包括ip-domain的设置)
      - [5.10.5.1. sudo vim /etc/bind/named.conf.local](#51051-sudo-vim-etcbindnamedconflocal)
      - [5.10.5.2. sudo mkdir /etc/bind/zones](#51052-sudo-mkdir-etcbindzones)
      - [5.10.5.3. sudo vim /etc/bind/zones/db.example.com](#51053-sudo-vim-etcbindzonesdbexamplecom)
      - [5.10.5.4. sudo named-checkzone example.com /etc/bind/zones/db.example.com](#51054-sudo-named-checkzone-examplecom-etcbindzonesdbexamplecom)
      - [5.10.5.5. sudo vim /etc/bind/zones/db.34.78.171](#51055-sudo-vim-etcbindzonesdb3478171)
      - [5.10.5.6. sudo vim /etc/bind/zones/db.35.226.154](#51056-sudo-vim-etcbindzonesdb35226154)
      - [5.10.5.7. sudo vim /etc/bind/zones/db.34.96.176](#51057-sudo-vim-etcbindzonesdb3496176)
      - [5.10.5.8. sudo named-checkzone 171.78.34.in-addr.arpa /etc/bind/zones/db.34.78.171](#51058-sudo-named-checkzone-1717834in-addrarpa-etcbindzonesdb3478171)
      - [5.10.5.9. sudo named-checkzone 154.226.35.in-addr.arpa /etc/bind/zones/db.35.226.154](#51059-sudo-named-checkzone-15422635in-addrarpa-etcbindzonesdb35226154)
      - [5.10.5.10. sudo named-checkzone 176.96.34.in-addr.arpa /etc/bind/zones/db.34.96.176](#510510-sudo-named-checkzone-1769634in-addrarpa-etcbindzonesdb3496176)
      - [5.10.5.11. sudo service bind9 restart](#510511-sudo-service-bind9-restart)
    - [5.10.6. 去另一台机子test[34.96.176.62]上进行配置](#5106-去另一台机子test349617662上进行配置)
      - [5.10.6.1. sudo vim /etc/resolvconf/resolv.conf.d/head](#51061-sudo-vim-etcresolvconfresolvconfdhead)
      - [5.10.6.2. sudo resolvconf -u](#51062-sudo-resolvconf--u)
      - [5.10.6.3. sudo vim /etc/resolv.conf](#51063-sudo-vim-etcresolvconf)
  - [5.11. 进行测试](#511-进行测试)
- [6. 对QUIC的介绍](#6-对quic的介绍)

# 2. motivation experiment
## 2.1. HAR
- 三台机子，每台机子只是固定的提供
## 2.2. experiment setup
- 三种集群，分别选择多种规格的资源
  - 带宽资源：1M，10M，100M，其他资源不变
  - RTT：25ms，50ms，100ms，300ms，其他资源不变
  - CPU资源：2核，4核，8核，其他资源不变
- 将我们三种浏览行为分别在上述三种集群进行相同的重放实验。
- 发现三种浏览行为对于三种资源的有着不同的敏感度。
  - browsing行为下的PLT随着RTT的增加而快速增加，而随着另外两种bandwidth和CPU的资源的增加，PLT并没有变化的很大。
  - downloading行为下的PLT随着bandwidth的增加而快速增加，而随着另外两种RTT和CPU的资源的增加，PLT并没有变化的很大。
  - computing行为下的PLT随着CPU的增加而快速增加，而随着另外两种bandwidth和RTT的资源的增加，PLT并没有变化的很大。


## 2.3. main experiment 
- baseline
  - 用Google的load balancing随机部署
  - 用Tencent的CDN技术
  - 用router进行random选择
- Aladdin
  - 一个extra指派资源标识的model
  - 每次请求给一个业务/行为标识
  - 再让这个connection根据这个标识进行CDN选择


# 3. Log Analysis
## 3.1. server_data
下属文件夹按照gcloud中的名称而来
<!-- server_$port.log: 基本没啥用，主要可以看cpu跑了多少次，然后写到了哪个文件夹里 -->
<!-- server_tmp_$port.log: 暂时没用 -->
<!-- iftop_log.txt: iftop的结果 -->

- traffic.log：记录启动机器后的流量
- cpu.log： 记录启动机器后的cpu
- experiment_results/ : 记录某个查询的cpu查询起始时间和终止时间，可以用来算最后的用户响应时间
  - **注意**
  - client的ip和server，router有点不同。client的是正常的ip，server和balancer的非首位会补满3位。
  - 例如：
  - client:192.168.23.45
  - server, router: 192.168.023.045


## 3.2. router_data
<!-- balancer_tmp_$port.log: 暂时没用 -->
- balancer_$port.log: balancer的选择结果
  ```
  Executing sql all costs 5.31872 milliseconds.
  Logs mysql optimal and suboptimal costs0.149472 milliseconds.
  user requires rtt_sensitive! # 用户选择某个资源敏感
  =====latency optimized routing and forwarding selecting START=====
  request rtt_sensitive
  count_latencies: 0 # count_* 0表示最优，1表示冗余发包，这个demo暂时没有加冗余逻辑
  Forwarded to server: server
  =====latency optimized routing and forwarding selecting END=====
  Packet forwarding costs 8.38253 milliseconds.
  ```


- experiment_results：
  ```
  latencies-0 usus-wet2, 50 # 最优
  latencies-1 eupe-wet1, 100 # 次优
  cpus-0 usus-wet2, 20.3
  cpus-1 eupe-wet1, 10.6
  throughputs-0 usus-wet2, 1.0685
  throughputs-1 eupe-wet1, 1.4015

  request rtt_sensitive
  The current dc is the best, choose server to forward. usus-wet2, 50 # 选择了哪个
  ```
  - **注意**
  - client的ip和server，router有点不同。client的是正常的ip，server和balancer的非首位会补满3位。
  - 例如：
  - client:192.168.23.45
  - server, router: 192.168.023.045



## 3.3. client_data
<!-- client_tmp_$port.log: 暂时没用 -->
- experiment_results/
  ```
  35.205.24.138 # anycast选择的balancer的ip
  website: downloading24 # 具体网页
  website_root_path: video # 类型
  website_www_opt: 1

  ***
  handshake time: 61901 # 握手时间

  ***
  PLT: 112477 microseconds
  PLT: 2692927 microseconds 
  PLT: 4008139 microseconds # 传输时间，每次请求单独算，最后一个数值即是结果（记录的是累加时间）
  ```


# 4. RUN experiment
## 4.1. server
### 4.1.1. 启机子
#### 4.1.1.1. 数据传输
perpare_data()
内容在%s/ngtcp2/XXX
在gcloud下的data

#### 4.1.1.2. 环境配置
**!!!!!!!PS: 需要把Hestia/machine.json手动的从server传到所有的clients' test**

### 4.1.2. start experiment
-m Hestia/experiment/gcloud/restart.py



## 4.2. client
### 4.2.1. client 启机子
-m Hestia/experiment/client/machines/gcp/start.py
- Hestia/experiment/client/data/hosts.json  
    ！！！！！PS: clients’ test 到 servers' test 的 /home/gtc

### 4.2.2. 数据传输
在client下的data

### 4.2.3. start exp
需要改动 - Hestia/experiment/client/data/start_wrapper.sh中的tmux send-key -t main:0 "${root}/start_polygon.sh" Enter，的polygon
-m Hestia/experiment/client/main.py 

### 4.2.4. 监听iftop
/home/gtc/Hestia/experiment/client/data/get_active_port.py




## 4.3. stop experiment - 在server测，但是影响所有的机子
python Hestia/scripts/kill_all.py




## 4.4. 传数据 - download to test instead of nds  - 在server测，但是影响所有的机子
python Hestia/scripts/fetch_data.py




## 4.5. re-limit wondershaper - 在server测，但是影响所有的机子
python Hestia/scripts/reset_wondershaper.py



## MySQL
mysql -u johnson --password=johnson serviceid_db -e "select * from measurements"



## Redis
redis-cli -h 127.0.0.1 -a "Hestia123456"



# 5. Code Log
## 5.1. 环境配置 & 编译
We are focusing on implementing [Second Implementation Draft](<https://github.com/quicwg/base-drafts/wiki/Second-Implementation-Draft>)

* https://quicwg.github.io/base-drafts/draft-ietf-quic-transport.html
* https://quicwg.github.io/base-drafts/draft-ietf-quic-tls.html

### 5.1.1. Requirements
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


### 5.1.2. environment
sudo apt install git tmux autoconf libtool pkg-config libev-dev  mysql-client mysql-server gcc g++ jq -y
sh -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"
sudo usermod -s /bin/zsh <username>
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
sudo apt-get install -y python3-distutils
sudo python3 get-pip.py
sudo pip3 config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple


### 5.1.3. mysql dev
sudo apt install libmysql++3v5 -y
wget http://launchpadlibrarian.net/355857431/libmysqlclient20_5.7.21-1ubuntu1_amd64.deb
sudo apt install ./libmysqlclient20_5.7.21-1ubuntu1_amd64.deb -y
wget http://launchpadlibrarian.net/355857415/libmysqlclient-dev_5.7.21-1ubuntu1_amd64.deb
sudo apt install ./libmysqlclient-dev_5.7.21-1ubuntu1_amd64.deb - y


### 5.1.4. openssl
git clone --depth 1 -b quic https://github.com/tatsuhiro-t/openssl
cd openssl
./config enable-tls1_3 --prefix=$PWD/build
make -j$(nproc)
make install_sw


### 5.1.5. lexbor
curl -O https://lexbor.com/keys/lexbor_signing.key
sudo apt-key add lexbor_signing.key
sudo touch /etc/apt/sources.list.d/lexbor.list
sudo echo "deb https://packages.lexbor.com/ubuntu/ bionic liblexbor" >> /etc/apt/sources.list.d/lexbor.list #可能需要手动写入
sudo echo "deb-src https://packages.lexbor.com/ubuntu/ bionic liblexbor" >> /etc/apt/sources.list.d/lexbor.list #可能需要手动写入
sudo apt update
sudo apt install liblexbor -y
sudo apt install liblexbor-dev -y


### 5.1.6. ngtcp 编译
cd ngtcp2
autoreconf -i
<!-- For Mac users who have installed libev with MacPorts, append
',-L/opt/local/lib' to LDFLAGS, and also pass
CPPFLAGS="-I/opt/local/include" to ./configure. -->
./configure PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/:$PWD/../openssl/build/lib/pkgconfig LDFLAGS="-Wl,-rpath,$PWD/../openssl/build/lib -llexbor"
make -j$(nproc) check
openssl genrsa -out server.key 2048
openssl req -new -x509 -key server.key -out server.crt -days 3650


### 5.1.7. ngtcp client 和 server 直连
examples/server 127.0.0.1 4433 server.key server.crt
examples/client 127.0.0.1 4433 -i -w <abc.com> -q





## 5.2. gcd deploy 配置
### 5.2.1. 配置Git
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
scp -r .ssh <username>@test_ip:/home/username

### 5.2.2. 配置gcloud
sudo apt-get install -y python3.7-dev jq
pip install paramiko gcloud

安装gcloud sdk: https://cloud.google.com/sdk/docs/install#linux
tar -zxvf google-cloud-sdk-319.0.0-linux-x86_64.tar.gz
	（project id看project-settings.json）
身份认证: https://cloud.google.com/docs/authentication/getting-started#cloud-console
	（认证用默认账号）
	（认证后，将json文件上传到服务器的~/keys/key.json）
gcloud projects add-iam-policy-binding <project_id> --member="serviceAccount:114286380919-compute@developer.gserviceaccount.com" --role="roles/owner"
export GOOGLE_APPLICATION_CREDENTIALS="/home/gtc/keys/key.json"

gcloud auth login
gcloud beta compute forwarding-rules create load-balancer-ipv4-forwarding-rule --global --target-tcp-proxy load-balancer-target-proxy
	(可以不管报错，只要按Y确认后，下载安装完就行，后面会有脚本具体执行)


### 5.2.3. vpc配置谷歌环境
<!-- 一个project只需要配置一次 -->
cd ~/Hestia/
./vpc.sh
```
    #!/bin/bash
    project_id=`jq -r .PROJECT_ID ~/Hestia/project-settings.json`
    gcloud compute --project=$project_id networks create default2 --subnet-mode=custom
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=asia-east1 --range=10.28.0.0/20
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=asia-east2 --range=10.32.0.0/20
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=northamerica-northeast1 --range=10.38.0.0/20
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=southamerica-east1 --range=10.40.0.0/20
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=us-central1 --range=10.42.0.0/20
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=us-east1 --range=10.46.0.0/20
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=us-east4 --range=10.48.0.0/20
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=us-west1 --range=10.50.0.0/20
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=us-west2 --range=10.52.0.0/20
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=europe-north1 --range=10.54.0.0/20
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=europe-west1 --range=10.56.0.0/20
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=europe-west2 --range=10.58.0.0/20
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=europe-west3 --range=10.60.0.0/20
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=europe-west4 --range=10.62.0.0/20
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=europe-west6 --range=10.64.0.0/20
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=asia-northeast1 --range=10.66.0.0/20
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=asia-northeast2 --range=10.68.0.0/20
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=asia-south1 --range=10.70.0.0/20
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=asia-southeast1 --range=10.72.0.0/20
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=australia-southeast1 --range=10.74.0.0/20
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=asia-northeast3 --range=10.78.0.0/20
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=us-west3 --range=10.80.0.0/20
    gcloud compute --project=$project_id networks subnets create default2 --network=default2 --region=us-west4 --range=10.82.0.0/20
```
VPC内容说明：
在gcloud主界面设置防火墙
	侧边栏——VPC网络——防火墙
	添加“mysql 入站 应用到所有实例	 IP 地址范围: 0.0.0.0/0 tcp:3306 允许 1000” 
	添加"a4433" 入站 应用到所有实例	 IP 地址范围: 0.0.0.0/0 tcp:4433 udp:4433 允许 1000” 
	添加"b4433" 出站 应用到所有实例	 IP 地址范围: 0.0.0.0/0 tcp:4433 udp:4433 允许 1000” 
	添加"a8833" 入站 应用到所有实例	 IP 地址范围: 0.0.0.0/0 tcp:8833 udp:8833 允许 1000” 
	添加"b8833" 出站 应用到所有实例	 IP 地址范围: 0.0.0.0/0 tcp:8833 udp:8833 允许 1000” 
	添加"a6379" 入站 应用到所有实例	 IP 地址范围: 0.0.0.0/0 tcp:6379 udp:6379 允许 1000” 
	添加"b6379" 出站 应用到所有实例	 IP 地址范围: 0.0.0.0/0 tcp:6379 udp:6379 允许 1000” 
  添加"a13989" 入站 应用到所有实例	 IP 地址范围: 0.0.0.0/0 tcp:13989 udp:13989 允许 1000” 
	添加"b13989" 出站 应用到所有实例	 IP 地址范围: 0.0.0.0/0 tcp:13989 udp:13989 允许 1000” 
	添加"a-iperf3" 入站 应用到所有实例	 IP 地址范围: 0.0.0.0/0 tcp:5200-5209 udp:5200-5209 允许 1000” 
	添加"b-iperf3" 出站 应用到所有实例	 IP 地址范围: 0.0.0.0/0 tcp:5200-5209 udp:5200-5209 允许 1000” 
	添加"a27017" 入站 应用到所有实例	 IP 地址范围: 0.0.0.0/0 tcp:27017 udp:27017 允许 1000” 
	添加"b27017" 出站 应用到所有实例	 IP 地址范围: 0.0.0.0/0 tcp:27017 udp:27017 允许 1000” 
	添加"a22" 入站 应用到所有实例	 IP 地址范围: 0.0.0.0/0 tcp:22 udp:22 允许 1000” 
	添加"b22" 出站 应用到所有实例	 IP 地址范围: 0.0.0.0/0 tcp:22 udp:22 允许 1000” 



### 5.2.4. 配置master-salve
sudo apt install libev-dev  mysql-client libmysql++-dev mysql-server gcc vim -y
pip install -r ~/Hestia/requirements.txt
在/etc/mysql/my.cnf中添加(sudo vim /etc/mysql/my.cnf)
  [mysqld]
  log-bin=mysql-bin
  server-id=2
	(这个2可以改成test机器ip地址的最后一位)
sudo vim /etc/mysql/mysql.conf.d/mysqld.cnf
  将 bind-address = 0.0.0.0 或者 bind-address = 127.0.0.1 注释
  将log_bin和server-id所在行，分别取消注释
  (不同test机器中，该文件所在位置不同)

sudo service mysql restart
sudo mysql
	GRANT replication slave ON *.* TO 'slave'@'%' IDENTIFIED BY '123456';  


### 5.2.5. 配置语言环境
echo "export LC_ALL=C" >> ~/.zshrc 
source ~/.zshrc



## 5.3. experiment deploy - Hestia
``` bash
# 在test上
cd /home/johnsonli1993/Hestia
# 先删除experiment.gcloud.main.py文件中的最后几条预设值的sql语句
# 这是启动机子并进行相关的配置，配置内容包括复制程序、配置数据库。
# 配置内容包括复制server，balancer到/home/wch19990119/data下，并且根据服务器的名字自动启动对应的server/balancer。
# data.zip 中的文件来自于/home/johnsonli1993/Hestia/experiment/gcloud/data文件夹进行压缩
python -m experiment.gcloud.main
sleep 120
python -m experiment.gcloud.restart
python -m experiment.client.machines.gcp.start
sleep 60
python -m experiment.client.main
```




## 5.4. 测量Google cloud 上 机子的BW，RTT和region的关系




## 5.5. How to do the measurements
work_path: /home/ubuntu/gtc/Hestia
### 5.5.1. 修改好配置后一键启动
./run_experiment.sh

### 5.5.2. step1  启动server机器
vim experiment/gcloud/main.py # (修改机器数量)
vim experiment/gcloud/config.py # (修改zones，确认测试的地点)

rm -r experiment/gcloud/data/websites
rm -r experiment/gcloud/data/tcp
rm -r experiment/gcloud/data/.ssh
python -m experiment.gcloud.main
python -m experiment.gcloud.restart # (等步骤二完成2分钟后)

### 5.5.3. step2 在aws上启动client机器并运行实验
vim experiment/aws/utils.py # (配置机器数量和位置)
1. python -m experiment.client.machines.aws.start
2. rm -r experiment/client/data/websites
3. python -m experiment.client.main # (等步骤二完成2分钟后)

### 5.5.4. step3 查看并存储数据

#### 5.5.4.1. 查看数据
1. mysql -ujohnson -pjohnson
2. use serviceid_db;
3. select * from transfer_time; # (当数据库中有client数量*5条数据时，整个测量代码运行结束)

#### 5.5.4.2. 存储数据
文件名自取
1. mysql -u johnson --password=johnson serviceid_db -e "select * from measurements" > ~/export_data/measurements_0714_europe_multiplt_unredundant.csv
2. mysql -u johnson --password=johnson serviceid_db -e "select * from transfer_time" > ~/export_data/transfer_time_0714_europe_multiplt_unredundant.csv
3. cp machine.json ~/export_data/machine_0714_europe_multiplt_unredundant.json

### 5.5.5. step4 删除机器
1. python -m experiment.client.machines.aws.cleanup
2. 在google cloud网页版上删除除了test之外的所有机器


## 5.6. motivation 实验部署
### 5.6.1. 修改实验配置
~/Hestia/motivation/scripts/motivation-settings.json修改DATA_TYPE，即文件数据类型
~/Hesita/experiment/gcloud/config.py修改ZONES，即机器启动的区域
~/Hesita/experiment/gcloud/main.py修改ZONE_NUMBERS，即机器启动的台数
 
### 5.6.2. 跑实验
cd ~/Hestia/
./run_motivation.sh
    start_time=$(date "+%Y%m%d%H%M%S")
    mkdir ~/Hestia/motivation/data/$start_time
    jq '.FILE_TIMESTAMP= '$start_time' '  ~/Hestia/motivation/scripts/motivation-settings.json > tmp.$$.json && mv tmp.$$.json ~/Hestia/motivation/scripts/motivation-settings.json
    echo $start_time

    python -m experiment.gcloud.main
    sleep 120
    python -m experiment.gcloud.restart
    python -m experiment.client.machines.gcp.start
    sleep 60
    python -m experiment.client.main
    sleep 60
    python -m experiment.motivation.main


### 5.6.3. 看数据
实验结束后，数据在~/Hestia/motivation/data/，时间最后的一个时间戳里
使用～/Hestia/experiment/motivation/analysis.py 导出数据分析得到的pandas形式的table。（这里默认使用最后一次实验的数据，可以修改变量Default_file_timestamp来选择某次实验数据）

### 5.6.4. TODO
每次实验记录的总体秒数，之后会写成一个脚本参数，现在是100s
 




## 5.7. ngtcp2 master -- 支持late binding的版本
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


## 5.8. ngtcp2 loadbalancer --- balancer是负责数据包转发的proxy
### 5.8.1. 安装dev包、mysqlclient
- sudo apt install libev-dev  mysql-client libmysql++-dev mysql-server -y

### 5.8.2. SSL_CTX_set_ciphersuites@OPENSSL_1_1_1 问题
- 把libmysqlclient-dev的版本降一下
  - sudo apt install libmysqlclient-dev=5.7.21-1ubuntu1
- 若有用apt安装发现有冲突，可以手动安装
    ```vim
    sudo apt install libmysql++3v5
    wget http://launchpadlibrarian.net/355857431/libmysqlclient20_5.7.21-1ubuntu1_amd64.deb
    sudo apt install ./libmysqlclient20_5.7.21-1ubuntu1_amd64.deb
    wget http://launchpadlibrarian.net/355857415/libmysqlclient-dev_5.7.21-1ubuntu1_amd64.deb
    sudo apt install ./libmysqlclient-dev_5.7.21-1ubuntu1_amd64.deb
    ```

### 5.8.3. 运行方法：
> Client：
- start-client.sh
- sudo ./examples/client <本机外网ip> 4433 

> server：
- start_server.sh
- sudo ./examples/server 0.0.0.0 4433 --interface eth0 --unicast <本机外网ip> server.key server.crt

> balancer
- start-balancer.sh
- sudo ./examples/balancer --datacenter test --user johnson --password johnson eth0 0.0.0.0 4433 ~/keys/server.key ~/keys/server.crt
- 本地dc名称：--datacenter <本机绑定的local datecenter名字>
- 数据库用户名 --user johnson
- 数据库密码 --password johnson



##  5.9. HTML applications
### 5.9.1. install ``lexbor`` library 
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

### 5.9.2. add ``lexbor`` library
- in configure running:
  - ./configure PKG_CONFIG_PATH=$PWD/../../openssl/build/lib/pkgconfig LDFLAGS="-Wl,-rpath,$PWD/../../openssl/build/lib -llexbor" --host=arm
  - ./configure PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/:$PWD/../openssl/build/lib/pkgconfig LDFLAGS="-Wl,-rpath,$PWD/../openssl/build/lib -llexbor" --host=arm
  - this means you need add ``llexbor`` and ``--host=arm``

### 5.9.3. dynamic link error 
- echo $LD_LIBRARY_PATH
- LD_LIBRARY_PATH=/usr/local/lib
- export LD_LIBRARY_PATH

### 5.9.4. get the inner element ``streams_`` in ``Client`` Class
- 通过增加了一个messages的全局变量数组，数据类型是message
- message struct 主要包括了client类中的conn_, streams_, 还有HTML的content信息。
- message中有一个``message_complete_cb_called``，用来控制收到data是否需要http解析

### 5.9.5. 多网站测量
> 相关配置
- 在ngtcp目录下增加index.csv，每一行是一个网站（eg: google.com）
- 在ngtcp目录下增加websites，其中放有har文件解析后的文件
> 脚本执行测试
./evaluate_top.sh


## 5.10. DNS server
### 5.10.1. setting
- 一台DNS server，外部ip是 34.78.171.37，内部ip是10.132.0.3，域名为dns.example.com
- 一台需要进行DNS查询的主机，外部IP是34.96.176.62，域名为client.example.com
- 其他的域名和主机均为假设
  - server1.example.com: 34.78.171.6
  - server2.example.com: 35.226.154.232

### 5.10.2. DNS server 上 安装BIND软件
sudo apt-get install bind9 bind9utils bind9-doc resolvconf -y

### 5.10.3. options
#### 5.10.3.1. sudo vim /etc/bind/named.conf.options
``` vim
acl "trusted" {
    10.132.0.3;
    34.78.171.37;
    34.96.176.62;
};
options {
        directory "/var/cache/bind";

        recursion no;
        // allow-recursion {
        //    trusted;
        // };
        // DNS server 的内部IP用来监听给其他client提供服务
        listen-on {10.132.0.3;};
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
#### 5.10.3.2. sudo named-checkconf

### 5.10.4. 简易设置【只有domain->ip】
#### 5.10.4.1. sudo vim /etc/bind/named.conf.local 
``` vim
zone "example.com" {
    type master;
    file "/etc/bind/zones/db.example.com";
};
```
#### 5.10.4.2. sudo mkdir /etc/bind/zones

#### 5.10.4.3. sudo vim /etc/bind/zones/db.example.com
``` vim
;
; BIND data file for local loopback interface
$TTL    604800
@       IN      SOA     dns.example.com. admin.example.com. (
          2         ; Serial
     604800         ; Refresh
      86400         ; Retry
    2419200         ; Expire
     604800 )       ; Negative Cache TTL
;
;
; name servers - NS records
     IN      NS      dns.example.com.
; name servers - A records
dns.example.com.          IN      A       34.78.171.37

server1.example.com.      IN      A       34.78.171.6

server2.example.com.      IN      A       35.226.154.232

client.example.com.        IN      A      34.96.176.62
```
#### 5.10.4.4. sudo named-checkzone example.com /etc/bind/zones/db.example.com
#### 5.10.4.5. sudo service bind9 restart


### 5.10.5. 完整设置【包括ip->domain的设置】
#### 5.10.5.1. sudo vim /etc/bind/named.conf.local 
``` vim
zone "example.com" {
    type master;
    file "/etc/bind/zones/db.example.com";
};

// DNS server 以及 server 1
zone "171.78.34.in-addr.arpa" {
    type master;
    file "/etc/bind/zones/db.34.78.171";
};

// server 2
zone "154.226.35.in-addr.arpa" {
    type master;
    file "/etc/bind/zones/db.35.226.154";
};

// client
zone "176.96.34.in-addr.arpa" {
    type master;
    file "/etc/bind/zones/db.34.96.176";
};
```
#### 5.10.5.2. sudo mkdir /etc/bind/zones

#### 5.10.5.3. sudo vim /etc/bind/zones/db.example.com
``` vim
;
; BIND data file for local loopback interface
$TTL    604800
@       IN      SOA     dns.example.com. admin.example.com. (
          2         ; Serial
     604800         ; Refresh
      86400         ; Retry
    2419200         ; Expire
     604800 )       ; Negative Cache TTL
;
;
; name servers - NS records
     IN      NS      dns.example.com.
; name servers - A records
dns.example.com.          IN      A       34.78.171.37

server1.example.com.      IN      A       34.78.171.6

server2.example.com.      IN      A       35.226.154.232

client.example.com.        IN      A      34.96.176.62
```
#### 5.10.5.4. sudo named-checkzone example.com /etc/bind/zones/db.example.com

#### 5.10.5.5. sudo vim /etc/bind/zones/db.34.78.171
``` vim
$TTL    604800
@       IN      SOA     example.com. admin.example.com. (
          1         ; Serial
     604800         ; Refresh
      86400         ; Retry
    2419200         ; Expire
     604800 )       ; Negative Cache TTL
; name servers
      IN      NS      nds.example.com.

; PTR Records
37   IN      PTR     nds.example.com.  ; 这一行的第一个数字对应10.128.0.8中的8
6   IN      PTR     server1.example.com.
```

#### 5.10.5.6. sudo vim /etc/bind/zones/db.35.226.154
``` vim
$TTL    604800
@       IN      SOA     example.com. admin.example.com. (
          1         ; Serial
     604800         ; Refresh
      86400         ; Retry
    2419200         ; Expire
     604800 )       ; Negative Cache TTL
; name servers
      IN      NS      dns.example.com.

; PTR Records
232   IN      PTR     server2.example.com.  ; 这一行的第一个数字对应10.128.0.8中的8
```

#### 5.10.5.7. sudo vim /etc/bind/zones/db.34.96.176
``` vim
$TTL    604800
@       IN      SOA     example.com. admin.example.com. (
          1         ; Serial
     604800         ; Refresh
      86400         ; Retry
    2419200         ; Expire
     604800 )       ; Negative Cache TTL
; name servers
      IN      NS      dns.example.com.

; PTR Records
62   IN      PTR     client.example.com.  ; 这一行的第一个数字对应10.128.0.8中的8
```

#### 5.10.5.8. sudo named-checkzone 171.78.34.in-addr.arpa /etc/bind/zones/db.34.78.171
#### 5.10.5.9. sudo named-checkzone 154.226.35.in-addr.arpa /etc/bind/zones/db.35.226.154
#### 5.10.5.10. sudo named-checkzone 176.96.34.in-addr.arpa /etc/bind/zones/db.34.96.176
#### 5.10.5.11. sudo service bind9 restart


### 5.10.6. 去另一台机子test[34.96.176.62]上进行配置
sudo apt-get install resolvconf -y
#### 5.10.6.1. sudo vim /etc/resolvconf/resolv.conf.d/head
``` vim
nameserver 10.140.0.2
```
#### 5.10.6.2. sudo resolvconf -u
#### 5.10.6.3. sudo vim /etc/resolv.conf
进行检查

## 5.11. 进行测试
```shell
nslookup 
dns.example.com 
10.140.0.2

client.example.com 
34.96.176.62

server1.example.com
34.78.171.6 

server2.example.com 
35.226.154.232
```


# 6. 对QUIC的介绍
[QUIC协议介绍](QUIC.md)