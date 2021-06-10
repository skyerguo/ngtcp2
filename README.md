- [1. ngtcp2 安装](#1-ngtcp2-安装)
  - [1.1. 分支说明](#11-分支说明)
    - [1.1.1. master](#111-master)
    - [1.1.2. motivation](#112-motivation)
    - [1.1.3. resource_demand](#113-resource_demand)
  - [1.2. 安装说明](#12-安装说明)
    - [1.2.1. 安装需要的包](#121-安装需要的包)
    - [1.2.2. 配置openssl](#122-配置openssl)
    - [1.2.3. 降低libmysqlclient-dev版本](#123-降低libmysqlclient-dev版本)
    - [1.2.4. 配置ngtcp2](#124-配置ngtcp2)
- [2. 运行说明](#2-运行说明)
  - [2.1. 单机器测试](#21-单机器测试)
  - [2.2. 云服务器多机器使用](#22-云服务器多机器使用)
- [3. 关键代码说明](#3-关键代码说明)
  - [3.1. metadata](#31-metadata)
  - [3.2. client](#32-client)
  - [3.3. balancer](#33-balancer)
  - [3.4. server](#34-server)
- [4. 传输文件说明](#4-传输文件说明)
  - [4.1. websites](#41-websites)
  - [4.2. websites2](#42-websites2)

# 1. ngtcp2 安装
## 1.1. 分支说明
### 1.1.1. master
- 这是一个早期版本，从学兵的分支获得的，没有metadata的版本

### 1.1.2. motivation

- 用于进行motivation实验的版本

- 进行motivation实验时，需要一些额外的手动配置

  

### 1.1.3. resource_demand

- 主要版本，有resource_demand需求
- 目前提供了cpu_sensitive, throughput_sensitive, latency_sensitive 三种{0,1}的资源权重



```
$ cd ~
$ git clone git@github.com:skyerguo/ngtcp2.git
$ cd ngtcp2
$ git checkout -b resource_demand
```



## 1.2. 安装说明 

### 1.2.1. 安装需要的包

```
$ sudo apt-get install -yqq pkg-config autoconf automake autotools-dev libtool libev-dev gdb zip unzip libcunit1 libcunit1-doc libcunit1-dev sshpass
$ cd ~
$ curl -O https://lexbor.com/keys/lexbor_signing.key
$ sudo apt-key add lexbor_signing.key
$ sudo chown gtc /etc/apt/sources.list.d/ -R
$ sudo chgrp gtc /etc/apt/sources.list.d/ -R
$ echo "deb https://packages.lexbor.com/ubuntu/ bionic liblexbor" > /etc/apt/sources.list.d/lexbor.list
$ echo "deb-src https://packages.lexbor.com/ubuntu/ bionic liblexbor" >> /etc/apt/sources.list.d/lexbor.list
$ sudo apt-get update
$ sudo apt-get install -yqq liblexbor liblexbor-dev
```



### 1.2.2. 配置openssl

 ```
$ cd ~/
$ git clone --depth 1 -b quic https://github.com/tatsuhiro-t/openssl
$ cd openssl
$ ./config enable-tls1_3 --prefix=$PWD/build
$ make -j$(nproc) && make install_sw
 ```



### 1.2.3. 降低libmysqlclient-dev版本

```
# 运行中出现“/usr/lib/gcc/x86_64-linux-gnu/7/../../../x86_64-linux-gnu/libmysqlclient.so: undefined reference to `SSL_CTX_set_ciphersuites@OPENSSL_1_1_1'”问题，也运行该部分，可以不需要wget
$ cd ~/
$ sudo apt install -y libmysql++3v5
$ wget http://launchpadlibrarian.net/355857431/libmysqlclient20_5.7.21-1ubuntu1_amd64.deb
$ sudo apt install -yqq --allow-downgrades ./libmysqlclient20_5.7.21-1ubuntu1_amd64.deb
$ sudo apt-mark hold libmysqlclient20
$ wget http://launchpadlibrarian.net/355857415/libmysqlclient-dev_5.7.21-1ubuntu1_amd64.deb
$ sudo apt install -yqq --allow-downgrades ./libmysqlclient-dev_5.7.21-1ubuntu1_amd64.deb
$ sudo apt-mark hold libmysqlclient-dev
```



### 1.2.4. 配置ngtcp2

```
$ cd ~/ngtcp2
$ sed -i 's/mysqlclient >= 5.7.23/mysqlclient >= 5.6.47/g' configure.ac
$ autoreconf -i
$ ./configure.sh && make
```



# 2. 运行说明
## 2.1. 单机器测试

```
$ cd ~/ngtcp2
$ openssl genrsa -out server.key 2048
$ openssl req -new -x509 -key server.key -out server.crt -days 3650
在tmux三个终端，按顺序分别启动（注意修改一些ip地址）
	$ ./start_server.sh
	$ ./start_balancer.sh
	$ ./start_client.sh
```



## 2.2. 云服务器多机器使用

- 假设三台机器，分别是A、B、C。A是client，B是dispatcher，C是server。
- A

```
sudo timeout 430 sudo LD_LIBRARY_PATH=${root} ${root}/client ${target} 4433 -i -p normal_1 -o 0 -w google.com --client_ip 123.123.123.123 --client_process 4433 --time_stamp 123456789 -q 

{root}表示有websites的根目录
{target}为balancer的ip
```

- B

```
sudo LD_LIBRARY_PATH=~/data ~/data/balancer --datacenter ${zone} --user johnson --password johnson bridge 0.0.0.0 4433 ~/data/server.key ~/data/server.crt -q

{zone}为地区的四个字符的缩写，表示本机绑定的local datecenter名字。

数据库用户名 --user johnson
数据库密码 --password johnson
```

- C

```
sudo LD_LIBRARY_PATH=~/data ~/data/server --interface=ens4 --unicast=${unicast} 0.0.0.0 4433 ~/data/server.key ~/data/server.crt -q

{unicast_ip}为server的外部ip
```



# 3. 关键代码说明

以下都以ngtcp2的resource_demand分支下的主文件夹作为相对路径的根目录。

## 3.1. metadata

* 需要修改的文件包括：lib/ngtcp2_crypto.c, lib/includes/ngtcp2/ngtcp2.h, examples/balancer.h, examples/balancer.cc, client.cc, debug.cc,

- lib/ngtcp2_crypto.c

  - 主要用于修改ngtcp2的metadata加解密的操作。

  ```
    -------
    if (params->cpu_sensitive) {
      len += 8;
    }
    --------
    if (params->cpu_sensitive) {
      p = ngtcp2_put_uint16be(p, NGTCP2_TRANSPORT_PARAM_CPU_SENSITIVE);
      p = ngtcp2_put_uint16be(p, 4);
      p = ngtcp2_put_uint32be(p, params->cpu_sensitive);
    }
    --------
    case NGTCP2_TRANSPORT_PARAM_CPU_SENSITIVE:
        flags |= 1u << NGTCP2_TRANSPORT_PARAM_CPU_SENSITIVE;
        if (ngtcp2_get_uint16(p) != sizeof(uint32_t)) {
          return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
        }
        // printf("decode cpu sensitive: %lld %lld\n", p, *p);
        p += sizeof(uint16_t);
        if ((size_t)(end - p) < sizeof(uint32_t)) {
          return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
        }
        params->cpu_sensitive = ngtcp2_get_uint32(p);
        // printf("decode cpu sensitive: %lld %lld %lld\n", p, *p, ngtcp2_get_uint32(p));
        p += sizeof(uint32_t);
        break;
  ```

  - lib/includes/ngtcp2/ngtcp2.h

  ```
    NGTCP2_TRANSPORT_PARAM_CPU_SENSITIVE = 12,
    --------
  	uint32_t cpu_sensitive;
  	...
  } ngtcp2_transport_params;
  
  	--------
    uint32_t cpu_sensitive;
  	...
  } ngtcp2_settings;
  ```

  

  - examples/balancer.h

  ```
  struct Config {
  	...
  	uint32_t cpu_sensitive = 0;
  ```

  

  - examples/balancer.cc

  ```
  和具体request选择算法相关的地方。
  根据后面算法调整后，再重新定义所在位置。
  ```

  

  - client.cc

  ```
  控制请求发出，具体params是什么。
  利用params.cpu_sensitive等来控制
  ```

  

  - debug.cc

  ```
  fprintf(outfile, "; cpu_sensitive=%u\n", params->cpu_sensitive);
  ```



## 3.2. client

用户端的核心代码。

```
通过config.website_root_path，给params.xxx_sensitive赋值。
"recv_error"处有添加penalty，使得数据更相符。
其他出错不自动断，不重传和恢复。
```



## 3.3. balancer

调度器的核心代码。

```
mysql+redis 查询，并排序：从“/* select balancer */”，到“Logs mysql optimal and suboptimal costs”
选择代码由于后面权重可能需要重新计算，暂时不描述选择逻辑。
```



## 3.4. server

```
注意cpu相关类型的请求，python运行的时候是在后台，不把结果和耗时返回给client
```



# 4. 传输文件说明

## 4.1. websites

* server端需要完整的数据，client端需要resource_list.txt

总共有四种文件类型：

- cpu：关键注意cpu.py里面，查询的数据库范围和次数
- normal_1：共263个网页，都是以www.开头
- normal_2：共110个网页，没有www.开头
- video：共50个视频文件流



## 4.2. websites2

* server端需要完整的数据，client端需要resource_list.txt

总共有三种文件类型：

- cpu：关键注意cpu.py里面，查询的数据库范围和次数
- normal_1：共1个网页，www.google.com
- video：共2个视频文件流文件，一个用于数据库初始化(1MB)，另一个用于实际传输(5MB)

