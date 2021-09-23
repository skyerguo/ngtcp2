sudo apt install git tmux autoconf libtool pkg-config libev-dev -y
sh -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"

curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
sudo apt-get install python3-distutils
sudo python3 get-pip.py
sudo pip3 config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simpl

sudo apt install make gcc -y

# openssl
git clone --depth 1 -b quic https://github.com/tatsuhiro-t/openssl
cd openssl
./config enable-tls1_3 --prefix=$PWD/build
make -j$(nproc)
make install_sw

# lexbor
curl -O https://lexbor.com/keys/lexbor_signing.key
sudo apt-key add lexbor_signing.key

sudo echo "deb https://packages.lexbor.com/ubuntu/ bionic liblexbor" >> /etc/apt/sources.list.d/lexbor.list
sudo echo "deb-src https://packages.lexbor.com/ubuntu/ bionic liblexbor" >> /etc/apt/sources.list.d/lexbor.list

sudo apt update
sudo apt install liblexbor -y
sudo apt install liblexbor-dev -y

