make -j$(nproc) > /dev/null
interface=`route |grep default| head -n1| tr -s ' '| cut -d' ' -f8`
sudo ./examples/dispatcher ${interface} 127.0.0.1 4433 /home/johnsonli1993/keys/server.key /home/johnsonli1993/keys/server.cert

