sudo ./examples/server 35.223.128.197 4433 --interface ens4 --unicast 35.223.128.197 server.key server.crt -q
sudo ./examples/server 35.223.128.197 4433 server.key server.crt -q
sudo ./examples/server 127.0.0.1 4433 server.key server.crt -q
# sudo /home/gtc/data/server 10.142.0.4 4433 --interface ens4 --unicast 10.142.0.4 /home/gtc/data/server.key /home/gtc/data/server.crt
# sudo /home/gtc/data/server 35.227.46.23 4433 --interface ens4 --unicast 35.227.46.23 /home/gtc/data/server.key /home/gtc/data/server.crt
# sudo LD_LIBRARY_PATH=/home/gtc/data /home/gtc/data/server --interface=ens4 --unicast=10.142.15.230 0.0.0.0 4433 /home/gtc/data/server.key /home/gtc/data/server.crt
