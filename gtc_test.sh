#examples/client 127.0.0.7 4433 -i -w google.com -q > gtc_temp.txt & pid=$!
#sleep 5
#kill -9 $pid
#echo $pid
examples/client 127.0.0.7 4433 -i -w instagram.com -q 2> gtc_temp2.txt

