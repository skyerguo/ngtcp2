#!/bin/bash
#examples/client 127.0.0.1 4433 -i -w wikipedia.org -q
#examples/client 127.0.0.1 4433 -i -w google.com -q
for row in $(cat index.csv); do
   examples/client 127.0.0.1 4433 -i -w $row -q 2>>gtc_temp1.log
done
for row in $(cat index.csv); do
   examples/client 127.0.0.1 4433 -i -w $row -q 2>>gtc_temp2.log
done
