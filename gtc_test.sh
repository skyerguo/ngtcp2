#!/bin/bash
#examples/client 127.0.0.1 4433 -i -w wikipedia.org -q
#examples/client 127.0.0.1 4433 -i -w google.com -q
for row in $(cat websites/normal/resource_list.txt); do
   echo $row
   examples/client 127.0.0.1 4433 -i -w $row -q
   break
done