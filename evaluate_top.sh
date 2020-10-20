#!/bin/bash

row_index=0
row_total=$(cat index.csv|wc -l)
for ((j=0;j<2;j++)); do
echo "row_total: " ${row_total}
#temp_index=$(cat index.csv)

for row in $(cat index.csv); do
    echo "row: " $row
    #echo "pid: " $pid
    let row_index+=1
    if [ "${row_index}" == "${row_total}" ]
    then
        examples/client 127.0.0.1 4433 -i -w $row -q 1>unused.log 2>>temp_0.log #& pid=$!
        #echo "index: " ${row_index} >>temp.log
        sleep 5
        #echo "pid: " $pid
        #sudo kill -9 $pid
        #echo "pid: " $pid
        break
    else
        examples/client 127.0.0.1 4433 -i -w $row -q 1>unused.log 2>>temp_0.log
    fi
done
echo "evaluate the top websites done" >>temp.log
done
for row in $(cat index.csv); do
    echo "row: " $row
    # echo "pid: " $pid
    examples/client 127.0.0.1 4433 -i -w $row -q 2>>temp_1.log
    let row_index+=1
    if [ "${row_index}" == "${row_total}" ]
    then
        echo "index: " ${row_index} >>temp.log
        sleep 5
        #sudo kill -9 $pid
        break
    fi
    break
done
