import pymongo
import random
import time

client = pymongo.MongoClient('localhost', 27017)
db = client['motivation_index']
collection = db['shuffle']

# f_out = open("/home/gtc/data/motivation_db/select.txt", "a")
f_out = open("/home/gtc/temp.txt", "a")
n = random.randint(50, 200)
print(n, file=f_out)
ori_time = int(time.strftime('%Y%m%d%H%M%S',time.localtime(time.time())))
ori_time = ori_time + 80000
print("start_time: ", ori_time, file=f_out)

for i in range(n):
    for item in collection.find({"value": random.randint(0, 5000000)}):
        print(str(i) + '/' + str(n))
        print(item, file=f_out)

ori_time = int(time.strftime('%Y%m%d%H%M%S',time.localtime(time.time())))
ori_time = ori_time + 80000
print("end_time: ",ori_time, file=f_out)

f_out.close()