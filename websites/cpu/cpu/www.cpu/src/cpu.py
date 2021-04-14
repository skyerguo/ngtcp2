import pymongo
import random
import time

client = pymongo.MongoClient('localhost', 27017)
db = client['motivation_index']
collection = db['shuffle']

def get_ms():
    ct = time.time()
    local_time = time.localtime(ct)
    data_head = int(time.strftime('%Y%m%d%H%M%S', local_time)) + 80000
    data_secs = (ct - int(ct)) * 1000
    time_stamp = "%s.%03d" % (str(data_head), data_secs)
    return time_stamp

# f_out = open("/home/gtc/data/motivation_db/select.txt", "a")
ori_time = get_ms()
# f_out = open("/home/gtc/select_mongodb_%s.txt" % ori_time, "a")
n = random.randint(50, 100)
n = 1
print(n)
ori_time = get_ms()
print("start_time: ", ori_time)

for i in range(n):
    for item in collection.find({"value": random.randint(0, 5000000)}):
        print(str(i + 1) + '/' + str(n))
        ori_time = get_ms()
        print(ori_time, '+', item)

print("done")

ori_time = get_ms()
print("end_time: ",ori_time)

# f_out.close()