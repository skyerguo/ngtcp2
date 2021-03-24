import pymongo
import random
import time

client = pymongo.MongoClient('localhost', 27017)
db = client['motivation_index']
collection = db['shuffle']

n = random.randint(10, 60)
print(n)

for i in range(n):
    for item in collection.find({"value": random.randint(0, 5000000)}):
        print(item)