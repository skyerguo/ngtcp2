import os

data_root = ['./normal_1', './normal_2']

max_len = 0
for root_path in data_root:
    for file_name in os.listdir(root_path):
        max_len = max(max_len, len(file_name))
print(max_len)