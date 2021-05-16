import os

f_in = open('./normal_1/resource_list.txt', 'r')

lines = [line.replace('\n','') for line in f_in]

print(len(lines))
# for file_name in os.listdir('./normal_1'):
#     if file_name == 'resource_list.txt':
#         continue
#     if file_name not in lines:
#         print(file_name)
#         os.system("rm -r ./normal_1/" + file_name)
