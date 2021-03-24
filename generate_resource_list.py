import os
from os.path import expanduser
from shutil import copyfile, copytree, copy

HOME = expanduser("~")
Data_src_path = '%s/ngtcp2/resource/global500/' % HOME
Data_des_path = '%s/ngtcp2/websites/normal/' % HOME

cnt_res = 500 # 留下的网站数量最大值
for first_file_name in os.listdir(Data_src_path):
    flag = 0
    src_file = os.path.join(Data_src_path, first_file_name)
    for second_file_name in os.listdir(src_file):
        if 'www.' + first_file_name == second_file_name:
            for third_file_name in os.listdir(os.path.join(src_file, second_file_name)):
                if "index.html" == third_file_name:
                    flag = 1
                    break

        if first_file_name == second_file_name:
            for third_file_name in os.listdir(os.path.join(src_file, second_file_name)):
                if "index.html" == third_file_name:
                    flag = 2
                    break

        if flag:
            break

    if flag:
        des_file = os.path.join(Data_des_path, first_file_name)
        if os.path.exists(des_file):
            os.system("rm -r " + des_file)
        copytree(src_file, des_file)
        # print(src_file)
        cnt_res -= 1
    if not cnt_res:
        break

f_out = open(Data_des_path + 'resource_list.txt', 'w')
for file_name in os.listdir(Data_des_path):
    if not file_name.endswith('.txt'):
        f_out.write(file_name + '\n')
f_out.close()