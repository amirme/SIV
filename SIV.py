#!/usr/bin/env python3
import argparse
import datetime
import os
import sys
import textwrap
import hashlib
import pwd
from grp import getgrgid
import json

# """function for json encoder function"""


def json_encoder(dir_dic_para, hash_dic_para, file_dic_para):
    dic = []

    dic.append(dir_dic_para)
    dic.append(file_dic_para)
    dic.append(hash_dic_para)

    encode = json.dumps(dic, indent=2, sort_keys=True)

    return encode



# """function for Creating hash of the file"""


def get_hash(file, hash_function):
    with open(file, 'rb') as mess_file:
        buffer = mess_file.read()
        hash_function.update(buffer)

        return hash_function.hexdigest()

# """ parsing the arguments of the SIV """

parser = argparse.ArgumentParser(description=textwrap.dedent(
                                 '''Initialization mode format : "SIV.py" -i -D "Monitoring directory" -V "Verification file" -R "Report file" -H "Hash function" 
                                    &
                                    Verification mode format : "SIV.py" -v -D "Monitoring directory" -V "Verification file" -R "Report file"'''))

arg_mode = parser.add_mutually_exclusive_group()
arg_mode.add_argument("-i", "--initialization", action="store_true", help="Initialization mode")
arg_mode.add_argument("-v", "--verification", action="store_true", help="Verification mode")
parser.add_argument("-D", "--monitoring_directory", type=str, help="Specify the monitoring directory")
parser.add_argument("-V", "--verification_file", type=str, help="Specify the name and location for the verification file")
parser.add_argument("-R", "--report_file", type=str, help="Specify the name and location fot the report file")
parser.add_argument("-H", "--hash_function", type=str, help="Supported hash functions are SHA-1 and MD-5")

args=parser.parse_args()

monitoring_dir = args.monitoring_directory
verification_f = args.verification_file
report_f = args.report_file
hash_func = args.hash_function


if args.initialization:

    print("Initialization mode")
    start_time = datetime.datetime.now()

    if os.path.isdir(monitoring_dir) == True:
        print("Monitoring directory is available\n")

        # checking the hash functions that are supported by the SIV
        if hash_func == "SHA-1" or hash_func == "MD-5" or hash_func == "sha-1" or hash_func == "md-5" or hash_func == "sha1" or hash_func == "md5" or hash_func == "SHA1" or hash_func == "MD5":
            print("Hash type is " + hash_func)

            dir_dic = {}
            file_dic = {}
            hash_dic = {}
            v_exist = False
            r_exist = False
            file_counter = 0
            directory_counter = 0
            rep_over = False
            ver_over = False

            # """checking that the verification file is exist or not"""
            if os.path.isfile(verification_f) == True:
                print("Verification file exists")
                v_exist = True

                # """checking to see if the verification file is in the monitoring directory or not"""
                if os.path.commonprefix([monitoring_dir, verification_f] == monitoring_dir):
                    print("Verification file is inside the monitoring directory")
                    sys.exit(0)
                else:
                    print("Verification file is outside the monitoring directory")

            if v_exist is True:
                print("Do you want to overwrite verification file?")
                ans = input("[y/n]")

                if ans is "n":
                    sys.exit()
                elif ans is "y":
                    os.open(verification_f, os.O_CREAT)

            # """checking to see if the report file is exist or not"""
            if os.path.isfile(report_f) == True:
                print("Report file exists")
                r_exist = True

                if os.path.commonprefix([monitoring_dir, report_f] == monitoring_dir):
                    print("Report file is inside the monitoring directory")
                    sys.exit()
                else:
                    print("Report file is outside the monitoring directory")





            if r_exist is True:
                print("Do you want to overwrite report file?")
                ans = input("[y/n]")

                if ans is "n":
                    sys.exit()
                elif ans is "y":
                    os.open(report_f, os.O_CREAT)

                    for root, directories, files in os.walk(monitoring_dir):
                        for file in files:
                            file_counter += 1
                            file_path = os.path.join(root, file)
                            file_size = os.stat(file_path).st_size
                            file_user_name = pwd.getpwuid(os.stat(file_path).st_uid).pw_name
                            file_group_name = getgrgid(os.stat(file_path).st_gid).gr_name
                            file_last_modification = datetime.datetime.fromtimestamp(os.stat(file_path).st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                            file_access_right = oct(os.stat(file_path).st_mode & 0o777)
                            if hash_func == "MD-5" or hash_func == "md-5" or hash_func == "md5" or hash_func == "MD5":
                                hash_string = "md5"
                                hash_type = hashlib.md5()
                                message = get_hash(file_path, hash_type)
                            else:
                                hash_string = "sha1"
                                hash_type = hashlib.sha1()
                                message = get_hash(file_path, hash_type)

                            hash_dic = {"hash_type": hash_string}

                            file_dic[file_path] = {"file_size": file_size, "file_user_name": file_user_name,
                                                   "file_group_name": file_group_name,
                                                   "file_last_modification": file_last_modification,
                                                   "file_access_right": file_access_right, "file_hash": message}




                        for directory in directories:
                            directory_counter+=1
                            directory_path = os.path.join(root, directory)
                            directory_size = os.stat(directory_path).st_size
                            directory_user_name = pwd.getpwuid(os.stat(directory_path).st_uid).pw_name
                            directory_group_name = getgrgid(os.stat(directory_path).st_gid).gr_name
                            directory_last_modification = datetime.datetime.fromtimestamp(os.stat(directory_path).st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                            directory_access_right =oct(os.stat(directory_path).st_mode & 0o777)


                            dir_dic[directory_path] = {"directory_size" : directory_size, "directory_user_name" : directory_user_name,
                                                        "directory_group_name" : directory_group_name, "directory_last_modification" : directory_last_modification, "directory_access_right" : directory_access_right}



                    json_encoded = json_encoder(dir_dic, hash_dic , file_dic)

                    with open(verification_f, 'w') as ver_file:
                        ver_file.write(json_encoded)

                    print("verification file is overwrited")

                    with open(report_f, 'w') as rep_file:
                        end_time = datetime.datetime.now()
                        elapsed_time = end_time - start_time
                        rep_file.write("\nReport file in Initialization mode : \n" +
                                       "\nMonitoring directory : " + monitoring_dir +
                                       "\nVerification file : " + verification_f +
                                       "\nNumber of files : " + str(file_counter) +
                                       "\nNumber of directories : " + str(directory_counter) +
                                       "\nTime : " + str(elapsed_time) + "\n")
                    print("Report file is overwrited")
            else:
                os.open(report_f, os.O_CREAT)
                os.open(verification_f, os.O_CREAT)

                for root, directories, files in os.walk(monitoring_dir):
                    for file in files:
                        file_counter += 1
                        file_path = os.path.join(root, file)
                        file_size = os.stat(file_path).st_size
                        file_user_name = pwd.getpwuid(os.stat(file_path).st_uid).pw_name
                        file_group_name = getgrgid(os.stat(file_path).st_gid).gr_name
                        file_last_modification = datetime.datetime.fromtimestamp(os.stat(file_path).st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                        file_access_right = oct(os.stat(file_path).st_mode & 0o777)
                        if hash_func == "MD-5":
                            hash_string = "md5"
                            hash_type = hashlib.md5()
                            message = get_hash(file_path, hash_type)
                        else:
                            hash_string = "sha1"
                            hash_type = hashlib.sha1()
                            message = get_hash(file_path, hash_type)

                        hash_dic = {"hash_type": hash_string}

                        file_dic[file_path] = {"file_size": file_size, "file_user_name": file_user_name,
                                               "file_group_name": file_group_name,
                                               "file_last_modification": file_last_modification,
                                               "file_access_right": file_access_right, "file_hash": message}

                    for directory in directories:
                        directory_counter += 1
                        directory_path = os.path.join(root, directory)
                        directory_size = os.stat(directory_path).st_size
                        directory_user_name = pwd.getpwuid(os.stat(directory_path).st_uid).pw_name
                        directory_group_name = getgrgid(os.stat(directory_path).st_gid).gr_name
                        directory_last_modification = datetime.datetime.fromtimestamp(os.stat(directory_path).st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                        directory_access_right = oct(os.stat(directory_path).st_mode & 0o777)

                        dir_dic[directory_path] = {"directory_size": directory_size,
                                                   "directory_user_name": directory_user_name,
                                                   "directory_group_name": directory_group_name,
                                                   "directory_last_modification": directory_last_modification,
                                                   "directory_access_right": directory_access_right}

                json_encoded = json_encoder(dir_dic, hash_dic, file_dic)

                with open(verification_f, 'w') as ver_file:
                    ver_file.write(json_encoded)

                print("verification file is created")

                with open(report_f, 'w') as rep_file:
                    end_time = datetime.datetime.now()
                    elapsed_time = end_time - start_time
                    rep_file.write("\nReport file in Initialization mode : \n" +
                                   "\nMonitoring directory : " + monitoring_dir +
                                   "\nVerification file : " + verification_f +
                                   "\nNumber of files : " + str(file_counter) +
                                   "\nNumber of directories : " + str(directory_counter) +
                                   "\nTime : " + str(elapsed_time) + "\n")
                print("Report file is created")
        else:
            print("Hash type is not supported")
            sys.exit()
    else:
        print("cannot find the monitoring directory")
        sys.exit()

elif args.verification:
    print("Verification mode")

    if os.path.isfile(verification_f) == True:
        print("Verification file exists\n")
    else:
        print("Verification file does not exist")
        sys.exit()

    if os.path.commonprefix([monitoring_dir, verification_f]) == monitoring_dir:
        print("Verification file must be outside of the monitoring directory")
        sys.exit()
    else:
        print("Verification file is outside of the monitoring directory")

    if os.path.commonprefix([monitoring_dir, report_f]) == monitoring_dir:
        print("Report file must be outside of the monitoring directory")
        sys.exit()
    else:
        print("Report file is outside of the monitoring directory")

    if os.path.isfile(report_f) is True:
        print("Do you want to overwrite report file?")
        ans = input("[y/n]")

        if ans is "n":
            sys.exit()
        else:
            print("The report file is overwrited")

    file_counter = 0
    directory_counter = 0
    warning_counter = 0

    with open(verification_f) as verification_check:
        old_walk = json.load(verification_check)
        hash_type = old_walk[2]

    start_time = datetime.datetime.now()

    with open(report_f, 'w') as report_check:

        for root, directories, files in os.walk(monitoring_dir):
            for directory in directories:
                directory_counter += 1
                directory_path = os.path.join(root, directory)
                directory_size = os.stat(directory_path).st_size
                directory_user_name = pwd.getpwuid(os.stat(directory_path).st_uid).pw_name
                directory_group_name = getgrgid(os.stat(directory_path).st_gid).gr_name
                directory_last_modification = datetime.datetime.fromtimestamp(os.stat(directory_path).st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                directory_access_right = oct(os.stat(directory_path).st_mode & 0o777)


                if directory_path in old_walk[0]:

                    if directory_size != old_walk[0][directory_path]['directory_size']:
                        report_check.write("warning: " + directory_path + " size has been changed\n")
                        warning_counter += 1
                    if directory_user_name != old_walk[0][directory_path]['directory_user_name']:
                        report_check.write("warning : " + directory_path + " username has been changed\n")
                        warning_counter += 1
                    if directory_group_name != old_walk[0][directory_path]['directory_group_name']:
                        report_check.write("warning : " + directory_path + " groupname has been changed\n")
                        warning_counter += 1
                    if directory_last_modification != old_walk[0][directory_path]['directory_last_modification']:
                        report_check.write("warning : " + directory_path + " last modification date has been changed\n")
                        warning_counter += 1
                    if directory_access_right != old_walk[0][directory_path]['directory_access_right']:
                        report_check.write("warning : " + directory_path + " directory access right has been changed\n")
                        warning_counter += 1
                else:
                    report_check.write("warning : " + directory_path + " has been created lately\n")
                    warning_counter += 1

        for directory_delete in old_walk[0]:

            if os.path.isdir(directory_delete) is False:
                report_check.write("warning : " + directory_delete + " has been deleted lately\n")
                warning_counter += 1


        for root, directories, files in os.walk(monitoring_dir):
            for file in files:
                file_counter += 1
                file_path = os.path.join(root, file)
                file_size = os.stat(file_path).st_size
                file_user_name = pwd.getpwuid(os.stat(file_path).st_uid).pw_name
                file_group_name = getgrgid(os.stat(file_path).st_gid).gr_name
                file_last_modification = datetime.datetime.fromtimestamp(os.stat(file_path).st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                file_access_right = oct(os.stat(file_path).st_mode & 0o777)

                if hash_func == "MD-5" or hash_func == "MD5" or hash_func == "md-5" or hash_func == "md5":
                    hash_string = "md5"
                    hash_type = hashlib.md5()
                    message = get_hash(file_path, hash_type)
                else:
                    hash_string = "sha1"
                    hash_type = hashlib.sha1()
                    message = get_hash(file_path, hash_type)


                if file_path in old_walk[1]:

                    if file_size != old_walk[1][file_path]['file_size']:
                        report_check.write("warning: " + file_path + " size has been changed\n")
                        warning_counter += 1
                    if file_user_name != old_walk[1][file_path]['file_user_name']:
                        report_check.write("warning : " + file_path + " username has been changed\n")
                        warning_counter += 1
                    if file_group_name != old_walk[1][file_path]['file_group_name']:
                        report_check.write("warning : " + file_path + " groupname has been changed\n")
                        warning_counter += 1
                    if file_last_modification != old_walk[1][file_path]['file_last_modification']:
                        report_check.write("warning : " + file_path + " last modification date has been changed\n")
                        warning_counter += 1
                    if file_access_right != old_walk[1][file_path]['file_access_right']:
                        report_check.write("warning : " + file_path + " access right has been changed\n")
                        warning_counter += 1
                    if message != old_walk[1][file_path]['file_hash']:
                        report_check.write("warning : " + file_path + " hash of the file has been changed\n")
                        warning_counter += 1
                else:
                    report_check.write("\n warning : " + file_path + " has been created lately\n")
                    warning_counter += 1

        for file_delete in old_walk[1]:
            if os.path.isfile(file_delete) is False:
                report_check.write("\nwarning : " + file_delete + " has been deleted lately\n")
                warning_counter += 1



        end_time = datetime.datetime.now()
        elapsed_time = end_time - start_time
        report_check.write("\nReport file in Verification mode :\n " +
                       "\nMonitoring directory : " + monitoring_dir +
                       "\nVerification file : " + verification_f +
                       "\nReport file : " + report_f +
                       "\nNumber of files : " + str(file_counter) +
                       "\nNumber of directories : " + str(directory_counter) +
                       "\nNumber of warnings : " + str(warning_counter) +
                       "\nTime : " + str(elapsed_time) + "\n")
