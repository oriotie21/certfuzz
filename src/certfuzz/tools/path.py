import os

def join2(str1, str2):
    if str2=="" or not os.path.isdir(str1):
        return str1
    else:
        return os.path.join(str1, str2)