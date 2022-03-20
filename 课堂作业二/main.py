# -*- coding: UTF-8 -*-
"""
@Project ：课堂作业二 
@File ：main.py
@Author ：AnthonyZ
@Date ：2022/3/19 13:47
"""

if __name__ == "__main__":
    content = "Methods of making messages unintelligible to adversaries have been necessary. Substitution is the simplest method that replaces a character in the plaintext with a fixed different character in the ciphertext. This method preserves the letter frequency in the plaintext and so one can search for the plaintext from a given ciphertext by comparing the frequency of each letter against the known common frequency in the underlying language."
    key = "BLACKHAT"
    result = []
    count = int(0)
    for index in content:
        if index == " ":
            temp = " "
        elif index == '.':
            temp = '.'
        else:
            temp = chr(((ord(index.lower()) - 97) + (ord(key[count % len(key)].lower()) - 97)) % 26 + 97)
            count += 1
        result.append(temp)
    result = "".join(result)
    print(str(result))
