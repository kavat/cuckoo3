import sys
import re
import json
import os
import enchant
import string

from optparse import OptionParser

def find_strings(filename, patterns, min_length=4):
    with open(filename, 'rb') as f:
        #content = f.read().decode('ascii', 'ignore')
        content = f.read().decode('latin-1', 'ignore')
        content_bxor = brxor(filename)
        results = []
        ascii_regex = re.compile(r'[ -~]{' + str(min_length) + r',}', re.IGNORECASE)
        for pattern_name, pattern_regex in patterns.items():
            if pattern_name == 'all':
                matches = ascii_regex.findall(content)
            else:
                matches = re.findall(pattern_regex, content)
            for match in matches:
                results.append(match)
        for pattern_name, pattern_regex in patterns.items():
            if pattern_name == 'all':
                matches = ascii_regex.findall(content_bxor)
            else:
                matches = re.findall(pattern_regex, content_bxor)
            for match in matches:
                results.append(match)
        return set(results)

def valid_ascii(char):
    if char in string.printable[:-3]:
        return True
    else:
        return None 

def xor(data, key):
    decode = ''
    if isinstance(key, str):
        key = int(key,16)
        
    for d in data:
        decode = decode + chr(ord(d) ^ key)
    return decode

# http://stackoverflow.com/questions/14678132/python-hexadecimal
def twoDigitHex(num):
    return '0x%02x' % num

def brxor(filename):
    word_dict = enchant.Dict('en_US')
    regex = re.compile(r'\x00(?!\x00).+?\x00') 
    buff = ''
    output_bxor = ""

    try:
        f = open(filename,'rb')
    except Exception:
        print('[ERROR] FILE CAN NOT BE OPENED OR READ!')
        return output_bxor
    # for each regex pattern found
    for match in regex.finditer(f.read().decode("latin-1", "ignore")):
        if len(match.group()) < 8:
            continue 
        # for XOR key in range of 0x0 to 0xff
        for key in range(1,0x100):
            # for each byte in match of regex pattern 
            for byte in match.group():
                if byte == '\x00':
                    buff = buff + '\x00'
                    continue 
                else:
                    tmp = xor(byte,key)
                    if valid_ascii(tmp) == None:
                        buff = ''
                        break
                    else:
                        buff = buff + tmp
            if buff != '':
                words = re.findall(r'\b[a-zA-Z]{4,}\b',buff)
                # TODO: case insensitive matches
                enchants = [x for x in words if word_dict.check(x.lower()) == True]
                if len(enchants) > 0:
                        output = '[%s (%s)] %s\n' % (hex(match.start()),twoDigitHex(key),buff)
                        output_bxor = '%s%s\n' % (output_bxor,buff)
                        # avoid line breaks in the middle of a string
                        output = output.strip().replace('\n', '\\n')
                        sys.stdout.write(output + '\n')
                buff = ''
    f.close()
    return output_bxor

def StringsDetonation(filename):
    rit = {'status':True, "occurrences":{}, 'msg':"" }
    all_patterns = {
        "url": "\\b(?:http|https|ftp):\\/\\/[a-zA-Z0-9-._~:?#[\\]@!$&'()*+,;=]+",
        "ipv4": "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b",
        "ipv6": "\\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\\b|\\b(?:[A-Fa-f0-9]{1,4}:){1,7}:\\b|\\b:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){1,6}\\b",
        "mac": "\\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\\b",
        "email": "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
        "packer": "^(upx|aspac|pec|fsg|themida|mew|armadillo|nsis|yoda|petite)"
    }
    patterns_ = ["url", "ipv4", "email", "packer"]
    for pattern_ in patterns_:
        rit['occurrences'][pattern_] = []
        patterns = {pattern_:all_patterns[pattern_]}
        for s in find_strings(filename, patterns):
            rit['occurrences'][pattern_].append(s)
    return rit
