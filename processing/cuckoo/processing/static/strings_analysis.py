import re
import json
import os
import enchant
import string
import subprocess

from optparse import OptionParser
from cuckoo.common.config import cfg

CHAR_BEFORE_AFTER = 20

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
    #print('[ERROR] FILE CAN NOT BE OPENED OR READ!')
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
        buff = ''
  f.close()
  return output_bxor

def prendi_tutti_contesti(testo, sottostringa, n):
  risultati = []
  start = 0
  while True:
    idx = testo.find(sottostringa, start)
    if idx == -1:
      break
    inizio = max(0, idx - n)
    fine = min(len(testo), idx + len(sottostringa) + n)
    risultati.append(testo[inizio:fine])
    start = idx + 1 # continua a cercare dopo l'occorrenza trovata
  return risultati

def run_cmd(cmd_list):
  result = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  return result.stdout.decode(errors='ignore'), result.stderr.decode(errors='ignore')

def StringsDetonation(filename, log_handler, errtracker_handler):
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
  log_handler.info(f"[{filename}] started string analysis stage 1")
  for pattern_ in patterns_:
    rit['occurrences'][pattern_] = []
    patterns = {pattern_:all_patterns[pattern_]}
    for s in find_strings(filename, patterns):
      rit['occurrences'][pattern_].append(s)

  log_handler.info(f"[{filename}] started string analysis stage 2")
  output, err = run_cmd(['strings', filename])
  lines = output.splitlines()
  rit['occurrences']['suspicious_string'] = []
  for line in lines:
    for pattern in cfg("cuckoo.yaml", "suspicious_strings"):
      if pattern in line.lower():
        rit['occurrences']['suspicious_string'].append(f"{pattern} in {prendi_tutti_contesti(line.lower(), pattern, CHAR_BEFORE_AFTER)}")

  log_handler.info(f"[{filename}] string analysis finished")

  return rit
