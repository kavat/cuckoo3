import os
import sys

sys.path.insert(0, '/opt/anubi')

import config
import conf_anubi

from core.common import (
  check_anubi_struct,
  create_anubi_struct,
  init_rules_repo,
  id_generator
)
 
from core.yara_scanner import ( 
  YaraScanner,
  yara_scan_single_file
)
 
from core.hash_scanner import (
  HashScanner,
  hash_scan_single_file
)

from core.ip_checker import (
  IpChecker
)

def anubi_analyze_single_file(filepath, orig_filename):

  rit = {'status':True, 'hash_scan':"", 'yara_scan':[], 'msg':"", "file":orig_filename}

  if os.path.isfile(filepath) == False:
    rit['msg'] = "{} not exists".format(filepath)
    rit['status'] = False
    return rit

  if check_anubi_struct() == False:
    config.loggers["resources"]["logger_anubi_main"].get_logger().info("Create necessary structs")
    create_anubi_struct()
  else: 
    config.loggers["resources"]["logger_anubi_main"].get_logger().info("Update existing rules: {}".format(init_rules_repo('main', True)))
    
  config.loggers["resources"]["logger_anubi_main"].get_logger().info("Starting Anubi for single scan file use..")
    
  config.loggers["resources"]["logger_anubi_yara"].get_logger().info("Oneshot yara_scan started")
  rit['yara_scan'] = yara_scan_single_file(YaraScanner(), filepath, 'main')
  
  config.loggers["resources"]["logger_anubi_hash"].get_logger().info("Oneshot hash_scan started")
  rit['hash_scan'] = hash_scan_single_file(HashScanner(), filepath, 'main')
    
  config.loggers["resources"]["logger_anubi_main"].get_logger().info("Finished Anubi for single scan file use..")
  if len(rit['hash_scan']) == 0:
    rit['hash_scan'].append("No malware detected")
  if len(rit['yara_scan']) == 0:
    rit['yara_scan'].append("No Yara rule triggered")
  
  return rit

class AnubiIPChecker:
  def __init__(self):
    self.ip_checker = IpChecker()

  def scan_flow(self, src, sport, dst, dport, proto):
    return self.ip_checker.scan_network_flow(src, sport, dst, dport, proto)
