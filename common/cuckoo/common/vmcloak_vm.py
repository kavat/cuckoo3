import nmap
import mysql.connector
import base64

from cuckoo.common.config import cfg

def GetCurrentGuacamoleVM():

  ritorno = []

  mydb = mysql.connector.connect(
    host=cfg("cuckoo.yaml", "guacamole", "db_ip"),
    user=cfg("cuckoo.yaml", "guacamole", "db_user"),
    password=cfg("cuckoo.yaml", "guacamole", "db_passwd"),
    database=cfg("cuckoo.yaml", "guacamole", "db_name")
  )

  mycursor = mydb.cursor()
  mycursor.execute("select connection_id, connection_name from guacamole_connection")

  rows = mycursor.fetchall()

  for row in rows:
    client_id_string = "{}\x00c\x00mysql".format(row[0])
    client_id_bytes = client_id_string.encode("ascii") 
  
    base64_bytes = base64.b64encode(client_id_bytes) 
    client_id = base64_bytes.decode("ascii") 
  
    url = "{}://{}:{}{}/#/client/{}?username={}&password={}".format(cfg("cuckoo.yaml", "guacamole", "web_protocol"), cfg("cuckoo.yaml", "guacamole", "web_ip"), cfg("cuckoo.yaml", "guacamole", "web_port"), cfg("cuckoo.yaml", "guacamole", "web_path"), client_id, cfg("cuckoo.yaml", "guacamole", "web_user"), cfg("cuckoo.yaml", "guacamole", "web_passwd"))
    ritorno.append({'ip': row[1], 'url': url})

  return ritorno

def InsertGuacamoleVM(ip):
  mydb = mysql.connector.connect(
    host=cfg("cuckoo.yaml", "guacamole", "db_ip"),
    user=cfg("cuckoo.yaml", "guacamole", "db_user"),
    password=cfg("cuckoo.yaml", "guacamole", "db_passwd"),
    database=cfg("cuckoo.yaml", "guacamole", "db_name")
  )

  mycursor = mydb.cursor()
  mycursor.execute("select connection_id from guacamole_connection_parameter where parameter_name = 'hostname' and parameter_value = '{}'".format(ip))
  row_count = mycursor.fetchone()

  if row_count == None:
    mycursor.execute("insert into guacamole_connection (connection_name, protocol) values ('{}', 'vnc')".format(ip))
    mycursor.execute("insert into guacamole_connection_parameter values ((select connection_id from guacamole_connection where connection_name = '{}'), 'hostname', '{}')".format(ip, ip))
    mycursor.execute("insert into guacamole_connection_parameter values ((select connection_id from guacamole_connection where connection_name = '{}'), 'port', '5900')".format(ip))
    mydb.commit()
  else:
    print("{} already present in Guacamole".format(ip))

def ClearGuacamoleVM(hosts_found):

  if len(hosts_found) == 0:
    hosts_found = "'nd'"

  mydb = mysql.connector.connect(
    host=cfg("cuckoo.yaml", "guacamole", "db_ip"),
    user=cfg("cuckoo.yaml", "guacamole", "db_user"),
    password=cfg("cuckoo.yaml", "guacamole", "db_passwd"),
    database=cfg("cuckoo.yaml", "guacamole", "db_name")
  )

  mycursor = mydb.cursor()
  mycursor.execute("select connection_id from guacamole_connection_parameter where parameter_name = 'hostname' and parameter_value not in ({})".format(",".join(hosts_found)))

  rows = mycursor.fetchall()

  for row in rows:
    delete_cursor = mydb.cursor()
    sql = "delete from guacamole_connection_parameter where connection_id = {}".format(row[0])
    print("Executing {}".format(sql))
    delete_cursor.execute(sql)
    sql = "delete from guacamole_connection where connection_id = {}".format(row[0])
    delete_cursor.execute(sql)
    print("Executing {}".format(sql))
    mydb.commit()

def GetLiveVM():
  port_searched = 5900
  hosts_found = []
  nm = nmap.PortScanner()
  nm.scan('192.168.30.0/24', "{}".format(port_searched))
  for host in nm.all_hosts():
    if host != "192.168.30.1":
      print("Host {} found".format(host))
      print("Host status {}".format(nm[host].state()))
      for port in nm[host]['tcp'].keys():
        if port == port_searched:
          print("TCP port {} found".format(port))
          InsertGuacamoleVM(host)
          hosts_found.append("'{}'".format(host))
  ClearGuacamoleVM(hosts_found) 
  return GetCurrentGuacamoleVM()
