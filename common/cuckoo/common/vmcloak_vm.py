import nmap

def GetLiveVM():
  port_searched = 3389
  ritorno = []
  nm = nmap.PortScanner()
  nm.scan('192.168.30.0/24', "{}".format(port_searched))
  for host in nm.all_hosts():
    if host != "192.168.30.1":
      print("Trovato host {}".format(host))
      print("Stato {}".format(nm[host].state()))
      for port in nm[host]['tcp'].keys():
        if port == port_searched:
          ritorno.append({"ip": host})
          print("Trovata porta {}".format(port))
  return ritorno
