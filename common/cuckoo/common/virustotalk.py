import requests
import json
import execjs
import base64
import time
 
from pprint import pprint
from random import randrange

def convert_leaves_to_string(obj):
  if isinstance(obj, dict):
    return {key: convert_leaves_to_string(value) for key, value in obj.items()}
  elif isinstance(obj, list):
    return [convert_leaves_to_string(element) for element in obj]
  else:
    return str(obj)

class VirusTotal:
 
  def __init__(self):
    self.url = "https://www.virustotal.com/{}"
    self.virustotal_cookies = cookies = {
      '_ga_BLNDV9X2JR': 'GS1.1.1717576452.39.1.1717576854.0.0.0',
      '_ga': 'GA1.2.1169951016.1704279517',
      '_ga_1R8YHMJVFG': 'GS1.1.1714652776.3.0.1714652784.0.0.0',
      '__gsas': 'ID=79a4a8fd03f29f9b:T=1712063204:RT=1712063204:S=ALNI_Maz-ZYDcSc1EgL1DpHgz3-ivVxxrg',
      'new-privacy-policy-accepted': '1',
      'ssm_au_c': 'k9UToAOr0Mqb8mnL8w3ck83XEpOB9aA+oY5alc21plKQgAAAAFiKHoOIczxzLLmP3fNNH8tb/FJZ1FoeD2BJoVHptZaM=',
      'ssm_au_d': '1',
      '_gid': 'GA1.2.1975526599.1717570596',
      '_gat': '1',
    }

    self.request_headers = {
      'Accept': 'application/json',
      'Accept-Language': 'en-US,en;q=0.5',
      'Accept-Encoding': 'gzip, deflate, br',
      'Referer': 'https://www.virustotal.com/',
      'content-type': 'application/json',
      'X-Tool': 'vt-ui-main',
      'x-app-version': 'v1x28x5',
      'Accept-Ianguage': 'en-US,en;q=0.9,es;q=0.8',
      'Sec-Fetch-Dest': 'empty',
      'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Site': 'same-origin',
      'Connection': 'keep-alive',
    }

    self.user_agents = [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:126.0) Gecko/20100101 Firefox/126.0',
      'Mozilla/5.0 (X11; Linux i686; rv:126.0) Gecko/20100101 Firefox/126.0',
      'Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0',
      'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:126.0) Gecko/20100101 Firefox/126.0',
      'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0',
      'Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.2535.85',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.2535.85'
    ]

  def generateAntiAbuseHeader(self):
    js='''
    function get_anti(){
      e1 = 1e10 * (1 + Math.random() % 5e4);
      if(e1 < 50) e1 = "-1";
      else e1 = e1.toFixed(0);
      e2 = "ZG9udCBiZSBldmls";
      e3 = Date.now() / 1e3;
      return (e1 + "-" + e2 + "-" + e3);
    }
    '''
    return base64.b64encode(execjs.compile(js).call('get_anti').encode('ascii'))

  def generateUserAgentHeader(self):
    return self.user_agents[randrange(0, len(self.user_agents))]

  def createHeaders(self):
    self.request_headers['X-VT-Anti-Abuse-Header'] = self.generateAntiAbuseHeader()
    self.request_headers['User-Agent'] = self.generateUserAgentHeader()

  def request(self, pattern):
    self.createHeaders()
    response = requests.get(self.url.format(pattern), headers=self.request_headers, cookies=self.virustotal_cookies)
    hits = {}
    try:
      hits = json.loads(response.content)
      stats = hits['data']['attributes']['last_analysis_stats']
      avs = hits['data']['attributes']['last_analysis_results']
      return {
        'error': 'ok',
        'hits': hits,
        'stats': stats,
        'avs': avs
      }
    except Exception as e:
      return {
        'error': 'ko',
        'msg': e,
        'hits': hits
      }

def fileinfo_request(file_hash):
  return VirusTotal().request("/ui/file/{}".format(file_hash))

def urlinfo_request(url):
  return VirusTotal().request("/ui/url/{}".format(url))

def ipinfo_request(ip):
  return VirusTotal().request("/ui/ip_addresses/{}".format(ip))
