import requests
import json
import execjs
import base64
import time

from random import randrange
from cuckoo.common.config import cfg
from ..abtracts import Processor

class VirustotalNoAPIKey(Processor):

  CATEGORY = ["file", "url"]
  KEY = "virustotal"

  @classmethod
  def enabled(cls):
    api_key = cfg("virustotal", "key", subpkg="processing")
    if api_key != "":
      return False
    return cfg("virustotal", "enabled", subpkg="processing")

  def init(self):
    self.url = cfg("virustotal", "url_noapikey", subpkg="processing")
    self.user_agents = cfg("virustotal", "user_agents", subpkg="processing")
    self.virustotal_cookies = cfg("virustotal", "cookies", subpkg="processing")
    self.virustotal_request_headers = cfg("virustotal", "request_headers", subpkg="processing")

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
    self.request_headers = self.virustotal_request_headers.copy()
    self.request_headers['X-VT-Anti-Abuse-Header'] = self.generateAntiAbuseHeader()
    self.request_headers['User-Agent'] = self.generateUserAgentHeader()

  def request(self, pattern):
    self.createHeaders()
    response = requests.get(self.url.format(pattern), headers=self.request_headers, cookies=self.virustotal_cookies)
    avs = {}
    try:
      r = json.loads(response.content)
      for row in r['data']:
        for av in row['attributes']['last_analysis_results']:
          avs[av] = row['attributes']['last_analysis_results'][av]
      return {'avs':avs}
    except e:
      self.ctx.log.warning("Error while making VirustotalNoAPI request", error=e)
      return {}

  def start(self):
    if self.ctx.analysis.category == "file":
      return self.request(self.ctx.result.get("target").sha256)
    elif self.ctx.analysis.category == "url":
      return self.request(self.ctx.result.get("target").url)
