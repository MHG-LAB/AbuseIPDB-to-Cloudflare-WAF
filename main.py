import json
import random
import socket
import requests
import time
import os
import yaml
import re
import sys

def load_config(path):
  f = open(path, 'r', encoding='utf-8')
  ystr = f.read()
  ymllist = yaml.load(ystr, Loader=yaml.FullLoader)
  return ymllist

if os.path.exists('config.yml'):
  c=load_config('config.yml')
  CLOUDFLARE_ACCOUNT_ID = c['CLOUDFLARE_ACCOUNT_ID']
  CLOUDFLARE_ZONE_ID = c['CLOUDFLARE_ZONE_ID']
  CLOUDFLARE_EMAIL = c['CLOUDFLARE_EMAIL']
  CLOUDFLARE_API_KEY = c['CLOUDFLARE_API_KEY']
  ABUSEIPDB_API_KEY = c['ABUSEIPDB_API_KEY']
else:
  CLOUDFLARE_ACCOUNT_ID = sys.argv[1]
  CLOUDFLARE_ZONE_ID = sys.argv[2]
  CLOUDFLARE_EMAIL = sys.argv[3]
  CLOUDFLARE_API_KEY = sys.argv[4]
  ABUSEIPDB_API_KEY = sys.argv[5]

def get_radom_ua():
  ua_list = [
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/22.0.1207.1 Safari/537.1",
    "Mozilla/5.0 (X11; CrOS i686 2268.111.0) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.57 Safari/536.11",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1092.0 Safari/536.6",
    "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1090.0 Safari/536.6",
    "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.83 Safari/537.1",]
  return ua_list[random.randint(0,len(ua_list)-1)]
  
  

cf_headers={"Content-Type":"application/json","X-Auth-Key":CLOUDFLARE_API_KEY,"X-Auth-Email":CLOUDFLARE_EMAIL,"User-Agent":get_radom_ua()}

def get_cf_data(url):
  global ttl
  ttl=ttl-1
  print("ttl:",ttl)
  if ttl<=0:
    return []
  if ttl<59:
    time.sleep(5)
  try:
    r=requests.get(url,headers=cf_headers)
    if type(r.json())==None or str(type(r.json())) != "<class 'dict'>":
      get_cf_data(url)
    else:
      return r.json()
  except Exception as e:
    get_cf_data(url)

def dele_cf_data(url,data):
  global ttl
  ttl=ttl-1
  print("ttl:",ttl)
  if ttl<=0:
    return []
  if ttl<59:
    time.sleep(5)
  try:
    if data:
      r=requests.delete(url,headers=cf_headers,data=data)
    else:
      r=requests.delete(url,headers=cf_headers)
    if type(r.json())==None or str(type(r.json())) != "<class 'dict'>":
      dele_cf_data(url,data)
    else:
      return r.json()
  except Exception as e:
    dele_cf_data(url,data)

def post_cf_data(url,data):
  global ttl
  ttl=ttl-1
  print("ttl:",ttl)
  if ttl<=0:
    return []
  if ttl<59:
    time.sleep(5)
  try:
    r=requests.post(url,headers=cf_headers,data=data)
    if type(r.json())==None or str(type(r.json())) != "<class 'dict'>":
      post_cf_data(url,data)
    else:
      return r.json()
  except Exception as e:
    post_cf_data(url,data)

def put_cf_data(url,data):
  global ttl
  ttl=ttl-1
  print("ttl:",ttl)
  if ttl<=0:
    return []
  if ttl<59:
    time.sleep(5)
  try:
    r=requests.put(url,headers=cf_headers,data=data)
    if type(r.json())==None or str(type(r.json())) != "<class 'dict'>":
      put_cf_data(url,data)
    else:
      return r.json()
  except Exception as e:
    put_cf_data(url,data)

def get_bad_ip_list():
  try:
    url = 'https://api.abuseipdb.com/api/v2/blacklist'
    querystring = {
        'confidenceMinimum':'90'
    }
    headers = {
      'Accept': 'application/json',
      'Key': ABUSEIPDB_API_KEY
    }
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    if response.status_code==200:
      decodedResponse = json.loads(response.text)
      print(json.dumps(decodedResponse, sort_keys=True, indent=4),file=open("./abuseipdb.json", "w"))
      list=decodedResponse['data']
      print("bad_ip_list_length:",len(list))
      return list
    else:
      print("error:",response.status_code)
      print(response.text)
      return []

  except Exception as e:
    print("error:",e)

def check_ipv4(ip):
  try:
    socket.inet_aton(ip)
    return True
  except socket.error:
    return False


print("==================== AbuseIPDB to Cloudflare WAF Start ====================")
w=False
x=False
ttl=60
a= get_cf_data("https://api.cloudflare.com/client/v4/zones/"+CLOUDFLARE_ZONE_ID+"/filters")
print(str(type(a)))
if str(type(a)) == "<class 'dict'>" and len(a)>0:
  print("filter_list_length:",len(a['result']))
  for i in a['result']:
    if 'ref' in i and i['ref'] == 'OHHHO':
      print(i["id"])
      w = i
      x = w
      break
  if w:
    # (ip.src in $block_ip)
    # (http.cookie eq "WAF-AbuseIPDB-WAF")
    a=re.findall(r'\(ip.src in \$block_ip\)',w['expression'])
    if len(a)>0:
      w['expression']=w['expression'].replace('(ip.src in $block_ip)','(http.cookie eq "WAF-AbuseIPDB-WAF")')
      ttl=60
      put_cf_data("https://api.cloudflare.com/client/v4/zones/"+CLOUDFLARE_ZONE_ID+"/filters",json.dumps([w]))
ttl=60
block_ip_list_id = False
a= get_cf_data("https://api.cloudflare.com/client/v4/accounts/"+CLOUDFLARE_ACCOUNT_ID+"/rules/lists")
print(str(type(a)))
if str(type(a)) == "<class 'dict'>" and len(a)>0:
  for i in a["result"]:
    if i['kind'] == "ip":
      block_ip_list_id=i['id']
      break
  if block_ip_list_id:
    print("block_ip_list_id:",block_ip_list_id)
    ttl=60
    a=dele_cf_data("https://api.cloudflare.com/client/v4/accounts/"+CLOUDFLARE_ACCOUNT_ID+"/rules/lists/"+block_ip_list_id,False)
    print(str(type(a)))
    ttl=60
    a=post_cf_data("https://api.cloudflare.com/client/v4/accounts/"+CLOUDFLARE_ACCOUNT_ID+"/rules/lists",json.dumps({"name":"block_ip","description":"This is block ip list.","kind":"ip"}))
    print(str(type(a)))
    block_ip_list_id=a['result']['id']
    print("block_ip_list_id2:",block_ip_list_id)
    if os.path.exists("./abuseipdb.json"):
      with open("./abuseipdb.json") as f:
        AbuseIPDBBlackList = json.load(f)['data']
      print("bad_ip_list_length:",len(AbuseIPDBBlackList))
    else:
      AbuseIPDBBlackList = get_bad_ip_list()
    if len(AbuseIPDBBlackList)>0:
      add_ip_list=[]
      for i in AbuseIPDBBlackList:
        if check_ipv4(i['ipAddress']):
          add_ip_list.append({"ip":i['ipAddress'],"comment":"AbuseIPDBBlackList"})
      print("add_ip_list_length:",len(add_ip_list))
      ttl=60
      r = post_cf_data("https://api.cloudflare.com/client/v4/accounts/"+CLOUDFLARE_ACCOUNT_ID+"/rules/lists/"+block_ip_list_id+"/items",json.dumps(add_ip_list))
      print(r)
  if x:
    # (ip.src in $block_ip)
    # (http.cookie eq "WAF-AbuseIPDB-WAF")
    a=re.findall(r'\(http.cookie eq "WAF-AbuseIPDB-WAF"\)',x['expression'])
    if len(a)>0:
      x['expression']=x['expression'].replace('(http.cookie eq "WAF-AbuseIPDB-WAF")','(ip.src in $block_ip)')
    ttl=60
    a=put_cf_data("https://api.cloudflare.com/client/v4/zones/"+CLOUDFLARE_ZONE_ID+"/filters",json.dumps([x]))
    print(str(type(a)))
print("==================== AbuseIPDB to Cloudflare WAF End ====================")


    # flag=True
    # while flag:
    #   ttl=60
    #   a= get_cf_data("https://api.cloudflare.com/client/v4/accounts/"+CLOUDFLARE_ACCOUNT_ID+"/rules/lists/"+block_ip_list_id+"/items")
    #   print(str(type(a)))
    #   if str(type(a)) == "<class 'dict'>" and len(a)>0:
    #     delete_ip_list=[]
    #     for i in a["result"]:
    #       if i['comment']=="AbuseIPDBBlackList":
    #         delete_ip_list.append({"id":i['id']})
    #     print("delete_ip_list_length:",len(delete_ip_list))
    #     if len(delete_ip_list)>0:
    #       ttl=60
    #       r= dele_cf_data("https://api.cloudflare.com/client/v4/accounts/"+CLOUDFLARE_ACCOUNT_ID+"/rules/lists/"+block_ip_list_id+"/items",'{"items":'+json.dumps(delete_ip_list)+'}')
    #       print(r)
    #     else:
    #       flag=False
    # AbuseIPDBBlackList = get_bad_ip_list()