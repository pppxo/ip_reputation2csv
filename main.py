import time
import requests
import csv
import json
import os
from bs4 import BeautifulSoup

row = {}

def checkConnection():
    try:
        requests.get("http://google.com")
    except:
        print("No Internet Connetion!!!")
        exit()

def mkFile():
    with open('result.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "VT Harmless", "VT Malicious", "VT Suspicious", "VT Undetected", "VT Country", "IPvoid Result", "AbuseIPDB is Whitelisted?", "AbuseIPDB Confedence Score", "AbuseIPDB Total Reports", "AbuseIPDB Last Reported", "AbuseIPDB ISP", "AbuseIPDB Country"])
        file.close()


def writeToFile(ip):
    print("* Checking IP: "+ ip)
    checkVT(ip)
    checkIPvoid(ip)
    checkAbuseIP(ip)
    with open('result.csv', 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([ip, row.get("vt_harmless"), row.get("vt_malicious"), row.get('vt_suspicious'), row.get('vt_undetected'), row.get('vt_country'), row.get('iv_result'), row.get('aipdb_isWhitelisted'), row.get('aipdb_conscore'), row.get('aipdb_totalreports'), row.get('aipdb_lastreportted'), row.get('aipdb_isp'), row.get('aipdb_countrycode')])
        file.close()


def checkVT(ip):

    url = 'https://www.virustotal.com/ui/ip_addresses/'+ip
    headers = {
            'Cookie': '_ga=GA1.2.215640500.1618697245; _gid=GA1.2.1017450505.1619061042',
            'X-Tool': 'vt-ui-main',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.72 Safari/537.36',
            'Content-Type': 'application/json',
            'X-App-Version': 'v1x14x2',
            'Accept': 'application / json',
            'Accept-Ianguage': 'en-US,en;q=0.9,es;q=0.8',
            'X-Vt-Anti-Abuse-Header': 'MTc4Mjc4NTIyNDQtWkc5dWRDQmlaU0JsZG1scy0xNjE5MTA2MTk5LjYzOA==',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'Referer': 'https://www.virustotal.com/',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en-GB;q=0.9,en;q=0.8,ar-AE;q=0.7,ar;q=0.6',
            'Connection': 'close'
        }

    try:
        response = requests.get(url, headers=headers)
    except:
        print("We're facing some issues with VirusTotal site.")
        exit()

    result = json.loads(response.text)
    row["vt_harmless"]= result['data']['attributes']['last_analysis_stats']['harmless']
    row["vt_malicious"]= result['data']['attributes']['last_analysis_stats']['malicious']
    row["vt_suspicious"] = result['data']['attributes']['last_analysis_stats']['suspicious']
    row["vt_undetected"] = result['data']['attributes']['last_analysis_stats']['undetected']
    row["vt_country"] = result['data']['attributes']['country']




def checkIPvoid(ip):
    url = 'https://www.ipvoid.com/ip-blacklist-check/'
    header = {
        'Cookie': '_omappvp=vlhiib17C77EKoVK43jMPqBn0iNOjROub7DhAgKRjpnYYKG2zzW4jZZVTNQpSnPnfM8fzvXJ38XUdo0OtUzkHVcEFIegqPMM; _omappvs=1619229909836; _ga=GA1.2.1273756274.1619229909; _gid=GA1.2.1371677310.1619229910; _gat_gtag_UA_47951715_30=1; __gads=ID=985ca39a9cc66f40-22bd9462efc7004e:T=1619229909:RT=1619229909:S=ALNI_MbD14uMXKMTUg59HqxADCtZuhcEaQ; cookiebanner-accepted=1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.72 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Sec-Ch-Ua': 'Chromium";v="89", ";Not A Brand";v="99',
        'Sec-Ch-Ua-Mobile': '?0',
        'Upgrade-Insecure-Requests': '1',
        'Origin': 'https://www.ipvoid.com',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'document',
        'Referer': 'https://www.ipvoid.com/',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'close'
    }

    try:
        respond = requests.post(url,data={'ip':ip}, headers=header)
    except:
        print("We're facing some troubles with IPvoid site.")
        exit()

    soup = BeautifulSoup(respond.text, 'lxml')
    table = soup.find("table",{"class":"table table-striped table-bordered"}).find("span").text
    row["iv_result"] = table


def checkAbuseIP(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': '0f9487d7ce322b7871a98a6b49012eb002e85866378c1df80c87b34fc5283fb48f4e3ac0c4cf8d6c'
    }
    try:
        response = requests.get(url=url, headers=headers, params=querystring)
    except:
        print("We're facing some troubles with AbuseIPDB site.")
        exit()

    rslt = json.loads(response.text)
    row["aipdb_conscore"] = rslt["data"]["abuseConfidenceScore"]
    row["aipdb_isWhitelisted"] = rslt["data"]["isWhitelisted"]
    row["aipdb_totalreports"] = rslt["data"]["totalReports"]
    row["aipdb_lastreportted"] = rslt["data"]["lastReportedAt"]
    row["aipdb_isp"] = rslt["data"]["isp"]
    row["aipdb_countrycode"] = rslt["data"]["countryCode"]


checkConnection()
mkFile()
f = open("IPs.txt", "r")
for ip in f:
    time.sleep(1)
    writeToFile(ip.strip())
f.close()
print(os.system("result.csv"))
exit()
