#!/usr/local/bin/python3

import requests
import argparse
import re
import shodan
import socket
import json
from time import sleep
from jinja2 import FileSystemLoader, Environment
from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI
import pandas as pd



shodanAPI = "YOUR-API-KEY"
HunterIOAPI = "YOUR-API-KEY"
HIBPAPI = "YOUR-API-KEY"
virustotalApi = "YOUR-API-KEY"

externalhosts = []
emailist = []
subdomainnumber = 0
breachednum = 0
iplist = []

class externalHost(object):
    def __init__(self,IPaddress,subdomain):
        self.IPaddress = IPaddress
        self.subdomains = [subdomain]
        self.openports = []
        self.vulns = []

def host2ip(subdomain):
    try:
        ip = socket.gethostbyname(subdomain)
        return ip
    except:
        return "No IP"

def GetSubdomains(basedomain):

    VirusTotalURL = 'https://www.virustotal.com/vtapi/v2/domain/report'
    list_unique= []
    subdomains = []
    
    #DNSDumpster
    try:
        res = DNSDumpsterAPI().search(basedomain)
        for host in res['dns_records']['host']:
            subdomains.append(host['domain'])
    except:
        pass

    #VT
    try:
        params = {'apikey':virustotalApi,'domain':basedomain}
        response = requests.get(VirusTotalURL, params=params)
        data = response.json()
        for subdom in data['subdomains']:
            subdomains.append(subdom)
    except:
        pass

    #crt.sh
    try:
        crtshbase = "https://crt.sh/?q=%."

        url = crtshbase + basedomain

        response = requests.get(crtshbase + basedomain)
        data = response.content

        for cert, domain in re.findall('<tr>(?:\s|\S)*?href="\?id=([0-9]+?)"(?:\s|\S)*?<td>([*_a-zA-Z0-9.-]+?\.' + re.escape(basedomain) + ')</td>(?:\s|\S)*?</tr>', str(data), re.IGNORECASE):
                domain = domain.split('@')[-1]
                subdomains.append(domain)
    except:
        pass

    list_unique=set(subdomains)
    print("\033[1;33m [!] " + str(len(list_unique)) + " Subdomains found")
    return list_unique

def ShodanScan(host):
    
    api = shodan.Shodan(shodanAPI)
    try:
        hostinfo = api.host(host.IPaddress)
        for element in hostinfo['data']:
            port = str(element['port']) + "/" + element['transport']
            try:
                banner = element['data'].split("\n")[0]
                banner = banner.strip('\r')
            except:
                banner = 'N/A'
            tempdict = {'Port':port,'Banner':banner}
            host.openports.append(tempdict)
        
            try:
                for vuln in element['vulns']:
                    host.vulns.append(vuln)
            except:
                pass    
    except:
        pass

def haveibeenpwned(email):
    #needs paid api key
    headers = {'hibp-api-key': HIBPAPI}
    urlEndpoint = "https://haveibeenpwned.com/api/v3/breachedaccount/"
    global breachednum
    urlToFetch = urlEndpoint+email
    r = requests.get(urlToFetch, verify=True, headers=headers)
    sleep(1.5)
    try:
        if r.status_code == 404:
            return "Not Breached"
        else:
            breachlist = "Found in following Breach Lists: "
            for breach in r.json():
                breachlist += breach['Name'] + ", " 
            breachednum +=1
            return breachlist[:-2]
    except:
        return "Not Breached"

def GetEmails(domain):
    print("\033[0;32m [!] Getting Emails")
    response = None
    limit = 100
    global emailist
    try:
        url = "https://api.hunter.io/v2/domain-search?domain="+domain+"&api_key="+HunterIOAPI+"&limit="+str(limit)
        #Sent request
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            output = response.json()
        except Exception as excp:
            print("\033[0;31m [!] " + excp)
        # Manage the response
        try:
            for emailobject in output['data']['emails']:     
                try:
                    breached = haveibeenpwned(emailobject['value'])
                    position = emailobject['position']
                    emailist.append({'Email Address':emailobject['value'],'Position':position,'Breached?':breached})
                except:
                    pass
        except Exception as e:
            print("\033[0;31m [!] Could not find any information about that")
    except Exception as exception:
        print("\033[0;31m [!] Error in main function" + str(exception))

def GenerateReport(domain):
    print("\033[0;32m [!] Generating Report")
    global externalhosts
    global emaillist
    global subdomainnumber
    global iplist

    env = Environment(
    loader=FileSystemLoader(searchpath="Templates"))

    base_template = env.get_template("report.html")
    Footprint_section_template = env.get_template("external_Footprint_Section.html")
    
    title = domain
    sections = list()
    for host in externalhosts:
        df = pd.DataFrame(host.openports)
        pd.set_option('display.max_colwidth', 100)
        OpenPorthtml = df.to_html(index=False)
        OpenPorthtml = OpenPorthtml.replace("<table border=\"1\" class=\"dataframe\">", "<table class=\"w3-table w3-striped w3-bordered w3-border w3-hoverable w3-white\">")
        sections.append(Footprint_section_template.render(
            IP = "<h3 id=\"" + host.IPaddress + "\">" + host.IPaddress,
            Subdomains=host.subdomains,
            OpenPortsTable =OpenPorthtml,
            Vulnerabilities=host.vulns
        ))

    df = pd.DataFrame(emailist)
    pd.set_option('display.max_colwidth', 100)
    EmailTablehtml = df.to_html(index=False)
    EmailTablehtml = EmailTablehtml.replace("<table border=\"1\" class=\"dataframe\">", "<table class=\"w3-table w3-striped w3-bordered w3-border w3-hoverable w3-white\">")
    
    with open("Reports/"+ domain +"_SurfaceScan_report.html", "w") as f:
        f.write(base_template.render(
            title=title,
            listofips=iplist,
            sections=sections,
            EmailTable=EmailTablehtml,
            ExternalHostNumber=str(len(externalhosts)),
            SubdomainNumber=str(subdomainnumber),
            EmailAddressNum=str(len(emailist)),
            BreachedEmails=str(breachednum)

        ))
    print("\033[0;32m [!] Report created: ./Reports/"+ domain +"_SurfaceScan_report.html" )


if __name__ == "__main__":
    
    aparser = argparse.ArgumentParser(description='SurfaceScan', usage="\npython3 SurfaceScan.py -d domain")
    aparser.add_argument("-d", "--domain", type=str, nargs='+', help="domain to scan")
    args = aparser.parse_args()
    domain=args.domain[0]
    domain_check = re.compile("^(http|https)?[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$")
    if not domain_check.match(domain):
        print("\033[0;31m [!] Error: Please enter a valid domain")
        exit

    print("\033[0;32m [!] Identifying Subdomains of: " + domain)
    print("\033[0;31m [!]", end =" ")
    subdomains = GetSubdomains(domain)
    subdomainnumber = len(subdomains)
    
    

    #GET IP OF SUBDOMAINS
    for subdomain in subdomains:
        IPaddress = host2ip(subdomain)
        flag = False
        if len(externalhosts) > 0:
            for host in externalhosts:
                if host.IPaddress == IPaddress:
                    flag = True
                    host.subdomains.append(subdomain)              
            if flag == False:
                externalhosts.append(externalHost(IPaddress, subdomain))
        else:
            externalhosts.append(externalHost(IPaddress, subdomain))
    
    #SHODAN SCAN IP
    print("\033[0;32m [!] Checking Shodan")
    for host in externalhosts:
        if host.IPaddress != "No IP":
            ShodanScan(host)
            iplist.append("<a href=\"#" + host.IPaddress +"\" class=\"w3-bar-item w3-button w4-padding\">" + host.IPaddress+ "</a>")

    GetEmails(domain)
    GenerateReport(domain)
            



