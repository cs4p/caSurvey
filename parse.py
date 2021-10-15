import xml.etree.ElementTree as ET

shell_cmd = 'nmap --script=ssl-cert -p 443 -iL gov_domains.txt -oX gov_domains.xml'

tree = ET.parse('gov_domains.xml')
root = tree.getroot()
ca_list = []
for cert in root.iter('script'):
    s = cert.attrib['output']
    lines = s.split('\n')
    for line in lines:
        if line[0:20] == 'Subject: commonName=':
            # if '/' in line:
            #     hostname = line.split('/')[0]
            if '=' in line:
                hostname = line.split('=')[1].split('/')[0]
            else:
                hostname = line
        if line[0:7] == 'Issuer:':
            ca = line[7:].split('/')[0][12:]
    d = {'hostname': hostname,'ca':ca}
    ca_list.append(d)
f = open('ca_list.csv','w')
for l in ca_list:
    string = l['hostname']+','+l["ca"]+'\n'
    f.write(string)
f.close()
