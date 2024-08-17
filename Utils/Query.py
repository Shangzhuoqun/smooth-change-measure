import subprocess
from typing import Tuple
from Config.Config import Conf

RootServers = [
    ['a.root-servers.net.', '198.41.0.4'],
    ['b.root-servers.net.', '170.247.170.2'],
    ['c.root-servers.net.', '192.33.4.12'],
    ['d.root-servers.net.', '199.7.91.13'],
    ['e.root-servers.net.', '192.203.230.10'],
    ['f.root-servers.net.', '192.5.5.241'],
    ['g.root-servers.net.', '192.112.36.4'],
    ['h.root-servers.net.', '198.97.190.53'],
    ['i.root-servers.net.', '192.36.148.17'],
    ['j.root-servers.net.', '192.58.128.30'],
    ['k.root-servers.net.', '193.0.14.129'],
    ['l.root-servers.net.', '199.7.83.42'],
    ['m.root-servers.net.', '202.12.27.33'],
]

def dig(cmdline):
    for _ in range(Conf.MaxTimes):
        sub = subprocess.Popen(cmdline, stdout=subprocess.PIPE, shell=True)
        sub.wait()

        lines = [line.decode().rstrip().lower().replace('\t', ' ') for line in sub.stdout.readlines()]
        res = []
        flag = False
        for line in lines:
            if line == '':
                flag = False
                continue
            elif 'answer section' in line:
                flag = True
                continue
            elif 'authority section' in line:
                flag = True
                continue
            elif 'additional section' in line:
                flag = True
                continue
            if flag:
                res.append(line)
        if len(res) != 0:
            return res

    return []

def unique(x: list):
    x.sort()
    k = 0
    for i in range(len(x)):
        if i == 0 or x[i] != x[i - 1]:
            x[k] = x[i]
            k += 1
    del x[k:]

def GetAuthFromSuper(domain) -> Tuple[list, int, dict]:
    
    ns_ip = dict()

    def recurse(domain, servers):
        flag = False
        servernames = []
        ttl = 3600*24*365
        details = dict() # 各个上级给出的应答
        for sname, sip in servers:
            cmd = f'dig @{sip} {domain} ns +all'
            lines = dig(cmd)
            tempns = []
            tempnsip = dict()
            for line in lines:
                attrs = line.split()
                ttype = attrs[3]
                curttl = int(attrs[1])
                if ttype == 'ns':
                    ttl = min(ttl, curttl)
                    servernames.append(attrs[4])
                    tempns.append(attrs[4])
                    if attrs[0] == domain:
                        flag = True
                elif ttype == 'a':
                    ttl = min(ttl, curttl)
                    if attrs[0] not in ns_ip:
                        ns_ip[attrs[0]] = {attrs[4]}
                    else:
                        ns_ip[attrs[0]].add(attrs[4])
                    if attrs[0] not in tempnsip:
                        tempnsip[attrs[0]] = {attrs[4]}
                    else:
                        tempnsip[attrs[0]].add(attrs[4])
        
            unique(tempns)
            resp = []
            for tns in tempns:
                if tns in tempnsip:
                    resp.extend([tns, tip] for tip in tempnsip[tns])
            details[f'{sname} {sip}'] = resp
            
        unique(servernames)
        nss = []
        for ns in servernames:
            if ns in ns_ip:
                nss.extend([[ns, ip] for ip in ns_ip[ns]])
            else:
                ips, curttl = getIPStartWithRoot(ns, servers)
                if len(ips) != 0:
                    ttl = min(ttl, curttl)
                    nss.extend([[ns, ip] for ip in ips])

        return (nss, ttl, details) if (flag or len(nss) == 0) else recurse(domain, nss)
    
    return recurse(domain.lower(), RootServers)

def getIPStartWithRoot(domain):
    ns_ip = dict()

    def recurse(domain, servers):
        flag = False
        servernames = []
        ttl = 3600*24*365
        for sname, sip in servers:
            cmd = f'dig @{sip} {domain} a'
            lines = dig(cmd)
            tempns = []
            tempnsip = dict()
            for line in lines:
                attrs = line.split()
                ttype = attrs[3]
                curttl = int(attrs[1])
                if ttype == 'ns':
                    ttl = min(ttl, curttl)
                    servernames.append(attrs[4])
                    tempns.append(attrs[4])
                elif ttype == 'a':
                    ttl = min(ttl, curttl)
                    if attrs[0] not in ns_ip:
                        ns_ip[attrs[0]] = {attrs[4]}
                    else:
                        ns_ip[attrs[0]].add(attrs[4])
                    if attrs[0] not in tempnsip:
                        tempnsip[attrs[0]] = {attrs[4]}
                    else:
                        tempnsip[attrs[0]].add(attrs[4])
                    if attrs[0] == domain:
                        flag = True
        
            unique(tempns)
            resp = []
            for tns in tempns:
                if tns in tempnsip:
                    resp.extend([tns, tip] for tip in tempnsip[tns])
            
        unique(servernames)
        nss = []
        for ns in servernames:
            if ns in ns_ip:
                nss.extend([[ns, ip] for ip in ns_ip[ns]])
        return (ns_ip[domain], ttl) if (flag == True or len(nss) == 0) else recurse(domain, nss)

    return recurse(domain, RootServers)
    

def getIPFromAuth(name, nsip) -> Tuple[list, int]:
    ns, ip = nsip
    cmd = f'dig @{ip} {name} a'
    res = dig(cmd)
    ips = []
    ttl = 3600*24*365
    for line in res:
        attrs = line.split()
        curttl = int(attrs[1])
        if attrs[3] == 'a' and attrs[0] == name.lower():
            ttl = min(ttl, curttl)
            ips.append(attrs[4])

    unique(ips)
    
    return ips, ttl

def getIPFromAuths(name, nsips) -> Tuple[list, int]:
    ips = []
    ttl = 3600*24*365
    for nsip in nsips:
        tips, tttl = getIPFromAuth(name, nsip)
        if len(tips) != 0:
            ttl = min(ttl, tttl)
            ips.extend(tips)
    
    unique(ips)
    return ips, ttl

def GetAuthFromAuth(domain, nsip) -> Tuple[list, int]:
    ns, ip = nsip
    cmd = f'dig @{ip} {domain} ns'
    res = dig(cmd)
    ttl = 3600*24*365
    servernames = []
    for line in res:
        attrs = line.split()
        curttl = int(attrs[1])
        if attrs[3] == 'ns' and attrs[0] == domain.lower():
            ttl = min(ttl, curttl)
            servernames.append(attrs[4])
    
    nss = []
    for ns in servernames:
        cmd = f'dig @{ip} {ns} a'
        res = dig(cmd)
        for line in res:
            attrs = line.split()
            curttl = int(attrs[1])
            if attrs[3] == 'a' and attrs[0] == ns:
                ttl = min(ttl, curttl)
                nss.append([ns, attrs[4]])
    unique(nss)
    return nss, ttl

def GetAuthFromAuths(domain, nsips) -> Tuple[list, int, dict]:
    nss = []
    ttl = 3600*24*365
    details = dict()
    for nsip in nsips:
        tnss, tttl = GetAuthFromAuth(domain, nsip)
        details[f'{nsip[0]} {nsip[1]}'] = tnss
        ttl = min(ttl, tttl)
        nss.extend(tnss)
    unique(nss)
    return nss, ttl, details

# nss = GetAuthFromSuper("cn.")
# print(GetAuthFromAuths('cn.', nss))