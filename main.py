import pandas as pd
import nmap
import ipaddress
from tabulate import tabulate
import sys
import time

def syn_scan(r):
    host_arg =r
    ps = nmap.PortScanner()
    syn = ps.scan(host_arg, arguments='-T5 -g 80 -sS --top-ports=1000')
    return syn

def parse_syn_data(syn):
    scan = syn
    status_dict = {}
    for ip in scan['scan'].keys():
        if 'tcp' in scan['scan'][ip].keys():
            for port in scan['scan'][ip]['tcp'].keys():
                if scan['scan'][ip]['tcp'][port]['state'] == 'open':
                    if ip not in status_dict.keys():
                        status_dict[ip] = [port]
                    else:
                        status_dict[ip].append(port)
    return status_dict


def count_live_in_range(portscan, ranges):
    range_count = {}
    for i in ranges:
        range_count[i] = 0
    l_of_ips = []
    for ip in portscan.keys():
        if '/' not in ip:
            convert_ip = ipaddress.ip_address(ip)
            l_of_ips.append(convert_ip)

    l_of_ranges = []
    for range in ranges:
        x = ipaddress.ip_network(range, False)
        l_of_ranges.append(x)

    for eachRange in l_of_ranges:
        for eachIP in l_of_ips:
            if eachIP in eachRange.hosts():
                range_count[str(eachRange)] = range_count[str(eachRange)] + 1

    for ip_range, count in range_count.items():
        range_count[ip_range] = [(str(count))]

    return range_count



def get_targets():
    full_list = []
    with open("targets.list") as f:
        ranges = f.readlines()
        for range in ranges:
            range_ = range.strip()
            if range_ in full_list:
                pass
            else:
                full_list.append(range_)
        return full_list
            


nm = nmap.PortScanner()
string_ranges=get_targets()
ss = syn_scan(' '.join(string_ranges))
syn_data = parse_syn_data(ss)
new_d = {}
for ip, ports in syn_data.items():
    new_d[ip] = ''.join(str(ports).strip('[]'))

df = pd.DataFrame.from_dict(new_d, orient='index', columns=['OPEN PORTS'])
print(tabulate(df, headers=('LIVE NODE', 'OPEN PORT(S)'), tablefmt='grid'))

df2 = pd.DataFrame.from_dict(count_live_in_range(ss['scan'], string_ranges), orient='index')
print(tabulate(df2, headers=('IP RANGE', 'LIVE HOST COUNT'), tablefmt='grid'))

