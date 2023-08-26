import concurrent.futures
import ipaddress

import nmap

targetlist = []


def target_list(ip_target):
    ip_list = ''
    for addr in ipaddress.IPv4Network(ip_target):
        ip_list = ip_list + ' ' + str(addr)
    ip_list = ip_list.split()
    del ip_list[-1]
    del ip_list[0]
    print(ip_list[0], '~', ip_list[-1])
    return ip_list


def scan_host(i):
    scan_range = nm.scan(hosts=i, arguments='-n -sP -PE -PA21,23,80,3389')
    scan_range = scan_range['scan'][i]
    scan_range = str(scan_range)
    print(scan_range)
    if scan_range.find("up") != -1:
        print(scan_range)
    else:
        pass

nm = nmap.PortScanner()

with concurrent.futures.ThreadPoolExecutor(max_workers=24) as executor:
    for i in target_list("192.168.0.0/24"):
        executor.submit(scan_host, i)
