#!/usr/bin/python3

import subprocess
import sys
import xml.etree.ElementTree as ET
import ipaddress

# output flags
debug=True
version=False

detected_cpes = set()

base_cmd = ['nmap']
options = ['-n', '--open', '-sV', '--script=cpe.nse', '-O']

def parse_xml(stream):
    tree=ET.parse(stream)
    root = tree.getroot()

    # finds the xml script tag that has the attribute id0 equal to 'cpe'
    cpe_out = root.find("./*/script[@id='cpe']")

    for host in cpe_out:
        ip = host.attrib["key"]
        for port_tab in host:
            port = port_tab.attrib["key"]
            for cpe in port_tab:
                trip = (ip, port, cpe.text)
                if trip not in detected_cpes:
                    detected_cpes.add(trip)
                    print(trip)

def scan_host(address, top_ports):

    cmd = base_cmd + options + ["--top-ports", str(top_ports), address]

    if debug:
        print('Doing scan_host')
        print('Command used: %r' % cmd)

    proc = subprocess.run(cmd)

    print(proc.stdout)


# Input: list of IP addresses or CIDR addresses
# Output: list of all included IP addresses
def input_to_addrs(in_args):
    # assert(type(input) == type(""))

    result = []
    for addr_in in in_args:
        local_result = [""]
        print("addr_in:")
        print(addr_in)
        if "/" in addr_in:
            net = ipaddress.ip_network(addr_in, strict=False)
            for addr in net.hosts():
                result.append(str(addr))
        else:
            result.append(addr_in)

    return result



if __name__ == '__main__':

    if version:
        print(f'Python version: %s' % sys.version)

    # scan_host("127.0.0.1")
    addrs = input_to_addrs(["192.168.1.0/24"])
    for addr in addrs:
        scan_host(addr, 100)
    #print(addrs)
    #parse_xml("out.xml")

