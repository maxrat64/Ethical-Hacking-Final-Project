#!/usr/bin/python3

import multiprocessing
from multiprocessing import Process, Lock, Value
import subprocess
import sys
import xml.etree.ElementTree as ET
import ipaddress


base_cmd = ['nmap', '-n', '--open', '-sV', '--script=cpe.nse', '-O', '-oX', '-']
port_list = [100, 1000, 65535]

verbose = True

# Input: list of IP addresses or CIDR addresses
# Output: list of all included IP addresses
def input_to_addrs(in_args):

    result = []
    for addr_in in in_args:

        # If CIDR address
        if "/" in addr_in:
            net = ipaddress.ip_network(addr_in, strict=False)
            for addr in net.hosts():
                result.append(str(addr))

        # If lone IP address
        else:
            result.append(addr_in)

    return result

# Input: string of xml
def parse_xml(stream, cpes, total):

    # Get XML element from the input string
    root = ET.fromstring(stream)

    # finds the xml script tag that has the attribute id0 equal to 'cpe'
    cpe_out = root.find("./*/script[@id='cpe']")

    # If no script output (e.g. host down) then return early without
    if cpe_out is None:
        return

    # First table is host
    for host in cpe_out:
        ip = host.attrib["key"]

        # Next table lists ports
        for port_tab in host:
            port = port_tab.attrib["key"]

            # Final table lists cpe
            for cpe in port_tab:

                # Get IP, port, cpe triple
                trip = (ip, port, cpe.text)
                if trip not in cpes:

                    # Add cpe and update the total count
                    cpes.add(trip)
                    with total.get_lock():
                        total.value += 1

def do_scan(addrs, total):

    cpes=set()

    for ports in port_list:
        for addr in addrs:
            cmd = base_cmd + ["--top-ports", str(ports), addr]
            out = subprocess.check_output(cmd, text=True)

            parse_xml(out, cpes, total)

            if verbose:
                with total.get_lock():
                    print("%d ports done for %d hosts" % (ports, len(addrs)))
                    print("%d total cpes found" % total.value)
  

if __name__ == '__main__':

    
    if len(sys.argv) == 1:
        print("Usage: ./scan.py <IP address/IP block> ...")

    all_addrs = input_to_addrs(sys.argv[1:])
    
    # Use all but 1 cpu
    cpus = multiprocessing.cpu_count() - 1

    # Separate addresses by inputs
    addr_inputs = []
    for i in range(cpus):
        addr_input = all_addrs[i::cpus]
        addr_inputs.append(addr_input)


    if verbose:
        print("CPUs used: %d, Addresses: %d" % (cpus, len(all_addrs)))

    procs = []
    total = Value('i', 0)

    for addr_input in addr_inputs:
        p = Process(target=do_scan, args=(addr_input, total))
        procs.append(p)
        p.start()


    for p in procs:
        p.join()