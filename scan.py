#!/usr/bin/env python3

# imports (local)
import vals
from search import getCVEData

import subprocess
import xml.etree.ElementTree as ET

base_cmd = ['nmap', '-n', '--open', '-sV', '--script=cpe.nse', '-O', '-oX', '-']

def print_table(d):

    for ip in d.keys():
        ip_block = d[ip]
        for port in ip_block.keys():
            port_block = ip_block[port]
            for spec in port_block.keys():
                result_dict = port_block[spec]
                print("%s, %s, %s: %s" % (ip, port, spec, result_dict))

def add_cpe(cpe, d, l, man):

    # Get individual info from cpe
    ip, port, spec = cpe
    
    # Get search
    try:
        search = getCVEData(spec)
    except Exception:
        if vals.verbose:
            print("search failed or yielded no results. cpe: %s" % spec)
        return

    # Put into result dictionary
    result = man.dict()
    result["url"] = search[0]
    result["n_vulns"] = search[1]
    result["max"] = search[2]
    result["avg"] = search[3]

    # Acquire lock for modifying dictionary
    with l:
        # Make tables if they don't exist
        if ip not in d:
            d[ip] = man.dict()
        if port not in d[ip]:
            d[ip][port] = man.dict()

        # update result
        d[ip][port][spec] = result

        if vals.verbose:
            print("new entry in table: %s, %s, %s: %s" % (ip, port, spec, result))

# Input: string of xml, set of cpes, dict, lock
def parse_xml(stream, cpes, d, l, man):

    # Get XML element from the input string
    root = ET.fromstring(stream)

    # finds the xml script tag that has the attribute id0 equal to 'cpe'
    cpe_out = root.find("./*/script[@id='cpe']")

    # If no script output (e.g. host down) then return early without adding
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

                # Get IP, port, cpe triple and add it to table if it's new
                trip = (ip, port, cpe.text)
                if trip not in cpes:
                    add_cpe(trip, d, l, man)


# Called by main which spawns a process and executes this function
def do_scan(addrs, d, l, man):

    # keep set of cpes to they're only unique values (not shared)
    cpes=set()

    # Search increasingly larger number of ports so most common ones are first
    for ports in vals.port_list:
        for addr in addrs:
            cmd = base_cmd + ["--top-ports", str(ports), addr]
            out = subprocess.check_output(cmd, text=True)

            parse_xml(out, cpes, d, l, man)
        
        if vals.verbose:
            print("%d ports completed for %d hosts" % (ports, len(addrs)))
