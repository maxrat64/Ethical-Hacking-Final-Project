#!/usr/bin/env/python

# imports
import vals
import multiprocessing
import ipaddress

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

# Input: the arguments passed into this program
# Output: list of list of addresses to scan
def setup_input(inputs):

    # Get 
    all_addrs = input_to_addrs(inputs)

    # Use all but 1 cpu
    cpus = multiprocessing.cpu_count() - 1

    if vals.verbose:
        print("Max CPUs used: %d" % cpus)

    # Separate addresses by inputs
    addr_inputs = []
    for i in range(cpus):
        addr_input = all_addrs[i::cpus]
        if len(addr_input) > 0:
            addr_inputs.append(addr_input)
        
            if vals.verbose:
                print("CPU group %d: # Addresses: %d" % (i, len(addr_input)))


    if vals.verbose:
        print("Total Addresses: %d" % len(all_addrs))

    return addr_inputs