#!/usr/bin/env python3

# imports (local)
import vals
from scan_utils import setup_input
from scan import do_scan, print_table
from gui import display

# imports (py modules)
import sys
from multiprocessing import Manager, Process

if __name__ == '__main__':

    # Need at least one argument specifying address(es) to scan
    if len(sys.argv) == 1:
        print("Usage: ./main.py <IP address/IP block> ...")

    # get lists of lists of addresses
    addr_inputs = setup_input(sys.argv[1:])

    # Get manager process which will keep track of all cpes
    with Manager() as manager:

        # list of processes, dict with all cpe info and lock for dict
        procs = []
        d = manager.dict()
        l = manager.Lock()

        # p = Process(target=display, args=(d, l))

        # make a process for each input
        for addr_input in addr_inputs:
            p = Process(target=do_scan, args=(addr_input, d, l, manager))
            procs.append(p)
            p.start()

        # join processses to end
        for p in procs:
            p.join()
        
        display(d)
        
    
