Sample nmap scan with this script:
`nmap --open -n -sV -O --top-ports 100 --script=cpe.nse 10.202.208.1-20` (requires root)
Currently produces a lot of duplicate results which will be handled by later script.
