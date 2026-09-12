# NETWORK SCANNER

A python tool that scans a local network and reports which hosts respond to ping. For this project, I used my local network

## Usage

Edit the `network` variable at the top of the script to match/suit your subnet: `network = "192.168.1."`
Then run: `python3 sweep.py`, which is the name of my python script
output: it should output a built top-to-bottom list of devices (their ip addresses) in that LAN that responded
`192.168.1.1 is up` ...


### How it works
The script loops over every host address in a /24 subnet (1 to 254) and builds a full IP address from the network prefix. For each address it uses
Python's `subprocess` module to run the system's `ping` command with a single packet and a one-second timeout.

Rather than parsing ping's text output the script checks its exit code. Linux programs return 0 on a success and non-zero on a failure, so a return
code of 0 means a reply came back. Ping's own output is sent to `DEVNULL` so only the script's results are printed.


## What I learned
Initially, the script silently found nothing. So I tested ping by hand to separate a network problem from a code problem.
It turned out that VirtualBox NAT could not answer pings, so I switched to Bridged Adapted. Even at that, the script printed nothing
and the bug was `"ip"`; I put the variable in quotes, thereby pasing a literal string.
Note: Ping's error message would have shown the problem immediately, but I was sending it to DEVNULL

## Limitations
- The subnet prefix is hardcoded and must be edited manually
- Scanning is sequential, so a full /24 sweep takes about 4 minutes: One address is checked at a time, and most of that is waiting on timeouts.
- A host that does not reply is not necessarily abesent. Many devices have firewalls that silently drop ICMP requests, so this is what answers,
not what exists (there may be more devices)

## Possible improvements
- run pings concurrently wit `concurrent.futures.ThreadPoolExecutor`.
- detect the local subnets automatically instead of having to hardcode it
- resolve MAC addresses from the ARP table to identify device manufacturers.


## Requirements

linux with `ping` available. Python3 standard library only
