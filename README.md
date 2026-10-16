# Network Inventory Scanner

Two Python tools for answering a question most networks can't answer about
themselves: **what is listening here, and what changed since last time?**

Built on an Ubuntu VM as a way of learning networking from the socket up,
rather than by reading about it.

---

## Why

Organisations lose track of their own machines. A test server gets spun up
and forgotten. A port is opened for debugging and never closed. A large
share of real breaches begin at exactly that kind of forgotten door.

`nmap` already scans better than anything here. What this adds is memory:
every scan is recorded, and each run reports what opened or closed since
the last one. "Port 9000 is open" is information. "Port 9000 **was not open
yesterday**" is a question somebody needs to answer.

---

## The tools

### `sweep.py` — who is on this network?

Pings every address in a range and reports which ones reply.

```bash
python3 sweep.py 192.168.1.
```

Runs 50 pings concurrently. Sequential, the same scan took around six
minutes; threaded it finishes in about six seconds, because the work is
waiting rather than computing.

### `portchecker.py` — what is that machine running, and what changed?

Attempts a TCP connection to each port given. Anything that completes the
handshake has a service behind it. Results are written to SQLite and
compared against the previous scan of the same host.

```bash
# single ports
python3 portchecker.py 127.0.0.1 22 80 8000

# a range
python3 portchecker.py 127.0.0.1 1-10000

# mixed
python3 portchecker.py 127.0.0.1 22 80 8000-8010
```

Example output:
Scanned 10000 ports on 127.0.0.1 in 0.68 seconds
80 open
631 open
8000 open
Saved as scan 7 in inventory.db

Changes since last scan:
9000 closed since last scan


---

## How the change detection works

Two tables in `inventory.db`:

- `scans` — one row per run: id, host, timestamp
- `open_ports` — one row per open port, carrying the id of the scan it
  belongs to

Each run looks up the most recent earlier scan of the same host, pulls its
ports into a set, and subtracts:

```python
newly_open   = current - previous
newly_closed = previous - current
```

Change detection is set subtraction. Written with lists and loops it would
be fifteen lines with an off-by-one bug hiding in it.

---

## Scope

Point this at machines you own or have written permission to test.

Completing a TCP handshake against someone else's host is unauthorised
access under Nigeria's Cybercrimes Act and equivalent laws elsewhere, and
your IP address is in their logs either way. `scanme.nmap.org` exists for
practice.

---

## What I learned

**The scanner found nothing, and the network wasn't the problem.**
First run returned no hosts at all. I'd assumed the code was broken, but
pinging by hand showed the VM was on VirtualBox NAT, where the emulated
gateway doesn't answer pings. Switching to Bridged Adapter gave me a real
address on the LAN. The lesson wasn't about VirtualBox — it was to test
the network and the code separately instead of guessing which one failed.

**Then it found nothing again, and that time it was the code.**
I had passed `"ip"` in quotes inside the subprocess list, sending the
literal string instead of the variable. The error explaining this was
being sent to `DEVNULL` and I never read it. Silencing output is
convenient until you need it.

**Refused is not the same as timed out.**
A refused connection means the host answered and nothing is listening —
a closed door. A timeout means nothing answered at all — a wall, usually a
firewall silently dropping packets. The distinction tells you which layer
the problem is on.

**Three SQL errors in a row, each pointing at the exact problem.**
`near "VALUE": syntax error` was a missing S. `no such table: open_ports`
was a CREATE TABLE block I'd skipped. `no such column: ports` was a plural
I'd invented. Each message named the failure precisely; the work was
reading past the traceback to the last line.

**Scanning my own machine found two services I didn't know about.**
Ports 80 and 631 were open before I started anything. 631 is CUPS, the
printing system. 80 was a web server pulled in as a dependency by
something I'd installed. That's the entire point of the tool, demonstrated
on the first real run.

---

## Limitations

- No input validation. A malformed prefix or port produces a Python
  traceback rather than a useful message.
- TCP only — no UDP scanning.
- Ports are identified by number, not by service. `80 open` not
  `80 open — Apache/2.4.58`.
- `sweep.py` relies on ICMP, so hosts configured not to answer pings are
  invisible to it.
- No scheduling. It runs when you run it.

---

## Requirements

Python 3, standard library only. No installation.
