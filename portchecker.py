import socket                                  # OS networking - lets us open TCP connections
import sys                                     # command-line arguments and exit codes
import time                                    # measuring how long the scan takes
import sqlite3                                 # built-in database engine, stored in one file
import subprocess                              # to run ss, the same way sweep.py runs ping
import re                                      # regular expressions, for parsing ss's output
from datetime import datetime                  # for timestamping each scan
from concurrent.futures import ThreadPoolExecutor   # runs many checks at once

DB_FILE = "inventory.db"                       # the database file, created on first run


# ---------------------------------------------------------------------------
# Argument handling
# ---------------------------------------------------------------------------

# sys.argv[0] is the script name, so a valid call has at least 3 items.
if len(sys.argv) < 3:
    print("Usage: python3 portchecker.py <host> <ports>")
    print("Example: python3 portchecker.py 127.0.0.1 22 80 8000")
    print("Example: python3 portchecker.py 127.0.0.1 1-1024")
    sys.exit(1)                                # non-zero exit code = "this failed"

host = sys.argv[1]                             # first argument is the target


def parse_ports(args):
    """Turn command-line arguments into a flat list of port numbers.
    Accepts single ports ('80') and ranges ('1-1024'), mixed freely."""
    ports = []
    for arg in args:
        if "-" in arg:                         # it's a range
            start, end = arg.split("-")        # "1-1024" -> ["1", "1024"]
            # +1 because range() excludes its upper bound
            ports.extend(range(int(start), int(end) + 1))
        else:                                  # it's a single port
            ports.append(int(arg))             # argv gives strings; sockets need ints
    return ports


ports = parse_ports(sys.argv[2:])              # [2:] = everything after the host


# ---------------------------------------------------------------------------
# The scan itself
# ---------------------------------------------------------------------------

def check(port):
    """Try to open a TCP connection to one port.
    Returns the port number if something is listening, otherwise None."""
    # AF_INET = IPv4, SOCK_STREAM = TCP (the protocol with the handshake)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)                            # give up after 1s rather than hang

    # connect_ex attempts the handshake and RETURNS an error code instead of
    # raising. 0 = connected. 111 = refused (host replied, nothing listening).
    code = s.connect_ex((host, port))          # one argument: a (host, port) tuple

    s.close()                                  # release the file descriptor

    if code == 0:
        return port
    return None                                # deliberate "nothing here"


# ---------------------------------------------------------------------------
# Who owns each listening port (localhost only)
# ---------------------------------------------------------------------------

def get_listening_processes():
    """Ask the OS which process is holding each listening TCP port.
    Returns a dict like {8000: 'python3 (pid 4821)'}.
    Only meaningful for our own machine - you cannot see process
    names on somebody else's host."""

    try:
        # -t TCP, -l listening sockets only, -n numeric, -p show the process
        result = subprocess.run(
            ["ss", "-tlnp"],
            capture_output=True,               # we want to READ the output this time
            text=True                          # return a string rather than raw bytes
        )
    except FileNotFoundError:                  # ss isn't installed - give up quietly
        return {}

    processes = {}

    for line in result.stdout.splitlines()[1:]:   # [1:] skips the header row
        # Address column looks like 0.0.0.0:8000 or [::]:631.
        # The port is the digits following a colon.
        match = re.search(r':(\d+)\s', line)
        if not match:
            continue                           # not the shape we expected; skip it
        port = int(match.group(1))             # group(1) is the part inside the brackets

        # Process column looks like: users:(("python3",pid=4821,fd=3))
        proc = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
        if proc:
            processes[port] = f"{proc.group(1)} (pid {proc.group(2)})"

    return processes


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def save_scan(host, open_ports):
    """Write this scan and its results to the database.
    Returns the id SQLite assigned to this scan."""

    conn = sqlite3.connect(DB_FILE)            # opens the file, creating it if absent
    cur = conn.cursor()                        # the cursor is what actually runs SQL

    # Two tables: one row per scan, one row per open port found in it.
    # IF NOT EXISTS makes these safe to run every time.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT NOT NULL,
            scanned_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS open_ports (
            scan_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    # The ? marks are placeholders; the values go in as a separate tuple.
    # Never build SQL by joining strings - that is how SQL injection happens.
    cur.execute(
        "INSERT INTO scans (host, scanned_at) VALUES (?, ?)",
        (host, datetime.now().isoformat(timespec="seconds"))
    )

    scan_id = cur.lastrowid                    # the id SQLite just gave that row

    for port in open_ports:
        cur.execute(
            "INSERT INTO open_ports (scan_id, port) VALUES (?, ?)",
            (scan_id, port)
        )

    conn.commit()                              # nothing is actually written until this
    conn.close()
    return scan_id


def get_previous_scan(host, before_scan_id):
    """Find the most recent EARLIER scan of this host and return the set of
    ports that were open in it. Returns None if this host has never been
    scanned before."""

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    # Newest scan of this host that isn't the one we just saved.
    # ORDER BY id DESC puts the highest id first; LIMIT 1 takes just that one.
    cur.execute("""
        SELECT id FROM scans
        WHERE host = ? AND id < ?
        ORDER BY id DESC
        LIMIT 1
    """, (host, before_scan_id))

    row = cur.fetchone()                       # one row, or None if nothing matched

    if row is None:                            # no earlier scan - this is the first
        conn.close()
        return None

    previous_id = row[0]                       # fetchone returns a tuple

    cur.execute("SELECT port FROM open_ports WHERE scan_id = ?", (previous_id,))

    # fetchall gives [(80,), (631,), ...] - pull the number out of each
    ports = {r[0] for r in cur.fetchall()}

    conn.close()
    return ports


# ---------------------------------------------------------------------------
# Run the scan
# ---------------------------------------------------------------------------

start_time = time.time()                       # seconds since 1970, taken before

# Threads help because this work is waiting, not computing.
with ThreadPoolExecutor(max_workers=100) as executor:
    results = list(executor.map(check, ports))  # one call per port, order preserved

open_ports = [p for p in results if p is not None]   # drop the Nones

# Process names only make sense when scanning our own machine.
# For a remote host we leave the dict empty and print ports alone.
if host in ("127.0.0.1", "localhost", "::1"):
    processes = get_listening_processes()
else:
    processes = {}

print("Scanned", len(ports), "ports on", host,
      "in", round(time.time() - start_time, 2), "seconds")

if open_ports:
    for port in open_ports:
        owner = processes.get(port)            # .get returns None if the key is absent
        if owner:
            print("  ", port, "open  -", owner)
        else:
            print("  ", port, "open")
else:
    print("   no open ports found")


# ---------------------------------------------------------------------------
# Record this scan, then compare it against the previous one
# ---------------------------------------------------------------------------

scan_id = save_scan(host, open_ports)              # write to the database
print("Saved as scan", scan_id, "in", DB_FILE)

previous = get_previous_scan(host, scan_id)        # ports open last time, or None

if previous is None:
    # Nothing to diff against yet - this run becomes the baseline.
    print("First scan of", host, "- nothing to compare against yet.")
else:
    current = set(open_ports)                      # list -> set, so we can subtract

    # Set subtraction: everything in the left set that isn't in the right one.
    newly_open = current - previous                # open now, wasn't before
    newly_closed = previous - current              # was open before, isn't now

    # An empty set is falsy, so this means "if either has anything in it".
    if newly_open or newly_closed:
        print("\nChanges since last scan:")        # \n prints a blank line first
        for port in sorted(newly_open):            # sorted() because sets have no order
            owner = processes.get(port)
            if owner:
                print("   +", port, "NEWLY OPEN  -", owner)
            else:
                print("   +", port, "NEWLY OPEN")
        for port in sorted(newly_closed):
            print("   -", port, "closed since last scan")
    else:
        print("\nNo change since last scan.")
