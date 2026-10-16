import socket	# this let's us open TCP connections
import sys	# this would be used to get command line arguments and exit codes
import time	# thsi would be used to measure how long the scan takes
import sqlite3	# this is the built-in database engine
from concurrent.futures import ThreadPoolExecutor # this would be used to run many checks concurrently
from datetime import datetime	# for timestampin each scan

DB_FILE = "inventory.db"	#the database file creation

# this conditional checks to ensure  that the arguments passed contains at least 3 items
if len(sys.argv) < 3:
	print("Usage: python3 portchecker.py <host> <port> [port ...]")
	print("Example: python3 portchecker.py 127.0.0.1 22 80 8000 9999")
	print("Example: python3 portchecker.py 127.0.0.1 1-1024")
	sys.exit(1)

host = sys.argv[1]	#to target the first argument
def parse_ports(args):
	""" This is a function to turn command-line arguments into a flat list of port numbers.
	Accepts single ports (eg 80 or 22) and ranges *(eg 1-1024) """
	ports = []
	for arg in args:
		if "-" in arg:
			start, end = arg.split("-")	# to handle port ranges like 8000-8012 for example
			ports.extend(range(int(start), int(end) + 1))
		else:
			ports.append(int(arg))
	return ports

ports = parse_ports(sys.argv[2:])	# this calls the function, passes arguments at the third index and fort as parameters into it, and stores it in the varible 'ports'



def check(port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)	# AF_INET = IPv4, SOCK_STREAM = TCP (the protocol with the handshake)
	s.settimeout(1)	# give up after 1 second 

	code = s.connect_ex((host, port))
	s.close()
	if code == 0:
		return port
	return None


# DATABASE

def save_scan(host, open_ports):
	""" a funtion that would write the scan and its database.
	Returns the id SQLite assigned to this scan."""
	
	conn = sqlite3.connect(DB_FILE)	#Opens the file or creates it if absent
	cur = conn.cursor()	#the cursor is what actully runs SQL

	#Two table: one row per scan, one row per open port found in it.
	#IF NOT EXISTS makes these safe to run every time - the only do abnyting on the very first run.
	cur.execute("""
		CREATE TABLE IF NOT EXISTS scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			host TEXT NOT NULL,
			scanned_at TEXT NOT NULL
		)
	""")

	cur.execute("""
		CREATE TABLE IF NOT EXISTS scans(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			host TEXT NOT NULL,
			scanned_at TEXT NOT NULL
		)
	""")

	cur.execute("""
		CREATE TABLE IF NOT EXISTS open_ports(
			scan_id INTEGER NOT NULL,
			port INTEGER NOT NULL,
			FOREIGN KEY (scan_id) REFERENCES scans(id)
		)
	""")

	# The ? marks ar placeholders; the values go in as a separate tuple.
	cur.execute(
		"INSERT INTO scans (host, scanned_at) VALUES (?, ?)",
		(host, datetime.now().isoformat(timespec="seconds"))
	)

	scan_id = cur.lastrowid		#the id SQLite just gave that row

	#Record each open port, tagged with the scan it came from.
	for port in open_ports:
		cur.execute(
			"INSERT INTO open_ports (scan_id, port) VALUES (?, ?)",
			(scan_id, port)
		)
	conn.commit()
	conn.close()
	return scan_id


def get_previous_scan(host, before_scan_id):
	"""Find the most recent EARLIER scan of this host and return the set of ports that were open in it
	Returns None if this host has never been scanned before """

	conn = sqlite3.connect(DB_FILE)
	cur = conn.cursor()

	#Newest scan of this host that isn't the one we just saved.
	#ORDER BY id DESC puts the highest id first; LIMIT 1 takes just that one.
	cur.execute("""
		SELECT id FROM scans
		WHERE host = ? AND id < ?
		ORDER BY id DESC
		LIMIT 1
	""", (host, before_scan_id))

	row = cur.fetchone()	#one row, or None if nothing matched

	if row is None:
		conn.close()
		return None

	previous_id = row[0]		#fetchone returns a tuple

	cur.execute("SELECT port FROM open_ports WHERE scan_id = ?", (previous_id,))

	ports = {r[0] for r in cur .fetchall()}

	conn.close()
	return ports



#--------------------------RUN THE SCAN-------------------------

start_time = time.time()

with ThreadPoolExecutor(max_workers = 100) as executor:	#Threads help because this work is waiting, not computing - 100 sockets
	results = list(executor.map(check, ports))

open_ports = [p for p in results if p is not None]

print("Scanned", len(ports), "ports on", host, "in", round(time.time() - start_time, 2), "seconds")

if open_ports:
	for port in open_ports:
		print(" ", port, "open")
else:
	print(" no open ports founr")


#------------------RECORD THIS SCAN, THEN COMPARE IT AGAINST THE PREVIOUS ONE-------

scan_id = save_scan(host,open_ports)	#write to the db
print("Saved as scan", scan_id, "in", DB_FILE)

previous = get_previous_scan(host,scan_id)	#checks for ports open previusly

if previous is None:
	#Nothing to compare against yet, so this run becomes the baseline
	print("First scan of", host, "-nothing to compare against yet")
else:
	current = set(open_ports)
	newly_open = current - previous	#the ones that are open now, butweren't before
	newly_closed = previous - current	#was open before, isn't nwo

	if newly_open or newly_closed:
		print("\nChanges since last scan:")
		for port in sorted(newly_open):
			print(" +", port, "NEWLY OPEN")
		for port in sorted(newly_closed):
			print("	-", port, "closed since last scan")

	else:
		print("\nNo changes since last scan")
