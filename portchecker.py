import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

if len(sys.argv) < 3:
	print("Usage: python3 portchecker.py <host> <port> [port ...]")
	print("Example: python3 portchecker.py 127.0.0.1 22 80 8000 9999")
	print("Example: python3 portchecker.py 127.0.0.1 1-1024")
	sys.exit(1)

host = sys.argv[1]
def parse_ports(args):
	ports = []
	for arg in args:
		if "-" in arg:
			start, end = arg.split("-")
			ports.extend(range(int(start), int(end) + 1))
		else:
			ports.append(int(arg))
	return ports

ports = parse_ports(sys.argv[2:])

def check(port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(1)
	code = s.connect_ex((host, port))
	s.close()
	if code == 0:
		return port
	return None


start_time = time.time()

with ThreadPoolExecutor(max_workers = 100) as executor:
	results = list(executor.map(check, ports))

open_ports = [p for p in results if p is not None]

print("Scanned", len(ports), "ports on", host, "in", round(time.time() - start_time, 2), "seconds")

if open_ports:
	for port in open_ports:
		print(" ", port, "open")
else:
	print(" no open ports founr")
