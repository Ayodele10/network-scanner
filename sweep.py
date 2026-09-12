import subprocess
from concurrent.futures import ThreadPoolExecutor

network = "192.168.1."

def is_up(host):
	ip = network + str(host)
	result = subprocess.run(
		["ping", "-c", "1", "-W", "1", ip],
		stdout = subprocess.DEVNULL,
		stderr = subprocess.DEVNULL
	)
	if result.returncode == 0:
		return ip
	return None

with ThreadPoolExecutor(max_workers = 50) as executor:
	results = list(executor.map(is_up, range(1, 255)))

for ip in results:
	if ip:
		print(ip, "is up")
